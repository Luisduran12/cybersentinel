"""
Buffer acotado entre la ingestión y el análisis.

Desacopla la recepción del procesamiento: la API acepta y encola en
microsegundos, y un worker consume por lotes al ritmo que el pipeline permita.
Sin este buffer, una ráfaga bloquearía al emisor durante todo el análisis.

Tres propiedades que un buffer de producción necesita y que aquí son explícitas:

- **Acotado.** Una cola sin límite no es un buffer, es una fuga de memoria
  diferida: ante una ráfaga sostenida el proceso crece hasta morir.
- **Con contrapresión.** Cuando está llena se rechaza con 429 y `Retry-After`
  en lugar de bloquear al emisor o descartar en silencio.
- **Con reintento y cola de fallidos.** Un fallo del pipeline reintenta el lote;
  si persiste, los eventos van a una cola de fallidos y quedan contabilizados,
  nunca perdidos sin registro.
"""
from __future__ import annotations

import logging
import queue
import threading
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


class QueueFull(Exception):
    """El buffer está lleno: hay que aplicar contrapresión al emisor."""


@dataclass
class QueueStats:
    enqueued: int = 0
    dequeued: int = 0
    rejected_backpressure: int = 0
    dead_lettered: int = 0
    retries: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "enqueued": self.enqueued,
            "dequeued": self.dequeued,
            "rejected_backpressure": self.rejected_backpressure,
            "dead_lettered": self.dead_lettered,
            "retries": self.retries,
        }


@dataclass
class IngestQueue:
    """Cola acotada, segura entre hilos, con estadísticas."""

    maxsize: int = 10_000
    stats: QueueStats = field(default_factory=QueueStats)

    def __post_init__(self) -> None:
        self._q: queue.Queue = queue.Queue(maxsize=self.maxsize)
        self._dead: list[Any] = []
        self._lock = threading.Lock()
        self._reservado = 0

    def put(self, item: Any) -> None:
        """Encola sin bloquear. Lanza QueueFull si no hay sitio."""
        try:
            self._q.put_nowait(item)
        except queue.Full:
            with self._lock:
                self.stats.rejected_backpressure += 1
            raise QueueFull(
                f"buffer lleno ({self.maxsize} eventos); reintenta más tarde"
            ) from None
        with self._lock:
            self.stats.enqueued += 1

    def reserve(self, n: int) -> bool:
        """
        Aparta sitio para `n` eventos antes de escribirlos en el registro.

        Existe por un problema concreto de orden: el registro de escritura
        anticipada tiene que grabarse **antes** de aceptar, y la cola puede
        estar llena. Sin reserva solo quedan dos malas opciones: grabar y luego
        descubrir que no cabe —dejando eventos aceptados que nadie procesará
        hasta el siguiente reinicio—, o comprobar el hueco y perderlo en la
        milésima siguiente frente a otra petición.

        Con la reserva, la contrapresión se decide antes de escribir y el hueco
        ya no se lo puede quitar nadie.
        """
        with self._lock:
            if self._q.qsize() + self._reservado + n > self.maxsize:
                self.stats.rejected_backpressure += n
                return False
            self._reservado += n
            return True

    def release(self, n: int) -> None:
        """Devuelve una reserva que no se llegó a usar (falló el registro)."""
        with self._lock:
            self._reservado = max(0, self._reservado - n)

    def put_reserved(self, item: Any) -> None:
        """Encola consumiendo una reserva. No puede fallar por falta de sitio."""
        self._q.put_nowait(item)
        with self._lock:
            self._reservado = max(0, self._reservado - 1)
            self.stats.enqueued += 1

    def drain(self, max_items: int, timeout: float = 0.5) -> list[Any]:
        """
        Extrae hasta `max_items`, esperando como mucho `timeout` por el primero.

        Procesar por lotes es lo que hace viable reutilizar el pipeline
        existente, que está pensado para listas de eventos: el detector de
        anomalías necesita ver un conjunto para tener una línea base.
        """
        lote: list[Any] = []
        try:
            lote.append(self._q.get(timeout=timeout))
        except queue.Empty:
            return lote

        while len(lote) < max_items:
            try:
                lote.append(self._q.get_nowait())
            except queue.Empty:
                break

        with self._lock:
            self.stats.dequeued += len(lote)
        return lote

    def dead_letter(self, items: list[Any], reason: str) -> None:
        """Aparta los eventos que el pipeline no pudo procesar."""
        with self._lock:
            self._dead.extend(items)
            self.stats.dead_lettered += len(items)
        logger.error("%d eventos a la cola de fallidos: %s", len(items), reason)

    def record_retry(self) -> None:
        with self._lock:
            self.stats.retries += 1

    @property
    def size(self) -> int:
        return self._q.qsize()

    @property
    def dead_letters(self) -> list[Any]:
        with self._lock:
            return list(self._dead)

    @property
    def reserved(self) -> int:
        with self._lock:
            return self._reservado

    @property
    def utilization(self) -> float:
        if not self.maxsize:
            return 0.0
        # La reserva cuenta: es sitio comprometido, aunque todavía esté vacío.
        return (self.size + self.reserved) / self.maxsize
