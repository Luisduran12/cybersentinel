"""
Worker que consume la cola y ejecuta el pipeline real.

Es la pieza que conecta la ingestión en tiempo real con el motor de análisis que
ya existe: **no reimplementa nada**. Toma lotes de la cola y llama a
`Pipeline.run_events`, el mismo método que usa la CLI.

Una advertencia metodológica que el servicio declara en `/ready` y en las
métricas: el detector de anomalías aprende su línea base del **primer lote** que
recibe, porque así funciona un detector no supervisado que no tiene un modelo
pre-entrenado. Hasta que ese lote llega, el componente informa `UNAVAILABLE`; a
partir de ahí, la línea base es la de ese primer lote y no se reajusta. En un
despliegue real la línea base debería venir de un periodo de referencia
validado, no del primer tráfico que entre por la puerta.
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..pipeline import ALERT_THRESHOLD, Pipeline
from .metrics import IngestMetrics
from .queue import IngestQueue

logger = logging.getLogger(__name__)


@dataclass
class QueuedEvent:
    """Un evento normalizado esperando análisis, con su hora de llegada."""

    event: Any
    received_at: float
    source: str
    #: Secuencia en el registro de escritura anticipada. El worker avanza el
    #: punto de control hasta aquí **después** de persistir el resultado.
    seq: int = 0


class IngestWorker:
    """Hilo que drena la cola por lotes y los pasa por el pipeline."""

    def __init__(
        self,
        pipeline: Pipeline,
        cola: IngestQueue,
        store: Any,
        metrics: IngestMetrics,
        incidents: Any = None,
        wal: Any = None,
        batch_size: int = 500,
        poll_timeout: float = 0.5,
        max_retries: int = 2,
    ) -> None:
        self.pipeline = pipeline
        self.cola = cola
        self.store = store
        self.incidents = incidents
        self.wal = wal
        self.metrics = metrics
        self.batch_size = batch_size
        self.poll_timeout = poll_timeout
        self.max_retries = max_retries

        self._hilo: threading.Thread | None = None
        self._parar = threading.Event()
        self.batches_processed = 0
        self.last_run_id: str | None = None

    # --- Ciclo de vida ----------------------------------------------------
    def start(self) -> None:
        if self._hilo and self._hilo.is_alive():
            return
        self._parar.clear()
        self._hilo = threading.Thread(target=self._bucle, name="ingest-worker", daemon=True)
        self._hilo.start()
        logger.info("Worker de ingestión iniciado (lote=%d)", self.batch_size)

    def stop(self, timeout: float = 10.0) -> None:
        self._parar.set()
        if self._hilo:
            self._hilo.join(timeout=timeout)
        logger.info("Worker de ingestión detenido")

    @property
    def is_running(self) -> bool:
        return bool(self._hilo and self._hilo.is_alive())

    @property
    def baseline_ready(self) -> bool:
        """¿El detector ya aprendió una línea base?"""
        det = self.pipeline.anomaly_detector
        return bool(det and det.is_fitted)

    # --- Bucle ------------------------------------------------------------
    def _bucle(self) -> None:
        while not self._parar.is_set():
            lote = self.cola.drain(self.batch_size, timeout=self.poll_timeout)
            if lote:
                self._procesar(lote)

        # Drenado final: lo encolado antes de parar no se descarta.
        while True:
            lote = self.cola.drain(self.batch_size, timeout=0.05)
            if not lote:
                break
            self._procesar(lote)

    def _procesar(self, lote: list[QueuedEvent]) -> None:
        """Ejecuta el pipeline sobre el lote, con reintentos acotados."""
        eventos = [q.event for q in lote]
        for intento in range(self.max_retries + 1):
            try:
                reporte = self.pipeline.run_events(eventos)
                self._persistir(reporte, lote)
                self.batches_processed += 1
                self.last_run_id = reporte.run_id
                return
            except Exception as exc:
                if intento < self.max_retries:
                    self.cola.record_retry()
                    espera = 0.1 * (2 ** intento)
                    logger.warning(
                        "El pipeline falló (%s: %s); reintento %d/%d en %.2fs",
                        type(exc).__name__, exc, intento + 1, self.max_retries, espera,
                    )
                    time.sleep(espera)
                    continue
                # Agotados los reintentos: a la cola de fallidos, nunca al olvido.
                self.cola.dead_letter(lote, f"{type(exc).__name__}: {exc}")
                self._persistir_fallidos(lote, f"{type(exc).__name__}: {exc}")
                self.metrics.record_failed(len(lote))
                # El punto de control avanza igualmente: los eventos quedan
                # escritos en la cola de fallidos, en disco. Si no avanzara, el
                # mismo lote se reprocesaría y volvería a fallar en cada
                # arranque, y el registro crecería para siempre.
                self._avanzar_checkpoint(lote)
                return

    def _persistir(self, reporte: Any, lote: list[QueuedEvent]) -> None:
        por_ref = {q.event.fingerprint(): q for q in lote}
        for resultado in reporte.results:
            encolado = por_ref.get(resultado.evidence.event_ref)
            # `source` viaja con el resultado para que el almacén lo registre.
            resultado.source = encolado.source if encolado else "desconocida"

        self.store.save_batch(reporte.results, umbral=ALERT_THRESHOLD)

        if self.incidents is not None:
            # Dos almacenes con dos preguntas distintas: `store` responde
            # «¿cuántos eventos vi y cómo fueron?» —resumen por evento—, y
            # `incidents` responde «¿qué tengo que investigar?» —evidencia
            # completa solo de lo que cruzó el umbral—. Unirlos obligaría a
            # elegir entre guardar 129 MB por cada 20 000 eventos o dejar al
            # analista sin el porqué de la alerta.
            try:
                self.incidents.save_batch(
                    reporte.results, umbral=ALERT_THRESHOLD,
                    eventos_por_ref={ref: q.event for ref, q in por_ref.items()},
                )
            except Exception:
                # Un fallo persistiendo incidentes no puede tumbar la ingestión
                # ni provocar un reintento del lote entero: el resumen por
                # evento ya está a salvo y el error queda con traza.
                logger.exception("No se pudieron persistir los incidentes del lote")

        ahora = time.perf_counter()
        for q in lote:
            self.metrics.record_processed(1, (ahora - q.received_at) * 1000.0)

        # El punto de control se mueve **después** de persistir, nunca antes.
        # Al revés, una caída entre ambas cosas daría por procesado lo que no
        # llegó a guardarse, que es justo la pérdida silenciosa que el registro
        # existe para impedir.
        self._avanzar_checkpoint(lote)

    def _avanzar_checkpoint(self, lote: list[QueuedEvent]) -> None:
        if self.wal is None:
            return
        mayor = max((q.seq for q in lote), default=0)
        if mayor:
            self.wal.checkpoint(mayor)

    def _persistir_fallidos(self, lote: list[QueuedEvent], motivo: str) -> None:
        """
        Escribe en disco lo que el pipeline no pudo procesar.

        La cola de fallidos vivía solo en memoria: contabilizaba la pérdida
        pero no la conservaba, así que un reinicio la borraba junto con la
        evidencia de que había ocurrido.
        """
        if self.wal is None:
            return
        import json
        from datetime import datetime, timezone

        ruta = Path(self.wal.dir) / "dead-letters.jsonl"
        try:
            with open(ruta, "a", encoding="utf-8") as fh:
                for q in lote:
                    fh.write(json.dumps({
                        "at": datetime.now(tz=timezone.utc).isoformat(timespec="seconds"),
                        "seq": q.seq, "source": q.source, "reason": motivo,
                        "event": q.event.to_dict() if hasattr(q.event, "to_dict") else str(q.event),
                    }, ensure_ascii=False, default=str) + "\n")
        except OSError:
            logger.exception("No se pudo escribir la cola de fallidos en %s", ruta)
