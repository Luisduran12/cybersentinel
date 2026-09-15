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


class IngestWorker:
    """Hilo que drena la cola por lotes y los pasa por el pipeline."""

    def __init__(
        self,
        pipeline: Pipeline,
        cola: IngestQueue,
        store: Any,
        metrics: IngestMetrics,
        batch_size: int = 500,
        poll_timeout: float = 0.5,
        max_retries: int = 2,
    ) -> None:
        self.pipeline = pipeline
        self.cola = cola
        self.store = store
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
                self.metrics.record_failed(len(lote))
                return

    def _persistir(self, reporte: Any, lote: list[QueuedEvent]) -> None:
        por_ref = {q.event.fingerprint(): q for q in lote}
        for resultado in reporte.results:
            encolado = por_ref.get(resultado.evidence.event_ref)
            # `source` viaja con el resultado para que el almacén lo registre.
            resultado.source = encolado.source if encolado else "desconocida"

        self.store.save_batch(reporte.results, umbral=ALERT_THRESHOLD)

        ahora = time.perf_counter()
        for q in lote:
            self.metrics.record_processed(1, (ahora - q.received_at) * 1000.0)
