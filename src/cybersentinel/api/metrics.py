"""
Métricas de la ingestión: caudal, latencia y errores.

Se miden dos latencias distintas porque responden a preguntas distintas:

- **de ingesta**: cuánto tarda la API en aceptar el evento. Es lo que percibe
  el emisor y lo que determina si puede seguir enviando.
- **de extremo a extremo**: desde que el evento llega hasta que su resultado
  está persistido. Es lo que determina en cuánto tiempo un analista puede verlo.

Los percentiles se calculan sobre una ventana deslizante de las últimas N
muestras: una media acumulada desde el arranque oculta una degradación reciente.
"""
from __future__ import annotations

import threading
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Any


def _percentil(valores: list[float], p: float) -> float:
    if not valores:
        return 0.0
    ordenados = sorted(valores)
    k = (len(ordenados) - 1) * (p / 100.0)
    bajo, alto = int(k), min(int(k) + 1, len(ordenados) - 1)
    return ordenados[bajo] + (ordenados[alto] - ordenados[bajo]) * (k - bajo)


@dataclass
class IngestMetrics:
    """Contadores y latencias del servicio, seguros entre hilos."""

    ventana: int = 10_000
    started_at: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        self._lock = threading.Lock()
        self._ingest_ms: deque[float] = deque(maxlen=self.ventana)
        self._e2e_ms: deque[float] = deque(maxlen=self.ventana)
        self.received = 0
        self.accepted = 0
        self.rejected_validation = 0
        self.rejected_backpressure = 0
        self.processed = 0
        self.failed = 0
        self.annotations: Counter[str] = Counter()
        self.validation_errors: Counter[str] = Counter()

    # --- Registro ---------------------------------------------------------
    def record_received(self, n: int = 1) -> None:
        with self._lock:
            self.received += n

    def record_accepted(self, n: int, ingest_ms: float, anotaciones: list[str]) -> None:
        with self._lock:
            self.accepted += n
            self._ingest_ms.append(ingest_ms)
            self.annotations.update(anotaciones)

    def record_validation_error(self, motivo: str) -> None:
        with self._lock:
            self.rejected_validation += 1
            self.validation_errors[motivo[:120]] += 1

    def record_backpressure(self, n: int = 1) -> None:
        with self._lock:
            self.rejected_backpressure += n

    def record_processed(self, n: int, e2e_ms_por_evento: float) -> None:
        with self._lock:
            self.processed += n
            self._e2e_ms.append(e2e_ms_por_evento)

    def record_failed(self, n: int) -> None:
        with self._lock:
            self.failed += n

    # --- Lectura ----------------------------------------------------------
    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            ingest = list(self._ingest_ms)
            e2e = list(self._e2e_ms)
            uptime = max(time.time() - self.started_at, 1e-9)
            return {
                "uptime_s": round(uptime, 2),
                "counters": {
                    "received": self.received,
                    "accepted": self.accepted,
                    "rejected_validation": self.rejected_validation,
                    "rejected_backpressure": self.rejected_backpressure,
                    "processed": self.processed,
                    "failed": self.failed,
                },
                "throughput_eps": {
                    "accepted": round(self.accepted / uptime, 2),
                    "processed": round(self.processed / uptime, 2),
                },
                "latency_ingest_ms": {
                    "p50": round(_percentil(ingest, 50), 4),
                    "p95": round(_percentil(ingest, 95), 4),
                    "p99": round(_percentil(ingest, 99), 4),
                    "samples": len(ingest),
                },
                "latency_end_to_end_ms": {
                    "p50": round(_percentil(e2e, 50), 4),
                    "p95": round(_percentil(e2e, 95), 4),
                    "p99": round(_percentil(e2e, 99), 4),
                    "samples": len(e2e),
                },
                "annotations": dict(self.annotations),
                "validation_errors": dict(self.validation_errors.most_common(10)),
            }
