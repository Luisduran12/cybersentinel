"""
API de ingestión de telemetría en tiempo real.

    uvicorn cybersentinel.api.app:app --host 0.0.0.0 --port 8000

Endpoints:
    POST /api/v1/events    ingesta (uno o varios eventos)
    GET  /api/v1/health    liveness: ¿el proceso responde?
    GET  /api/v1/ready     readiness: ¿puede aceptar tráfico útil?
    GET  /api/v1/metrics   caudal, latencias p50/p95/p99, errores
    GET  /api/v1/incidents últimos eventos que superaron el umbral

Diseño: la ingestión es **asíncrona**. La API valida, normaliza y encola, y
responde 202 sin esperar al análisis. Si respondiera con el veredicto, el emisor
quedaría bloqueado durante todo el pipeline —que incluye recuperación RAG y
explicación— y el caudal se desplomaría.

Lo que esta API NO tiene todavía, y hay que decirlo antes de exponerla:
autenticación, autorización, TLS y límite de caudal por cliente. Está pensada
para desplegarse **detrás** de un proxy que aporte esas cuatro cosas, no
directamente en una red no confiable.
"""
from __future__ import annotations

import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request, Response, status
from fastapi.responses import JSONResponse

from ..config import ROOT
from ..ingestion import Normalizer
from ..pipeline import ALERT_THRESHOLD, Pipeline
from .metrics import IngestMetrics
from .models import EventBatch, IngestResponse, RawEvent
from .queue import IngestQueue, QueueFull
from .store import ResultStore
from .worker import IngestWorker, QueuedEvent

logger = logging.getLogger(__name__)

#: Configuración por entorno. Sin valores mágicos escondidos en el código.
QUEUE_MAXSIZE = int(os.environ.get("CYBERSENTINEL_QUEUE_MAXSIZE", "20000"))
BATCH_SIZE = int(os.environ.get("CYBERSENTINEL_BATCH_SIZE", "500"))
DB_PATH = os.environ.get("CYBERSENTINEL_DB", str(ROOT / "data" / "runtime" / "events.db"))
RULES_DIR = os.environ.get("CYBERSENTINEL_RULES", str(ROOT / "config" / "rules"))
AUDIT_PATH = os.environ.get("CYBERSENTINEL_AUDIT", str(ROOT / "data" / "runtime" / "audit.jsonl"))


class IngestService:
    """Estado del servicio: pipeline real, cola, almacén, worker y métricas."""

    def __init__(
        self,
        rules_dir: str | Path = RULES_DIR,
        db_path: str | Path = DB_PATH,
        audit_path: str | Path | None = AUDIT_PATH,
        queue_maxsize: int = QUEUE_MAXSIZE,
        batch_size: int = BATCH_SIZE,
        **pipeline_kwargs: Any,
    ) -> None:
        self.normalizer = Normalizer()
        # El MISMO Pipeline que usa la CLI. No hay una versión "de servicio".
        self.pipeline = Pipeline(
            rules_dir=rules_dir, audit_path=audit_path, **pipeline_kwargs
        )
        self.queue = IngestQueue(maxsize=queue_maxsize)
        self.store = ResultStore(db_path)
        self.metrics = IngestMetrics()
        self.worker = IngestWorker(
            pipeline=self.pipeline, cola=self.queue, store=self.store,
            metrics=self.metrics, batch_size=batch_size,
        )

    def start(self) -> None:
        self.worker.start()

    def stop(self) -> None:
        self.worker.stop()

    def ingest(self, eventos: list[RawEvent]) -> IngestResponse:
        """Valida, normaliza y encola. No analiza: de eso se encarga el worker."""
        inicio = time.perf_counter()
        self.metrics.record_received(len(eventos))

        aceptados = 0
        rechazados = 0
        errores: list[dict[str, Any]] = []
        anotaciones: list[str] = []

        for indice, crudo in enumerate(eventos):
            try:
                registro, anot = crudo.to_record()
                evento = self.normalizer.normalize_record(registro)
                self.queue.put(QueuedEvent(
                    event=evento, received_at=time.perf_counter(),
                    source=evento.source,
                ))
                aceptados += 1
                anotaciones.extend(anot)
                anotaciones.extend(evento.tags)
            except QueueFull as exc:
                # Contrapresión: se informa, no se descarta en silencio.
                self.metrics.record_backpressure(len(eventos) - indice)
                rechazados += len(eventos) - indice
                errores.append({"index": indice, "error": "buffer lleno",
                                "detail": str(exc)})
                break
            except Exception as exc:
                rechazados += 1
                motivo = f"{type(exc).__name__}: {exc}"
                self.metrics.record_validation_error(motivo)
                errores.append({"index": indice, "error": "normalización", "detail": motivo[:200]})

        ms = (time.perf_counter() - inicio) * 1000.0
        if aceptados:
            self.metrics.record_accepted(aceptados, ms, anotaciones)

        return IngestResponse(
            accepted=aceptados, rejected=rechazados, queued=self.queue.size,
            annotations={a: anotaciones.count(a) for a in set(anotaciones)},
            errors=errores[:20],
        )


def create_app(svc: IngestService | None = None) -> FastAPI:
    """
    Construye la aplicación. Sin `svc` crea el servicio por defecto.

    El servicio vive en `app.state`, no en una global del módulo: con una global,
    dos aplicaciones en el mismo proceso —algo habitual en pruebas y en
    despliegues con varios montajes— se pisarían la instancia y la segunda
    dejaría a la primera apuntando a un worker detenido.
    """

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.service = svc or IngestService()
        app.state.service.start()
        logger.info("Servicio de ingestión listo")
        yield
        app.state.service.stop()

    app = FastAPI(
        title="CyberSentinel — Ingestión de telemetría",
        version="1.0.0",
        description=(
            "Ingesta de telemetría en tiempo real hacia el pipeline defensivo. "
            "Sin autenticación ni TLS: desplegar detrás de un proxy que los aporte."
        ),
        lifespan=lifespan,
    )

    def _svc(request: Request) -> IngestService:
        servicio = getattr(request.app.state, "service", None)
        if servicio is None:
            raise RuntimeError("El servicio no está inicializado")
        return servicio

    @app.post("/api/v1/events", status_code=status.HTTP_202_ACCEPTED,
              response_model=IngestResponse, summary="Ingerir telemetría")
    async def ingest_events(batch: EventBatch, request: Request,
                            response: Response) -> IngestResponse:
        resultado = _svc(request).ingest(batch.events)
        if resultado.accepted == 0 and resultado.rejected:
            # Nada entró: no es un 202. Distinguir contrapresión de dato inválido.
            hay_contrapresion = any(e["error"] == "buffer lleno" for e in resultado.errors)
            response.status_code = (
                status.HTTP_429_TOO_MANY_REQUESTS if hay_contrapresion
                else status.HTTP_422_UNPROCESSABLE_ENTITY
            )
            if hay_contrapresion:
                response.headers["Retry-After"] = "1"
        elif resultado.rejected:
            response.status_code = status.HTTP_207_MULTI_STATUS
        return resultado

    @app.get("/api/v1/health", summary="Liveness")
    async def health() -> dict[str, Any]:
        """¿El proceso está vivo? No dice nada sobre si es útil."""
        return {"status": "alive", "service": "cybersentinel-ingest"}

    @app.get("/api/v1/ready", summary="Readiness")
    async def ready(request: Request) -> JSONResponse:
        """
        ¿Puede aceptar tráfico útil?

        No basta con estar vivo: si el worker está caído o el buffer saturado,
        aceptar tráfico solo acumularía pérdidas.
        """
        s = _svc(request)
        saturada = s.queue.utilization >= 0.95
        listo = s.worker.is_running and not saturada
        cuerpo = {
            "ready": listo,
            "worker_running": s.worker.is_running,
            "queue_size": s.queue.size,
            "queue_utilization": round(s.queue.utilization, 4),
            "baseline_ready": s.worker.baseline_ready,
            "baseline_note": (
                "el detector aprende la línea base del primer lote recibido; "
                "hasta entonces el componente ML informa UNAVAILABLE"
            ),
            "components": s.pipeline.component_status,
        }
        return JSONResponse(
            cuerpo,
            status_code=status.HTTP_200_OK if listo else status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    @app.get("/api/v1/metrics", summary="Caudal, latencia y errores")
    async def metrics(request: Request) -> dict[str, Any]:
        s = _svc(request)
        datos = s.metrics.snapshot()
        datos["queue"] = {**s.queue.stats.to_dict(),
                          "size": s.queue.size,
                          "maxsize": s.queue.maxsize,
                          "utilization": round(s.queue.utilization, 4)}
        datos["worker"] = {"running": s.worker.is_running,
                           "batches_processed": s.worker.batches_processed,
                           "baseline_ready": s.worker.baseline_ready,
                           "last_run_id": s.worker.last_run_id}
        datos["store"] = s.store.summary()
        datos["alert_threshold"] = ALERT_THRESHOLD
        return datos

    @app.get("/api/v1/incidents", summary="Eventos que superaron el umbral")
    async def incidents(request: Request, limit: int = 50) -> dict[str, Any]:
        s = _svc(request)
        return {"threshold": ALERT_THRESHOLD,
                "incidents": s.store.incidents(limit=min(limit, 500))}

    @app.exception_handler(Exception)
    async def _errores(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Error no controlado en %s", request.url.path)
        return JSONResponse(
            {"error": type(exc).__name__, "detail": str(exc)[:200]},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    return app


app = create_app()
