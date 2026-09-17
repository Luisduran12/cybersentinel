"""
API de ingestión de telemetría en tiempo real.

    uvicorn cybersentinel.api.app:app --host 0.0.0.0 --port 8000

Endpoints:
    POST /api/v1/auth/token   emite un token de sesión (usuario + contraseña)
    GET  /api/v1/auth/whoami  quién soy y qué puedo hacer
    POST /api/v1/auth/logout  revoca el token en uso
    POST /api/v1/events       ingesta (uno o varios eventos)   · events:write
    GET  /api/v1/health       liveness: ¿el proceso responde?  · público
    GET  /api/v1/ready        readiness: ¿acepta tráfico útil? · público (resumido)
    GET  /api/v1/metrics      caudal, latencias, errores       · metrics:read
    GET  /api/v1/incidents    lo que superó el umbral          · incidents:read
    GET  /api/v1/identities   credenciales vivas               · identity:admin
    POST /api/v1/identities/keys      emitir clave de sensor   · identity:admin
    DELETE /api/v1/identities/keys/{id} revocar clave          · identity:admin
    GET  /api/v1/incidents/stats  cifras de cabecera           · incidents:read
    GET  /api/v1/incidents/{id}   incidente con su evidencia   · incidents:read
    PATCH /api/v1/incidents/{id}  estado, propietario, cierre  · incidents:write
    POST /api/v1/incidents/{id}/notes     anotar               · incidents:write
    POST /api/v1/incidents/{id}/decision  veredicto HITL       · incidents:write
    POST /api/v1/drain            retirada ordenada            · identity:admin
    GET  /soc/                    panel del analista           · público (estático)

Diseño: la ingestión es **asíncrona**. La API valida, normaliza y encola, y
responde 202 sin esperar al análisis. Si respondiera con el veredicto, el emisor
quedaría bloqueado durante todo el pipeline —que incluye recuperación RAG y
explicación— y el caudal se desplomaría.

Toda ruta que no sea una sonda de salud exige credencial y permiso (ver
`security/`). Las sondas quedan abiertas a propósito: un orquestador que no
puede consultarlas mata el proceso creyéndolo muerto, y `/ready` sin credencial
devuelve solo si acepta tráfico, no el detalle de los componentes.

El texto en claro solo se acepta desde la propia máquina: desde cualquier otro
origen se exige TLS —terminado aquí o por un proxy de confianza— y, si no lo
hay, la petición se rechaza con 403 en vez de dejar viajar la credencial. Ver
`security/transport.py`.
"""
from __future__ import annotations

import logging
import os
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from ..config import ROOT
from ..governance import AuditLog
from ..governance.dataset_manager import DatasetManager
from ..governance.feedback import HumanDecision, StructuredDecision
from ..ingestion import Normalizer
from ..pipeline import ALERT_THRESHOLD, Pipeline
from .metrics import IngestMetrics
from .models import (
    CreatedKeyResponse, CreateKeyRequest, TriageRequest, EventBatch,
    IncidentPatch, IngestResponse, NoteRequest, RawEvent, TokenRequest,
    TokenResponse,
)
from .incidents import Filtro, IncidentError, IncidentStore
from .queue import IngestQueue
from .security import (
    AuthError, Permission, Principal, Role, SecurityConfig, SecurityGate,
    TransportPolicy, charge_events, limit_anonymous, requires, role_matrix,
)
from .store import ResultStore
from .wal import WriteAheadLog
from .worker import IngestWorker, QueuedEvent

logger = logging.getLogger(__name__)

#: Raíz de los archivos del panel SOC. Se sirven desde el propio proceso: un
#: panel que exige su propio despliegue, su propio dominio y su propia
#: configuración de CORS es un panel que en la práctica no se instala.
PANEL_DIR = Path(__file__).parent / "panel"

#: Configuración por entorno. Sin valores mágicos escondidos en el código.
QUEUE_MAXSIZE = int(os.environ.get("CYBERSENTINEL_QUEUE_MAXSIZE", "20000"))
BATCH_SIZE = int(os.environ.get("CYBERSENTINEL_BATCH_SIZE", "500"))
DB_PATH = os.environ.get("CYBERSENTINEL_DB", str(ROOT / "data" / "runtime" / "events.db"))
RULES_DIR = os.environ.get("CYBERSENTINEL_RULES", str(ROOT / "config" / "rules"))
AUDIT_PATH = os.environ.get("CYBERSENTINEL_AUDIT", str(ROOT / "data" / "runtime" / "audit.jsonl"))
IDENTITY_DB = os.environ.get(
    "CYBERSENTINEL_IDENTITY_DB", str(ROOT / "data" / "runtime" / "identities.db"))
WAL_DIR = os.environ.get("CYBERSENTINEL_WAL", str(ROOT / "data" / "runtime" / "wal"))
FEEDBACK_STORE = os.environ.get(
    "CYBERSENTINEL_FEEDBACK", str(ROOT / "data" / "feedback" / "decisions.jsonl"))

#: Cómo se traduce el veredicto del analista a motivo de cierre. `UNCERTAIN`
#: no aparece a propósito: un incidente sobre el que el analista duda no está
#: resuelto, y cerrarlo automáticamente lo escondería del panel sin que nadie
#: haya decidido nada.
RESOLUCION_POR_VEREDICTO = {
    "TRUE_POSITIVE": "true_positive",
    "FALSE_POSITIVE": "false_positive",
    "BENIGN": "benign",
}


class IngestService:
    """Estado del servicio: pipeline real, cola, almacén, worker y métricas."""

    def __init__(
        self,
        rules_dir: str | Path = RULES_DIR,
        db_path: str | Path = DB_PATH,
        audit_path: str | Path | None = AUDIT_PATH,
        queue_maxsize: int = QUEUE_MAXSIZE,
        batch_size: int = BATCH_SIZE,
        incidents_path: str | Path | None = None,
        feedback_store: str | Path | None = None,
        wal_dir: str | Path | None = None,
        **pipeline_kwargs: Any,
    ) -> None:
        self.normalizer = Normalizer()
        # El MISMO Pipeline que usa la CLI. No hay una versión "de servicio".
        self.pipeline = Pipeline(
            rules_dir=rules_dir, audit_path=audit_path, **pipeline_kwargs
        )
        self.queue = IngestQueue(maxsize=queue_maxsize)
        # Nada se acepta hasta que está escrito aquí. Ver `wal.py`.
        self.wal = WriteAheadLog(wal_dir or WAL_DIR)
        self._ingest_lock = threading.Lock()
        self.draining = False
        self.store = ResultStore(db_path)
        self.incidents = IncidentStore(
            incidents_path or Path(db_path).with_name("incidents.db"))
        self.metrics = IngestMetrics()
        # El mismo almacén de decisiones que usa `cybersentinel decide`: el
        # panel no abre un circuito paralelo de etiquetado.
        self.feedback = DatasetManager(store_path=feedback_store or FEEDBACK_STORE)
        self.worker = IngestWorker(
            pipeline=self.pipeline, cola=self.queue, store=self.store,
            incidents=self.incidents, metrics=self.metrics, batch_size=batch_size,
            wal=self.wal,
        )

    def start(self) -> None:
        """Recupera lo que quedó del arranque anterior y arranca el worker."""
        # Arrancar después de parar es legítimo. Sin este reinicio explícito, el
        # servicio quedaba en retirada para siempre y con el registro cerrado.
        self.draining = False
        self.wal.reopen()
        
        t0 = time.perf_counter()
        recuperados = self.recover()
        t1 = time.perf_counter()
        self.metrics.recovery_time_ms = (t1 - t0) * 1000.0
        
        if recuperados:
            logger.warning(
                "Recuperados %d eventos aceptados y no procesados del arranque "
                "anterior. No se perdió nada; se reprocesarán.", recuperados)
        self.worker.start()
        
        self._supervisor = threading.Thread(target=self._supervisar, name="supervisor", daemon=True)
        self._supervisor.start()

    def _supervisar(self) -> None:
        """
        Vigila que el worker siga vivo. Si muere por un error no capturado,
        lo reinicia para no perder eventos silenciosamente.
        """
        while not self.draining:
            time.sleep(5)
            if not self.worker.is_running and not self.draining:
                logger.error("Supervisor: El worker ha muerto inesperadamente. Reiniciando...")
                self.worker.start()

    def recover(self) -> int:
        """
        Reencola lo aceptado y no procesado que dejó el proceso anterior.

        Se normaliza de nuevo desde el registro crudo en vez de guardar el
        evento ya normalizado: así la recuperación recorre exactamente el mismo
        camino que la ingestión, y no puede divergir cuando un parser cambie.
        """
        recuperados = 0
        for entrada in self.wal.replay():
            try:
                evento = self.normalizer.normalize_record(entrada.record)
            except Exception as exc:
                # Un registro que ya no normaliza —porque el parser cambió— no
                # puede bloquear la recuperación del resto.
                logger.error("No se pudo recuperar el registro %d: %s",
                             entrada.seq, exc)
                continue
            if not self.queue.reserve(1):
                logger.error(
                    "El buffer se llenó durante la recuperación en la secuencia "
                    "%d: el resto sigue en el registro y se recuperará en el "
                    "siguiente arranque.", entrada.seq)
                break
            self.queue.put_reserved(QueuedEvent(
                event=evento, received_at=time.perf_counter(),
                source=entrada.source, seq=entrada.seq))
            recuperados += 1
        return recuperados

    def stop(self) -> None:
        """
        Apagado ordenado: dejar de aceptar, drenar, bajar a disco.

        El orden importa. Marcar `draining` primero hace que `/ready` devuelva
        503 y que el balanceador deje de enviar tráfico **antes** de que la cola
        empiece a vaciarse; al revés, los eventos que llegasen durante el
        drenado se quedarían sin worker que los procese.
        """
        self.draining = True
        self.worker.stop()
        self.wal.release()

    def ingest(self, eventos: list[RawEvent]) -> IngestResponse:
        """Valida, normaliza y encola. No analiza: de eso se encarga el worker."""
        inicio = time.perf_counter()
        self.metrics.record_received(len(eventos))

        rechazados = 0
        errores: list[dict[str, Any]] = []
        anotaciones: list[str] = []
        validos: list[tuple[dict[str, Any], Any]] = []

        # 1. Validar y normalizar. Se hace fuera del candado: es lo caro, y no
        #    toca estado compartido.
        for indice, crudo in enumerate(eventos):
            try:
                registro, anot = crudo.to_record()
                evento = self.normalizer.normalize_record(registro)
            except Exception as exc:
                rechazados += 1
                motivo = f"{type(exc).__name__}: {exc}"
                self.metrics.record_validation_error(motivo)
                errores.append({"index": indice, "error": "normalización",
                                "detail": motivo[:200]})
                continue
            validos.append((registro, evento))
            anotaciones.extend(anot)
            anotaciones.extend(evento.tags)

        aceptados = 0
        if validos:
            # 2. Reservar, registrar y encolar bajo un solo candado, para que el
            #    orden de secuencia del registro coincida con el de la cola. Si
            #    no coincidieran, el punto de control del worker podría saltarse
            #    eventos aún sin procesar y un fallo los perdería.
            with self._ingest_lock:
                if not self.queue.reserve(len(validos)):
                    self.metrics.record_backpressure(len(validos))
                    rechazados += len(validos)
                    errores.append({
                        "index": len(eventos) - len(validos), "error": "buffer lleno",
                        "detail": f"buffer lleno ({self.queue.maxsize} eventos); "
                                  "reintenta más tarde"})
                else:
                    try:
                        seqs = self.wal.append([(r, e.source) for r, e in validos])
                    except Exception as exc:
                        # No se pudo registrar: no se acepta. Un 503 honesto es
                        # mejor que un 202 que miente.
                        self.queue.release(len(validos))
                        rechazados += len(validos)
                        errores.append({"index": 0, "error": "registro no disponible",
                                        "detail": f"{type(exc).__name__}: {exc}"[:200]})
                        logger.exception("Fallo al escribir el registro anticipado")
                    else:
                        ahora = time.perf_counter()
                        for (_, evento), seq in zip(validos, seqs):
                            self.queue.put_reserved(QueuedEvent(
                                event=evento, received_at=ahora,
                                source=evento.source, seq=seq))
                        aceptados = len(validos)

        ms = (time.perf_counter() - inicio) * 1000.0
        if aceptados:
            self.metrics.record_accepted(aceptados, ms, anotaciones)

        return IngestResponse(
            accepted=aceptados, rejected=rechazados, queued=self.queue.size,
            annotations={a: anotaciones.count(a) for a in set(anotaciones)},
            errors=errores[:20],
        )


def _default_gate() -> SecurityGate:
    """
    Puerta por defecto: identidades en SQLite y auditoría encadenada.

    La auditoría de seguridad va al **mismo** log encadenado que el resto del
    sistema, no a uno aparte. Un registro de autenticación en un archivo propio
    se puede borrar sin romper ninguna cadena; aquí, borrar un intento fallido
    invalida la verificación de todo lo posterior.
    """
    return SecurityGate(SecurityConfig(
        identity_db=IDENTITY_DB,
        audit_log=AuditLog(AUDIT_PATH) if AUDIT_PATH else None,
    ))


def create_app(svc: IngestService | None = None,
               gate: SecurityGate | None = None,
               transport: TransportPolicy | None = None) -> FastAPI:
    """
    Construye la aplicación. Sin `svc` crea el servicio por defecto.

    El servicio vive en `app.state`, no en una global del módulo: con una global,
    dos aplicaciones en el mismo proceso —algo habitual en pruebas y en
    despliegues con varios montajes— se pisarían la instancia y la segunda
    dejaría a la primera apuntando a un worker detenido. La puerta de seguridad
    vive en el mismo sitio y por la misma razón.
    """

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.service = svc or IngestService()
        app.state.gate = gate or _default_gate()

        # Un solo objeto `AuditLog` por archivo. Dos instancias sobre el mismo
        # registro calculan `index` y `prev_hash` cada una por su cuenta y
        # dejan dos cadenas entrelazadas; `AuditLog` ya se defiende releyendo el
        # archivo, pero compartir la instancia evita esa relectura en cada
        # entrada y deja la intención explícita en vez de confiada al arreglo.
        del_pipeline = getattr(app.state.service.pipeline, "audit", None)
        de_la_puerta = app.state.gate.audit
        if del_pipeline is not None and (
            de_la_puerta is None
            or Path(de_la_puerta.path) == Path(del_pipeline.path)
        ):
            app.state.gate.audit = del_pipeline

        app.state.service.start()
        logger.info("Servicio de ingestión listo (secreto de token: %s)",
                    app.state.gate.signer.source)
        yield
        app.state.service.stop()
        # El contador de usos de las claves se vuelca en diferido (ver
        # `IdentityStore._touch_key`); en un apagado ordenado no se pierde.
        app.state.gate.store.flush_usage()

    app = FastAPI(
        title="CyberSentinel — Ingestión de telemetría",
        version="1.1.0",
        description=(
            "Ingesta de telemetría en tiempo real hacia el pipeline defensivo. "
            "Autenticada (clave de API para sensores, token para personas), con "
            "autorización por permisos y límite de caudal por cliente. "
            "**Sin TLS**: desplegar detrás de un terminador TLS."
        ),
        lifespan=lifespan,
    )

    def _svc(request: Request) -> IngestService:
        servicio = getattr(request.app.state, "service", None)
        if servicio is None:
            raise RuntimeError("El servicio no está inicializado")
        return servicio

    # --- Frontera de seguridad -------------------------------------------
    @app.post("/api/v1/auth/token", response_model=TokenResponse,
              dependencies=[Depends(limit_anonymous)],
              summary="Emitir token de sesión")
    async def emitir_token(credenciales: TokenRequest, request: Request) -> TokenResponse:
        """
        Cambia usuario y contraseña por un token de vida corta.

        `limit_anonymous` se aplica **antes** que el manejador: derivar la
        contraseña con scrypt cuesta ~100 ms a propósito, y sin ese límite
        previo el propio mecanismo de defensa sería la palanca para tumbar el
        servicio.
        """
        try:
            return TokenResponse(**request.app.state.gate.issue_token(
                credenciales.username, credenciales.password, request))
        except AuthError as exc:
            cabeceras = {"WWW-Authenticate": 'Bearer realm="cybersentinel"'}
            if exc.retry_after:
                cabeceras["Retry-After"] = str(exc.retry_after)
            # Mismo mensaje para usuario inexistente y contraseña incorrecta.
            return JSONResponse(
                {"error": "no_autenticado", "reason": exc.motivo},
                status_code=status.HTTP_401_UNAUTHORIZED, headers=cabeceras,
            )

    @app.get("/api/v1/auth/whoami", summary="Quién soy y qué puedo hacer")
    async def whoami(principal: Principal = Depends(requires())) -> dict[str, Any]:
        """Sin permiso concreto: basta con estar autenticado."""
        return {**principal.to_dict(), "token_id": principal.token_id}

    @app.post("/api/v1/auth/logout", summary="Revocar el token en uso")
    async def logout(request: Request,
                     principal: Principal = Depends(requires())) -> dict[str, Any]:
        if not principal.token_id:
            return {"revoked": False,
                    "reason": "las claves de API se revocan desde /identities, no aquí"}
        request.app.state.gate.revoke_token(
            principal.token_id,
            expires_at=int(principal.claims.get("exp", 0)),
            subject=principal.display)
        return {"revoked": True, "token_id": principal.token_id,
                "note": "la revocación se guarda en el almacén de identidades: "
                        "vale en todas las réplicas y sobrevive al reinicio"}

    @app.get("/api/v1/auth/roles", summary="Matriz de roles y permisos")
    async def roles(_: Principal = Depends(requires())) -> dict[str, Any]:
        return {"roles": role_matrix()}

    # --- Administración de credenciales ----------------------------------
    @app.get("/api/v1/identities", summary="Credenciales vivas")
    async def identidades(request: Request,
                          principal: Principal = Depends(requires(Permission.IDENTITY_ADMIN)),
                          include_revoked: bool = False) -> dict[str, Any]:
        almacen = request.app.state.gate.store
        return {"users": almacen.list_users(),
                "api_keys": almacen.list_api_keys(include_revoked=include_revoked),
                "summary": almacen.summary()}

    @app.post("/api/v1/identities/keys", status_code=status.HTTP_201_CREATED,
              response_model=CreatedKeyResponse, summary="Emitir clave de sensor")
    async def crear_clave(cuerpo: CreateKeyRequest, request: Request,
                          principal: Principal = Depends(requires(Permission.IDENTITY_ADMIN)),
                          ) -> CreatedKeyResponse:
        puerta = request.app.state.gate
        try:
            rol = Role(cuerpo.role)
        except ValueError:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                detail={"error": "rol_desconocido",
                                        "valid": [r.value for r in Role]}) from None
        emitida = puerta.store.create_api_key(
            label=cuerpo.label, role=rol, created_by=principal.id,
            expires_in_days=cuerpo.expires_in_days)
        puerta._record(actor=principal.id, action="api_key_created",
                       detail={"key_id": emitida.key_id, "role": rol.value,
                               "label": cuerpo.label, "expires_at": emitida.expires_at})
        return CreatedKeyResponse(
            key_id=emitida.key_id, api_key=emitida.token, role=rol.value,
            label=emitida.label, expires_at=emitida.expires_at)

    @app.delete("/api/v1/identities/keys/{key_id}", summary="Revocar clave de sensor")
    async def revocar_clave(key_id: str, request: Request,
                            principal: Principal = Depends(requires(Permission.IDENTITY_ADMIN)),
                            ) -> dict[str, Any]:
        puerta = request.app.state.gate
        revocada = puerta.store.revoke_api_key(key_id)
        if revocada:
            puerta._record(actor=principal.id, action="api_key_revoked",
                           detail={"key_id": key_id})
        return {"revoked": revocada, "key_id": key_id}

    @app.post("/api/v1/events", status_code=status.HTTP_202_ACCEPTED,
              response_model=IngestResponse, summary="Ingerir telemetría")
    async def ingest_events(batch: EventBatch, request: Request, response: Response,
                            principal: Principal = Depends(requires(Permission.EVENTS_WRITE)),
                            ) -> IngestResponse:
        # El caudal de eventos se cobra aquí, con el lote ya validado y antes de
        # normalizar nada: un cliente fuera de cuota no debe consumir pipeline.
        charge_events(request, principal, len(batch.events))
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
        """
        ¿El proceso está vivo? No dice nada sobre si es útil.

        Pública a propósito y deliberadamente escueta: no revela versión, ni
        componentes, ni estado interno. Es lo único que se puede saber del
        servicio sin presentar credencial.
        """
        return {"status": "alive", "service": "cybersentinel-ingest"}

    @app.get("/api/v1/ready", summary="Readiness")
    async def ready(request: Request) -> JSONResponse:
        """
        ¿Puede aceptar tráfico útil?

        No basta con estar vivo: si el worker está caído o el buffer saturado,
        aceptar tráfico solo acumularía pérdidas.

        Queda **sin credencial** porque un orquestador que no puede consultarla
        reinicia el proceso creyéndolo muerto. A cambio, sin credencial devuelve
        solo el veredicto: el estado de cada componente, la ocupación del buffer
        y la configuración de la frontera son inteligencia útil para quien esté
        preparando un ataque, y solo se sirven con `metrics:read`.
        """
        s = _svc(request)
        saturada = s.queue.utilization >= 0.95
        listo = s.worker.is_running and not saturada and not s.draining
        codigo = status.HTTP_200_OK if listo else status.HTTP_503_SERVICE_UNAVAILABLE

        puerta = request.app.state.gate
        try:
            principal = puerta.authenticate(request)
        except AuthError:
            principal = None
        if principal is None or not principal.can(Permission.METRICS_READ):
            # Sin credencial, el balanceador necesita saber si mandar tráfico y
            # nada más. `draining` se incluye porque es la diferencia entre «se
            # está apagando ordenadamente» y «se ha roto», y confundirlas hace
            # que el orquestador reinicie un proceso que estaba terminando bien.
            return JSONResponse({"ready": listo, "draining": s.draining},
                                status_code=codigo)

        return JSONResponse({
            "ready": listo,
            "worker_running": s.worker.is_running,
            "queue_size": s.queue.size,
            "queue_utilization": round(s.queue.utilization, 4),
            "queue_reserved": s.queue.reserved,
            "draining": s.draining,
            "wal": s.wal.stats(),
            "baseline_ready": s.worker.baseline_ready,
            "baseline_note": (
                "el detector aprende la línea base del primer lote recibido; "
                "hasta entonces el componente ML informa UNAVAILABLE"
            ),
            "components": s.pipeline.component_status,
            "security": {**puerta.status(),
                         "transport": request.app.state.transport.status()},
        }, status_code=codigo)

    @app.get("/api/v1/metrics", summary="Caudal, latencia y errores")
    async def metrics(request: Request,
                      _: Principal = Depends(requires(Permission.METRICS_READ)),
                      ) -> dict[str, Any]:
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
        datos["rate_limit"] = request.app.state.gate.limiter.stats()
        datos["wal"] = s.wal.stats()
        datos["incidents"] = s.incidents.stats()
        return datos

    @app.post("/api/v1/drain", summary="Dejar de aceptar tráfico y vaciar la cola")
    async def drain(request: Request,
                    principal: Principal = Depends(requires(Permission.IDENTITY_ADMIN)),
                    ) -> dict[str, Any]:
        """
        Marca el proceso como «en retirada» sin matarlo.

        Es la mitad que falta de un apagado ordenado. Si se manda `SIGTERM` sin
        más, el proceso deja de escuchar de golpe y el balanceador sigue
        enviándole tráfico durante los segundos que tarda en enterarse: esas
        peticiones se pierden. Con esto, el orden correcto es:

            1. `POST /api/v1/drain`  → `/ready` pasa a 503
            2. esperar a que el balanceador lo saque de rotación
            3. `SIGTERM` → se vacía la cola y se cierra el registro

        No se puede deshacer desde la API a propósito: un proceso que vuelve a
        aceptar tráfico después de anunciar que se retiraba es exactamente el
        que el balanceador ya no vigila.
        """
        servicio = _svc(request)
        servicio.draining = True
        request.app.state.gate._record(
            actor=principal.id, action="service_draining",
            detail={"queue_size": servicio.queue.size,
                    "wal_pending": servicio.wal.pending()})
        logger.warning("Drenado solicitado por %s: /ready devolverá 503", principal.id)
        return {"draining": True, "queue_size": servicio.queue.size,
                "wal_pending": servicio.wal.pending(),
                "next": "espera a que el balanceador lo saque de rotación y "
                        "manda SIGTERM"}

    # --- Incidentes: lo que el panel SOC consume --------------------------
    @app.get("/api/v1/incidents/stats", summary="Cifras de cabecera del panel")
    async def incident_stats(request: Request,
                             _: Principal = Depends(requires(Permission.INCIDENTS_READ)),
                             ) -> dict[str, Any]:
        # Declarada antes que `/{incident_id}`: en caso contrario, «stats» se
        # interpretaría como el identificador de un incidente.
        return {**_svc(request).incidents.stats(), "threshold": ALERT_THRESHOLD}

    @app.get("/api/v1/incidents", summary="Incidentes filtrables")
    async def incidents(
        request: Request,
        principal: Principal = Depends(requires(Permission.INCIDENTS_READ)),
        state: str | None = None, severity: str | None = None,
        owner: str | None = None, entity: str | None = None,
        technique: str | None = None, unassigned: bool = False,
        q: str | None = None, since: str | None = None,
        limit: int = 50, offset: int = 0,
    ) -> dict[str, Any]:
        resultado = _svc(request).incidents.list(Filtro(
            state=state, severity=severity, owner=owner, entity=entity,
            technique=technique, unassigned=unassigned, query=q, since=since,
            limit=limit, offset=offset,
        ))
        return {**resultado, "threshold": ALERT_THRESHOLD,
                "queried_by": principal.display,
                "can_write": principal.can(Permission.INCIDENTS_WRITE)}

    @app.get("/api/v1/incidents/{incident_id}", summary="Un incidente con toda su evidencia")
    async def incident_detail(incident_id: str, request: Request,
                              principal: Principal = Depends(requires(Permission.INCIDENTS_READ)),
                              ) -> dict[str, Any]:
        incidente = _svc(request).incidents.get(incident_id)
        if incidente is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND,
                                detail={"error": "no_encontrado", "incident_id": incident_id})
        return {**incidente, "can_write": principal.can(Permission.INCIDENTS_WRITE)}

    @app.patch("/api/v1/incidents/{incident_id}", summary="Cambiar estado, propietario o severidad")
    async def incident_update(incident_id: str, cambio: IncidentPatch, request: Request,
                              principal: Principal = Depends(requires(Permission.INCIDENTS_WRITE)),
                              ) -> dict[str, Any]:
        servicio, puerta = _svc(request), request.app.state.gate
        try:
            incidente = servicio.incidents.update(
                incident_id, actor=principal.display, state=cambio.state,
                owner=cambio.owner, severity=cambio.severity,
                resolution=cambio.resolution, note=cambio.note,
                clear_owner=cambio.clear_owner,
            )
        except IncidentError as exc:
            # 422 y no 500: el error es del cliente —una transición que no
            # existe— y el mensaje dice qué sí se puede hacer.
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                detail={"error": "transicion_invalida",
                                        "reason": str(exc)}) from None
        puerta._record(actor=principal.id, action="incident_updated",
                       detail={"incident_id": incident_id, "state": cambio.state,
                               "owner": cambio.owner, "severity": cambio.severity,
                               "resolution": cambio.resolution})
        return incidente

    @app.post("/api/v1/incidents/{incident_id}/notes", status_code=status.HTTP_201_CREATED,
              summary="Anotar la investigación")
    async def incident_note(incident_id: str, nota: NoteRequest, request: Request,
                            principal: Principal = Depends(requires(Permission.INCIDENTS_WRITE)),
                            ) -> dict[str, Any]:
        try:
            return _svc(request).incidents.add_note(incident_id, principal.display, nota.text)
        except IncidentError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND,
                                detail={"error": "no_encontrado", "reason": str(exc)}) from None

    @app.get("/api/v1/incidents/{incident_id}/timeline", summary="Cronología del incidente")
    async def incident_timeline(incident_id: str, request: Request,
                                principal: Principal = Depends(requires(Permission.INCIDENTS_READ)),
                                ) -> list[dict[str, Any]]:
        incidente = _svc(request).incidents.get(incident_id)
        if incidente is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND,
                                detail={"error": "no_encontrado", "incident_id": incident_id})
        return _svc(request).incidents.timeline(incident_id)

    @app.post("/api/v1/incidents/{incident_id}/triage", status_code=status.HTTP_201_CREATED,
              summary="Decisión de triaje del analista (human-in-the-loop)")
    async def incident_triage(incident_id: str, cuerpo: TriageRequest, request: Request,
                              principal: Principal = Depends(requires(Permission.INCIDENTS_WRITE)),
                              ) -> dict[str, Any]:
        """
        Registra el veredicto y actualiza el estado.
        """
        servicio, puerta = _svc(request), request.app.state.gate
        incidente = servicio.incidents.get(incident_id)
        if incidente is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND,
                                detail={"error": "no_encontrado", "incident_id": incident_id})

        if cuerpo.action == "COMMENT":
            if not cuerpo.reason:
                raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Falta el texto del comentario")
            return servicio.incidents.add_note(incident_id, principal.display, cuerpo.reason)

        estado_destino = ""
        veredicto_enum = None
        if cuerpo.action == "CONFIRM":
            estado_destino = "confirmed"
            veredicto_enum = HumanDecision.TRUE_POSITIVE
        elif cuerpo.action == "REJECT":
            estado_destino = "false_positive"
            veredicto_enum = HumanDecision.FALSE_POSITIVE
        elif cuerpo.action == "UNCERTAIN":
            estado_destino = "uncertain"
            veredicto_enum = HumanDecision.UNCERTAIN
        else:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Acción desconocida")

        decision = StructuredDecision(
            detection_id=incident_id, event_id=incidente["event_ref"],
            timestamp=datetime.fromisoformat(incidente["event_time"]),
            analyst_decision=veredicto_enum, confidence=1.0,
            reason=cuerpo.reason,
            selected_evidence={k: incidente[k] for k in (
                "incident_id", "run_id", "event_ref", "event_id", "score",
                "anomaly_score", "detection_status", "techniques", "tactics",
                "rules", "cti", "narrative", "raw_event") if k in incidente},
            analyst_id=principal.display,
            model_version=servicio.pipeline.component_status.get("ml", "desconocida"),
            rule_version=servicio.pipeline.component_status.get("sigma", "desconocida"),
            data_source=f"soc-panel:{incident_id}",
            created_at=datetime.now(tz=timezone.utc),
        )
        aceptada = servicio.feedback.submit_decision(decision)
        if not aceptada:
            raise HTTPException(status.HTTP_409_CONFLICT,
                                detail={"error": "decision_rechazada",
                                        "reason": "duplicada"})

        servicio.incidents.record_decision(
            incident_id, principal.display, veredicto_enum.value, cuerpo.reason,
            decision.fingerprint())
        
        try:
            resultado = servicio.incidents.update(
                incident_id, actor=principal.display, state=estado_destino, note=cuerpo.reason
            )
        except IncidentError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))

        puerta._record(actor=principal.id, action="analyst_triage",
                       detail={"incident_id": incident_id, "decision": cuerpo.action})

        return {"decision": decision.to_dict(), "incident": resultado}

    # --- Transporte -------------------------------------------------------
    app.state.transport = transport or TransportPolicy.from_env()

    @app.middleware("http")
    async def _exigir_tls(request: Request, call_next):
        """
        Rechaza el texto en claro desde orígenes remotos, antes de tocar nada.

        Va por delante de la autenticación a propósito: comprobar una
        contraseña que acaba de viajar legible por la red no la hace menos
        legible. Si la conexión no es segura, la credencial ya está
        comprometida y lo único útil es no seguir.

        `/api/v1/health` queda fuera: es la sonda del orquestador, no lleva
        credenciales ni revela nada, y devolver 403 ahí haría que se reiniciara
        el proceso por un problema de red.
        """
        politica: TransportPolicy = request.app.state.transport
        if request.url.path != "/api/v1/health":
            motivo = politica.refusal_reason(request)
            if motivo:
                return JSONResponse(
                    {"error": "tls_requerido", "reason": motivo},
                    status_code=status.HTTP_403_FORBIDDEN,
                )
        respuesta = await call_next(request)
        for clave, valor in politica.response_headers(request).items():
            respuesta.headers.setdefault(clave, valor)
        return respuesta

    # --- Panel SOC --------------------------------------------------------
    @app.middleware("http")
    async def _cabeceras_de_seguridad(request: Request, call_next):
        """
        Cabeceras que el navegador necesita para no ejecutar lo que no debe.

        La telemetría la escribe el atacante y el panel la muestra. El código
        del panel ya inserta todo con `textContent`, pero una política de
        contenido estricta convierte un descuido futuro en un error de consola
        en lugar de en ejecución de código en el navegador del analista.
        `frame-ancestors 'none'` impide además que el panel se empotre en otra
        página para robar clics.
        """
        respuesta = await call_next(request)
        respuesta.headers.setdefault("Content-Security-Policy", (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; form-action 'self'; "
            "frame-ancestors 'none'; base-uri 'none'"))
        respuesta.headers.setdefault("X-Content-Type-Options", "nosniff")
        respuesta.headers.setdefault("Referrer-Policy", "no-referrer")
        respuesta.headers.setdefault("X-Frame-Options", "DENY")
        return respuesta

    @app.get("/", include_in_schema=False)
    async def _raiz() -> RedirectResponse:
        return RedirectResponse("/soc/")

    if PANEL_DIR.is_dir():
        # Los archivos del panel son públicos: son HTML, CSS y JavaScript sin
        # un solo dato dentro. Todo lo que muestran lo piden a la API con el
        # token del analista, y esa sí exige credencial y permiso.
        app.mount("/soc", StaticFiles(directory=PANEL_DIR, html=True), name="soc")
    else:
        logger.warning("No se encontró el panel en %s: la API funciona, "
                       "pero /soc no servirá nada", PANEL_DIR)

    @app.exception_handler(Exception)
    async def _errores(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Error no controlado en %s", request.url.path)
        return JSONResponse(
            {"error": "internal_error", "detail": "Error interno del servidor"},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    return app


app = create_app()
