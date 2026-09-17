"""
Pipeline orquestador de CyberSentinel.

Une los componentes en un único flujo operativo:

    telemetría → normalización → Sigma → ML → correlación temporal → evidencia
    → ATT&CK → CTI → RAG → explicación → gobernanza → auditoría → HITL

Principios de esta capa, que son los que hacen que el resultado sea evidencia y
no una apariencia de evidencia:

1. **Ningún componente simulado.** No hay modelos de mentira ni constantes
   haciendo de señal. Si un componente no está disponible no se sustituye por un
   doble: se declara ausente.
2. **Toda etapa deja registro.** Cada evento produce una traza con el estado de
   cada etapa (OK, NO_DATA, DISABLED, UNAVAILABLE, ERROR) y si hubo respaldo. Una
   etapa que falla en silencio es indistinguible de una que funciona.
3. **Nunca se fabrica evidencia.** Cuando un componente no aporta, el campo queda
   vacío y su estado lo explica.
4. **Trazabilidad completa.** `run_id` identifica la ejecución y `event_ref` el
   evento concreto, de modo que cualquier conclusión puede reconstruirse.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np

from .analytics.deviation import DeviationDetector
from .analytics.profiler import EntityProfiler
from .analytics.risk_score import PROACTIVE_ALERT_THRESHOLD, RiskScoreTracker
from .config import DEFAULT_MARKOV_MODEL_PATH, ROOT, Settings
from .correlation import mitre
from .correlation.correlator import Correlator, Finding
from .correlation.sequence_model import CanonicalBaseline, MarkovChainModel, SequenceModel
from .cti.abuseipdb import AbuseIPDBFeed
from .cti.cache import CTICache
from .cti.enricher import LiveCTIEnricher
from .cti.enrichment import CTIEnricher
from .cti.otx import OTXFeed
from .cti.stix_ingestor import StixIngestor
from .detection.anomaly import AnomalyDetector
from .detection.hybrid import DetectionEvidence, RetrievedContext
from .detection.rules_engine import RuleHit, RulesEngine
from .detection.temporal import TemporalCorrelator
from .governance.audit import AuditLog
from .governance.dataset_manager import DatasetManager
from .governance.policy import Decision, GovernancePolicy
from .ingestion import Normalizer
from .llm.explainer import LLMExplainer
from .llm.providers import build_chat_model
from .observability import StageStatus, TraceContext, new_run_id
from .rag.embeddings import LocalLSAEmbeddings
from .rag.vector_store import RAGStore
from .response import ActionType, ResponseAction, ResponseExecutor, ResponsePlanner, ResponseStore
from .schema import SecurityEvent

logger = logging.getLogger(__name__)

DEFAULT_CTI_DIR = ROOT / "data" / "cti"
DEFAULT_KNOWLEDGE_DIR = ROOT / "data" / "knowledge"
DEFAULT_SEQUENCES = ROOT / "config" / "sequences.yaml"

#: Puntuación híbrida a partir de la cual un evento se considera hallazgo.
#:
#: La comparación es `>=`, no `>`. Con `>` una coincidencia de regla determinista
#: —que puntúa exactamente 50.0— no llegaba a ser hallazgo, de modo que la
#: configuración "solo Sigma" del estudio de ablación no podía detectar nada por
#: construcción. Una regla que casa es una detección.
ALERT_THRESHOLD = 50.0

#: Traduce el vocabulario de `ResponsePlanner` (governance/policy.py) al de
#: `ActionType` (response/executor.py). "enrich_context" no tiene ejecutor
#: real definido a propósito: es puramente informativo, no dispara nada.
RESPONSE_ACTION_MAP: dict[str, "ActionType"] = {
    "notify_analyst": ActionType.SEND_WEBHOOK_ALERT,
    "snapshot_evidence": ActionType.CREATE_TICKET,
    "block_ip": ActionType.BLOCK_IP,
    "isolate_host": ActionType.ISOLATE_HOST,
    "disable_account": ActionType.DISABLE_ACCOUNT,
    "reset_password": ActionType.RESET_PASSWORD,
}


@dataclass
class IncidentResult:
    """Resultado por evento: evidencia, explicación, traza y contramedidas."""

    evidence: DetectionEvidence
    narrative: str
    trace: TraceContext
    recommendations: list[Any] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence": self.evidence.to_dict(),
            "narrative": self.narrative,
            "trace": self.trace.to_dict(),
            "recommendations": [r.to_dict() for r in self.recommendations],
        }


@dataclass
class PipelineReport:
    total_events: int
    total_findings: int
    results: list[IncidentResult] = field(default_factory=list)
    anomaly_threshold_used: float | None = None
    run_id: str = ""
    #: Estado de cada componente al arrancar: qué se pudo ejecutar realmente.
    component_status: dict[str, str] = field(default_factory=dict)
    #: Secuencias de ataque detectadas por la correlación temporal.
    correlated_incidents: list[dict[str, Any]] = field(default_factory=list)
    #: Predicciones de kill-chain (Fase 4-D): un incidente correlacionado por
    #: entidad/ventana, con la fase siguiente más probable ya reponderada por
    #: contexto (tipo de entidad, severidad, velocidad, CTI).
    kill_chain_predictions: list[dict[str, Any]] = field(default_factory=list)
    #: Alertas proactivas (Fase 4-D, tarea D3): entidades cuyo risk score
    #: acumulado cruzó el umbral en este lote, antes de que exista un
    #: incidente que las dispare.
    proactive_alerts: list[dict[str, Any]] = field(default_factory=list)
    #: Coste en milisegundos de las fases que se ejecutan **por lote**, no por
    #: evento: Sigma con agregación, correlación y ajuste/puntuación del modelo
    #: necesitan ver la serie entera. La traza por evento no puede medirlas —solo
    #: ve la consulta al resultado ya calculado— así que sin esto un desglose de
    #: latencia atribuye una fracción mínima del tiempo real y el resto
    #: desaparece. Se mide donde ocurre.
    batch_timings_ms: dict[str, float] = field(default_factory=dict)

    @property
    def findings(self) -> list[IncidentResult]:
        """Solo los eventos que superaron el umbral de alerta."""
        return [r for r in self.results if r.evidence.hybrid_score >= ALERT_THRESHOLD]

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "total_events": self.total_events,
            "total_findings": self.total_findings,
            "num_incidents": len(self.results),
            "anomaly_threshold_used": (
                round(self.anomaly_threshold_used, 4)
                if self.anomaly_threshold_used is not None else None
            ),
            "component_status": self.component_status,
            "batch_timings_ms": {k: round(v, 4) for k, v in self.batch_timings_ms.items()},
            "correlated_incidents": self.correlated_incidents,
            "kill_chain_predictions": self.kill_chain_predictions,
            "proactive_alerts": self.proactive_alerts,
            "incidents": [r.to_dict() for r in self.results],
        }


class Pipeline:
    """Orquestador principal, con banderas de ablación para el benchmark."""

    def __init__(
        self,
        rules_dir: str | Path,
        sigma_rules_dir: str | Path | None = None,
        settings: Settings | None = None,
        # Banderas de ablación
        enable_ml: bool = True,
        enable_temporal: bool = True,
        enable_cti: bool = True,
        enable_rag: bool = True,
        enable_llm: bool = True,
        enable_behavior: bool = True,
        #: Apagado por defecto a propósito: implica llamadas de red reales a
        #: servicios externos (AbuseIPDB, OTX) y consumo de cuota gratuita.
        #: A diferencia de enable_ml/enable_temporal (cómputo local), esto no
        #: debe activarse por accidente en una prueba o en un batch offline.
        enable_live_cti: bool = False,
        #: Correlación de hallazgos en incidentes + predicción de kill-chain
        #: (Fase 4-D). Cómputo local puro: seguro por defecto, a diferencia
        #: de enable_live_cti.
        enable_kill_chain_prediction: bool = True,
        anomaly_threshold: float | None = None,
        # Fuentes de datos (todas con valor por defecto en el repositorio)
        cti_dir: str | Path | None = None,
        knowledge_dir: str | Path | None = None,
        sequences_path: str | Path | None = None,
        baseline_path: str | Path | None = None,
        live_cti_cache_path: str | Path | None = None,
        live_cti_feeds: list[Any] | None = None,
        markov_model_path: str | Path | None = DEFAULT_MARKOV_MODEL_PATH,
        risk_score_path: str | Path | None = None,
        #: Ejecución real de respuesta Nivel 1 (Fase 4-E). Seguro por
        #: defecto: DRY_RUN=true global y cada integración es NOT_CONFIGURED
        #: sin credenciales, igual que enable_live_cti.
        enable_response_execution: bool = True,
        response_store_path: str | Path | None = None,
        response_executor: Any | None = None,
        # Gobernanza y auditoría
        policy: GovernancePolicy | None = None,
        audit_path: str | Path | None = None,
        # Inyección (pruebas y otros proveedores)
        embeddings: Any | None = None,
        chat_model: Any | None = None,
        run_id: str | None = None,
        **kwargs: Any,
    ) -> None:
        if kwargs:
            # Antes se tragaban en silencio: `policy` y `audit_path` se perdían
            # sin que nadie lo notara, y con ellos la capa de gobernanza entera.
            logger.warning(
                "Argumentos no reconocidos por Pipeline (se ignoran): %s",
                ", ".join(sorted(kwargs)),
            )

        self.settings = settings or Settings.load()
        self.run_id = run_id or new_run_id()

        self.enable_ml = enable_ml
        self.enable_temporal = enable_temporal
        self.enable_cti = enable_cti
        self.enable_rag = enable_rag
        self.enable_llm = enable_llm
        self.enable_behavior = enable_behavior
        self.enable_live_cti = enable_live_cti
        self.anomaly_threshold = anomaly_threshold or self.settings.detection.anomaly_threshold

        self.component_status: dict[str, str] = {}

        self.normalizer = Normalizer()
        self.rules_engine = RulesEngine.from_directory(rules_dir)
        self._sigma_rules_loaded = 0
        if sigma_rules_dir is not None:
            sigma_dir = Path(sigma_rules_dir)
            if sigma_dir.is_dir():
                sigma_rules = RulesEngine.from_sigma_directory(sigma_dir).rules
                self.rules_engine.rules += sigma_rules
                self._sigma_rules_loaded = len(sigma_rules)
            else:
                logger.warning(
                    "sigma_rules_dir=%s no existe; se ignoran las reglas Sigma públicas.",
                    sigma_dir,
                )
        self.component_status["sigma"] = (
            f"OK ({len(self.rules_engine.rules)} reglas: "
            f"{len(self.rules_engine.rules) - self._sigma_rules_loaded} propias + "
            f"{self._sigma_rules_loaded} pySigma)"
        )

        self.anomaly_detector = AnomalyDetector() if enable_ml else None
        self.component_status["ml"] = "OK" if enable_ml else "DISABLED"

        self.stix_ingestor: StixIngestor | None = None
        self.temporal_correlator = self._build_temporal(sequences_path) if enable_temporal else None
        self.cti_enricher = self._build_cti(cti_dir) if enable_cti else None
        self.rag_store = self._build_rag(knowledge_dir, embeddings) if enable_rag else None
        self.llm_explainer = self._build_llm(chat_model) if enable_llm else None

        self.baseline_path = Path(baseline_path) if baseline_path else None
        self.profiler = EntityProfiler(path=self.baseline_path) if enable_behavior else None
        self.deviation_detector = DeviationDetector() if enable_behavior else None
        self.component_status["behavior"] = (
            "OK (perfiles vacíos: aprende desde el primer evento)" if enable_behavior
            else "DISABLED"
        )

        self.live_cti_enricher = (
            self._build_live_cti(live_cti_cache_path, live_cti_feeds)
            if enable_live_cti else None
        )
        if not enable_live_cti:
            self.component_status["live_cti"] = "DISABLED"

        self.enable_kill_chain_prediction = enable_kill_chain_prediction
        self.correlator = (
            self._build_correlator(markov_model_path) if enable_kill_chain_prediction else None
        )
        if not enable_kill_chain_prediction:
            self.component_status["kill_chain_prediction"] = "DISABLED"

        self.risk_tracker = RiskScoreTracker(path=risk_score_path)
        self.component_status["risk_score"] = "OK"

        for nombre, activo in (
            ("temporal", enable_temporal), ("cti", enable_cti),
            ("rag", enable_rag), ("llm", enable_llm),
        ):
            if not activo:
                self.component_status[nombre] = "DISABLED"

        # Gobernanza: qué contramedidas son admisibles y bajo qué condición.
        self.policy = policy or GovernancePolicy()
        self.planner = ResponsePlanner(self.policy)
        self.audit = AuditLog(audit_path) if audit_path else None
        self.component_status["audit"] = "OK" if self.audit else "DISABLED"

        self.enable_response_execution = enable_response_execution
        if response_executor is not None:
            self.response_executor = response_executor
        elif enable_response_execution:
            ruta_store: str | Path = (
                response_store_path if response_store_path
                else Path(audit_path).with_name("response_actions.db") if audit_path
                else ":memory:"
            )
            self.response_executor = ResponseExecutor(
                store=ResponseStore(ruta_store), audit=self.audit,
            )
        else:
            self.response_executor = None
        self.component_status["response_execution"] = (
            f"OK (dry_run={self.response_executor.global_dry_run})"
            if self.response_executor else "DISABLED"
        )

        # Sumidero de decisiones humanas (HITL).
        self.dataset_manager = DatasetManager()

    # --- Construcción de componentes -----------------------------------------
    def _build_temporal(self, sequences_path: str | Path | None) -> TemporalCorrelator:
        path = Path(sequences_path) if sequences_path else DEFAULT_SEQUENCES
        correlator = TemporalCorrelator.from_yaml(path)
        self.component_status["temporal"] = (
            f"OK ({len(correlator.rules)} secuencias)" if correlator.rules
            else "NO_DATA (sin reglas de secuencia)"
        )
        return correlator

    def _build_cti(self, cti_dir: str | Path | None) -> CTIEnricher:
        """Carga los bundles STIX disponibles. Sin indicadores, CTI no aporta."""
        directory = Path(cti_dir) if cti_dir else DEFAULT_CTI_DIR
        ingestor = StixIngestor()
        bundles = 0
        if directory.exists():
            for archivo in sorted(directory.glob("*.json")):
                ingestor.load_from_file(archivo)
                bundles += 1

        if not ingestor.indicators:
            self.component_status["cti"] = f"NO_DATA (sin indicadores en {directory})"
            logger.warning(
                "CTI habilitado pero sin indicadores cargados desde %s: no habra "
                "coincidencias.", directory,
            )
        else:
            self.component_status["cti"] = (
                f"OK ({len(ingestor.indicators)} indicadores de {bundles} bundle(s))"
            )
        self.stix_ingestor = ingestor
        return CTIEnricher(ingestor)

    def _build_live_cti(self, cache_path: str | Path | None,
                        feeds: list[Any] | None) -> LiveCTIEnricher:
        """
        Feeds CTI en vivo (AbuseIPDB, OTX). Sin API key configurada
        (`CYBERSENTINEL_ABUSEIPDB_KEY`/`CYBERSENTINEL_OTX_KEY`), los clientes
        se construyen igual —son reales, no mocks— pero cada consulta
        devuelve `NOT_CONFIGURED` en vez de simular un resultado limpio.
        """
        feeds = feeds if feeds is not None else [AbuseIPDBFeed(), OTXFeed()]
        cache = CTICache(path=cache_path)
        configurados = [f.name for f in feeds if f.configured]
        if configurados:
            self.component_status["live_cti"] = f"OK (feeds activos: {', '.join(configurados)})"
        else:
            self.component_status["live_cti"] = (
                "NOT_CONFIGURED (sin API key: CYBERSENTINEL_ABUSEIPDB_KEY / "
                "CYBERSENTINEL_OTX_KEY). Clientes reales, sin key configurada."
            )
        return LiveCTIEnricher(feeds=feeds, cache=cache)

    def _build_correlator(self, markov_model_path: str | Path | None) -> Correlator:
        """
        Correlación de hallazgos + predicción de kill-chain (Fase 4-D).

        Con un modelo de Markov entrenado disponible (`cybersentinel
        train-prediction`), la predicción es probabilística y medible; sin
        él, `Correlator` ya cae por su cuenta a `CanonicalBaseline` (la
        heurística del orden canónico), que es honesta sobre no tener una
        probabilidad real detrás.
        """
        sequence_model: SequenceModel | None = None
        if markov_model_path:
            ruta = Path(markov_model_path)
            if ruta.exists():
                try:
                    sequence_model = MarkovChainModel.load(ruta)
                except (OSError, ValueError, KeyError) as exc:
                    logger.warning(
                        "No se pudo cargar el modelo de Markov en %s (%s); "
                        "se usa CanonicalBaseline.", ruta, exc,
                    )
        self.component_status["kill_chain_prediction"] = (
            f"OK ({sequence_model.name if sequence_model else 'canonical-baseline'})"
        )
        return Correlator(sequence_model=sequence_model)

    def _build_rag(self, knowledge_dir: str | Path | None, embeddings: Any | None) -> RAGStore:
        """
        Indexa el corpus de conocimiento con embeddings reales.

        Sin ingesta, `RAGStore.retrieve()` devuelve siempre una lista vacía: el
        componente existiría sin participar. Aquí se indexa de verdad, o se
        declara que no hay corpus.
        """
        directory = Path(knowledge_dir) if knowledge_dir else DEFAULT_KNOWLEDGE_DIR
        modelo = embeddings if embeddings is not None else LocalLSAEmbeddings()
        store = RAGStore(modelo)

        if not directory.exists():
            self.component_status["rag"] = f"NO_DATA (no existe {directory})"
            logger.warning("RAG habilitado pero no existe el corpus en %s.", directory)
            return store

        store.ingest_directory(directory, ext="*.md")
        if store.vectorstore is None:
            self.component_status["rag"] = f"NO_DATA (corpus vacio en {directory})"
        else:
            nombre = getattr(modelo, "name", type(modelo).__name__)
            self.component_status["rag"] = (
                f"OK ({len(store.indexed_hashes)} documentos, embeddings {nombre})"
            )
        return store

    def _build_llm(self, chat_model: Any | None) -> LLMExplainer:
        """
        Usa el modelo real si hay credenciales; si no, respaldo determinista.

        Nunca se construye un modelo de mentira: `LLMExplainer` acepta None y lo
        declara en el estado de cada explicación.
        """
        modelo = chat_model if chat_model is not None else build_chat_model(
            self.settings.explanation.model
        )
        if modelo is None:
            self.component_status["llm"] = (
                "UNAVAILABLE (sin credenciales de Anthropic; explicacion determinista)"
            )
            return LLMExplainer(None)
        nombre = (
            "inyectado" if chat_model is not None
            else f"claude:{self.settings.explanation.model}"
        )
        self.component_status["llm"] = f"OK ({nombre})"
        return LLMExplainer(modelo, provider_name=nombre)

    # --- Ejecución ------------------------------------------------------------
    def _rag_query(self, event: SecurityEvent, hits: list[RuleHit]) -> str:
        """
        Construye la consulta desde el evento, no desde una cadena fija.

        El pipeline anterior consultaba literalmente "query", así que el contexto
        recuperado no guardaba relación alguna con el evento analizado.
        """
        partes = [f"{h.rule.mitre_technique} {h.rule.title}" for h in hits]
        if event.command_line:
            partes.append(event.command_line[:200])
        if event.process_name:
            partes.append(event.process_name)
        partes.append(f"{event.category} {event.action}")
        if event.dst_port:
            partes.append(f"puerto {event.dst_port}")
        return " ".join(partes)

    @staticmethod
    def _entity_of(event: SecurityEvent) -> str:
        return event.host or event.user or event.src_ip or "desconocida"

    def _dispatch_response_actions(self, evidence: DetectionEvidence, event: SecurityEvent,
                                   recomendaciones: list[Any]) -> None:
        """
        Traduce las recomendaciones ya clasificadas (ALLOWED/REQUIRES_APPROVAL/
        PROHIBITED) en `ResponseAction`s reales. PROHIBITED nunca llega
        aquí como acción — ni se genera, ni se audita como intento: la
        política ya la descartó en `ResponsePlanner`.
        """
        objetivo = {
            "host": event.host, "user": event.user,
            "ip": event.dst_ip or event.src_ip, "entity": evidence.entity,
        }
        for rec in recomendaciones:
            if rec.verdict.decision == Decision.PROHIBITED:
                continue
            tipo = RESPONSE_ACTION_MAP.get(rec.verdict.action.action_type)
            if tipo is None:
                continue
            accion = ResponseAction(
                incident_id=evidence.event_id, action_type=tipo, target=objetivo,
                justification=rec.verdict.action.reason or rec.verdict.explanation,
                requested_by="pipeline",
            )
            self.response_executor.request_action(accion)

            # Nivel 1 complementario: si se recomienda bloquear una IP, se
            # registra ya mismo en la lista local de bloqueo (rápido, local,
            # reversible) mientras la regla de firewall en sí espera
            # aprobación humana (Nivel 2, más arriba).
            if rec.verdict.action.action_type == "block_ip" and objetivo["ip"]:
                self.response_executor.request_action(ResponseAction(
                    incident_id=evidence.event_id, action_type=ActionType.BLOCK_IOC_LOCAL,
                    target=objetivo, justification=rec.verdict.action.reason,
                    requested_by="pipeline",
                ))

    def run_events(self, events: list[SecurityEvent]) -> PipelineReport:
        import time as _time

        results: list[IncidentResult] = []
        findings_count = 0
        tiempos_lote: dict[str, float] = {}

        # --- Reglas sobre la serie completa ---------------------------------
        # `evaluate` incluye las reglas con agregación temporal (fuerza bruta,
        # balizas C2), que `evaluate_event` no puede resolver por definición:
        # necesitan ver varios eventos a la vez.
        _t = _time.perf_counter()
        todos_los_hits = self.rules_engine.evaluate(events)
        hits_por_evento: dict[str, list[RuleHit]] = {}
        for hit in todos_los_hits:
            hits_por_evento.setdefault(hit.event.fingerprint(), []).append(hit)
        tiempos_lote["sigma_batch"] = (_time.perf_counter() - _t) * 1000.0

        # --- Correlación temporal sobre todos los hits -----------------------
        incidentes_correlados: list[dict[str, Any]] = []
        secuencias_por_evento: dict[str, list[str]] = {}
        _t = _time.perf_counter()
        if self.enable_temporal and self.temporal_correlator:
            self.temporal_correlator.clear()
            self.temporal_correlator.observe_batch(todos_los_hits)
            for incidente in self.temporal_correlator.correlate():
                incidentes_correlados.append(incidente.to_dict())
                etiqueta = (
                    f"{incidente.name} [{' -> '.join(incidente.matched_sequence)}] "
                    f"(confianza {incidente.confidence:.2f})"
                )
                for hit in incidente.hits:
                    secuencias_por_evento.setdefault(
                        hit.event.fingerprint(), []
                    ).append(etiqueta)

        tiempos_lote["temporal_batch"] = (_time.perf_counter() - _t) * 1000.0

        # --- Detector de anomalías -------------------------------------------
        puntuaciones: dict[str, float] = {}
        resultados_anomalia: list[Any] = []
        _t = _time.perf_counter()
        if self.enable_ml and self.anomaly_detector:
            from .ml.base import Dataset

            if not self.anomaly_detector.is_fitted:
                self.anomaly_detector.fit(Dataset(X=np.array([]), events=events))
            if self.anomaly_detector.is_fitted:
                resultados_anomalia = list(self.anomaly_detector.score(events))
                for resultado in resultados_anomalia:
                    puntuaciones[resultado.event.fingerprint()] = resultado.anomaly_score

        tiempos_lote["ml_batch"] = (_time.perf_counter() - _t) * 1000.0

        # --- Por evento -------------------------------------------------------
        # Entidades con contexto CTI de campaña conocida (Fase 4-D): alimenta
        # tanto el reponderado de la predicción de kill-chain como, en el
        # futuro, cualquier otra etapa que quiera saber "¿esto ya se sabe
        # asociado a un actor?" sin tener que releer cti_hits/live_cti_hits.
        apt_flagged_entities: set[str] = set()
        _t = _time.perf_counter()
        for ev in events:
            ref = ev.fingerprint()
            trace = TraceContext(event_id=ev.event_id, run_id=self.run_id, event_ref=ref)

            # 1. Sigma
            trace.start("sigma")
            rule_hits = hits_por_evento.get(ref, [])
            trace.end(
                "sigma",
                StageStatus.OK if rule_hits else StageStatus.NO_DATA,
                detail=f"{len(rule_hits)} regla(s) activada(s)",
            )

            # 2. ML
            anomaly_score = 0.0
            if not self.enable_ml or not self.anomaly_detector:
                trace.skipped("ml")
            else:
                trace.start("ml")
                if ref in puntuaciones:
                    anomaly_score = puntuaciones[ref]
                    trace.end("ml", StageStatus.OK, detail=f"score {anomaly_score:.4f}")
                else:
                    trace.end(
                        "ml", StageStatus.UNAVAILABLE,
                        detail="modelo sin entrenar: datos insuficientes para la linea base",
                    )

            # 3. Correlación temporal
            temp_context: list[str] = []
            if not self.enable_temporal or not self.temporal_correlator:
                trace.skipped("temporal")
            else:
                trace.start("temporal")
                temp_context = secuencias_por_evento.get(ref, [])
                trace.end(
                    "temporal",
                    StageStatus.OK if temp_context else StageStatus.NO_DATA,
                    detail=f"{len(temp_context)} secuencia(s)",
                )

            # 4. ATT&CK observado experimentalmente (no cobertura estructural):
            # solo técnicas cuyas reglas se activaron sobre este evento.
            tecnicas: list[str] = []
            tacticas: list[str] = []
            for hit in rule_hits:
                tecnica = hit.rule.mitre_technique
                if tecnica and tecnica != "unknown" and tecnica not in tecnicas:
                    tecnicas.append(tecnica)
                    for tactica in (mitre.tactics_of(tecnica) or [hit.rule.mitre_tactic]):
                        if tactica and tactica != "unknown" and tactica not in tacticas:
                            tacticas.append(tactica)

            # 5. CTI
            cti_hits: list[Any] = []
            if not self.enable_cti or not self.cti_enricher:
                trace.skipped("cti")
            else:
                trace.start("cti")
                cti_hits = self.cti_enricher.enrich_event(ev)
                trace.end(
                    "cti",
                    StageStatus.OK if cti_hits else StageStatus.NO_DATA,
                    detail=f"{len(cti_hits)} coincidencia(s)" if cti_hits else "CTI_MATCH=NONE",
                )

            # 5.5 Behavioral analytics (Fase 4-B): se evalúa contra el
            # baseline TAL COMO ESTABA antes de este evento; el propio evento
            # se aprende después (más abajo), no antes de compararse consigo
            # mismo.
            desviaciones: list[Any] = []
            if not self.enable_behavior or not self.deviation_detector:
                trace.skipped("behavior")
            else:
                trace.start("behavior")
                desviaciones = self.deviation_detector.evaluate(ev, self.profiler)
                trace.end(
                    "behavior",
                    StageStatus.OK if desviaciones else StageStatus.NO_DATA,
                    detail=f"{len(desviaciones)} desviación(es)" if desviaciones
                    else "sin desviaciones frente al baseline",
                )

            # 5.6 CTI en vivo (Fase 4-C): solo se consulta si el evento ya
            # trae alguna señal propia. Consultar AbuseIPDB/OTX por cada
            # evento —la inmensa mayoría benignos— agotaría la cuota
            # gratuita (1.000/día) en minutos y no es lo que pide el prompt:
            # "cuando CyberSentinel detecta un evento sospechoso".
            live_cti_hits: list[Any] = []
            hay_senal_previa = bool(rule_hits) or anomaly_score >= 0.5 or bool(desviaciones)
            if not self.enable_live_cti or not self.live_cti_enricher:
                trace.skipped("live_cti")
            elif not hay_senal_previa:
                trace.end("live_cti", StageStatus.NO_DATA,
                         detail="sin señal previa; no se consulta para ahorrar cuota")
            else:
                trace.start("live_cti")
                live_cti_hits = self.live_cti_enricher.enrich_event(ev).results
                consultados = [r for r in live_cti_hits if r.status != "NOT_CONFIGURED"]
                trace.end(
                    "live_cti",
                    StageStatus.OK if consultados else StageStatus.UNAVAILABLE,
                    detail=(f"{len(consultados)} consulta(s) real(es)" if consultados
                           else "feeds sin API key configurada"),
                )

            evidence = DetectionEvidence(
                event_id=ev.event_id,
                run_id=self.run_id,
                event_ref=ref,
                entity=self._entity_of(ev),
                rule_matches=rule_hits,
                anomaly_score=anomaly_score,
                temporal_context=temp_context,
                mitre_context=tecnicas,
                mitre_tactics=tacticas,
                cti_hits=cti_hits,
                behavioral_deviations=desviaciones,
                live_cti_hits=live_cti_hits,
            )

            if self.enable_behavior and self.profiler:
                self.profiler.observe(ev)

            # 5.7 Risk score persistente por entidad (Fase 4-D, tarea D2) y
            # marca de contexto CTI (alimenta el reponderado de kill-chain
            # más abajo). Solo se registra si hubo alguna señal: un evento
            # sin nada detectado no es "una detección" que deba mover el
            # risk score de nadie.
            entidad = evidence.entity
            cti_confirmado = any(
                {"nation-state", "c2"} & set(h.indicator.labels) for h in cti_hits
            ) or any(
                getattr(h, "malicious", False) and (getattr(h, "score", 0) or 0) >= 75
                for h in live_cti_hits
            )
            if cti_confirmado and entidad:
                apt_flagged_entities.add(entidad)
            if entidad and evidence.hybrid_score > 0:
                self.risk_tracker.record_detection(
                    entidad, evidence.hybrid_score, when=ev.timestamp,
                    cti_confirmed=cti_confirmado, reason=evidence.detection_status,
                )

            # 6. RAG
            rag_docs: list[Any] = []
            if not self.enable_rag or not self.rag_store:
                trace.skipped("rag")
            else:
                trace.start("rag")
                try:
                    # Anclada en las técnicas ya identificadas: si sabemos que
                    # el evento es T1110, el documento de T1110 debe estar en el
                    # contexto, no depender de que el vector lo encuentre.
                    rag_docs = self.rag_store.retrieve_grounded(
                        self._rag_query(ev, rule_hits), anchors=tecnicas, k=3
                    )
                    trace.end(
                        "rag",
                        StageStatus.OK if rag_docs else StageStatus.NO_DATA,
                        detail=f"{len(rag_docs)} fragmento(s)",
                    )
                except Exception as exc:
                    logger.error("Fallo en la recuperacion RAG: %s", exc)
                    trace.end("rag", StageStatus.ERROR, detail=str(exc)[:120])
                evidence.rag_context = [
                    RetrievedContext(
                        source_uri=d.metadata.get("source_uri", "desconocida"),
                        filename=d.metadata.get("filename", ""),
                        excerpt=d.page_content,
                    )
                    for d in rag_docs
                ]

            # 7. Explicación
            if not self.enable_llm or not self.llm_explainer:
                trace.skipped("llm")
                evidence.llm_status = "DISABLED"
                narrative = ""
            else:
                trace.start("llm")
                try:
                    resultado = self.llm_explainer.explain(evidence, rag_docs)
                except Exception as exc:
                    # Un fallo del explicador no puede tumbar el analisis, pero
                    # tampoco puede pasar desapercibido: se registra como ERROR
                    # y la explicacion pasa a ser la determinista.
                    logger.error(
                        "El explicador fallo (%s): %s", type(exc).__name__, exc
                    )
                    from .llm.providers import ExplanationResult, deterministic_explanation
                    resultado = ExplanationResult(
                        text=deterministic_explanation(evidence),
                        status="ERROR", provider="deterministico", fallback_used=True,
                    )
                narrative = resultado.text
                evidence.explanation = resultado.text
                evidence.llm_status = resultado.status
                evidence.fallback_used = resultado.fallback_used
                try:
                    estado = StageStatus(resultado.status)
                except ValueError:
                    estado = StageStatus.OK
                trace.end(
                    "llm", estado,
                    detail=f"proveedor {resultado.provider}",
                    fallback_used=resultado.fallback_used,
                )

            evidence.stage_status = {s.name: s.status.value for s in trace.stages}

            # 8. Gobernanza: contramedidas propuestas y clasificadas
            recomendaciones = self.planner.plan(evidence)

            # 9. Respuesta (Fase 4-E): solo para hallazgos reales, no para
            # cada evento benigno que también pasa por el planner. Notificar
            # o generar comandos en el 100% del tráfico agotaría cuotas
            # reales (mismo razonamiento que el Bloque C con CTI en vivo) y
            # ahogaría al analista en ruido.
            if (self.enable_response_execution and self.response_executor
                    and evidence.hybrid_score >= ALERT_THRESHOLD):
                self._dispatch_response_actions(evidence, ev, recomendaciones)

            results.append(IncidentResult(
                evidence=evidence, narrative=narrative, trace=trace,
                recommendations=recomendaciones,
            ))

            if evidence.hybrid_score >= ALERT_THRESHOLD:
                findings_count += 1
                if self.audit:
                    self.audit.record(
                        actor="agent",
                        action="incident_analyzed",
                        detail={
                            "run_id": self.run_id,
                            "event_ref": ref,
                            "entity": evidence.entity,
                            "detection_status": evidence.detection_status,
                            "hybrid_score": round(evidence.hybrid_score, 2),
                            "rules": [h.rule.id for h in rule_hits],
                            "techniques": tecnicas,
                            "llm_status": evidence.llm_status,
                            "fallback_used": evidence.fallback_used,
                            "recommended_actions": [
                                r.verdict.to_dict() for r in recomendaciones
                            ],
                        },
                    )

        tiempos_lote["per_event_loop"] = (_time.perf_counter() - _t) * 1000.0

        # --- Kill-chain: correlación + predicción (Fase 4-D) ------------------
        kill_chain_predictions: list[dict[str, Any]] = []
        proactive_alerts: list[dict[str, Any]] = []
        _t = _time.perf_counter()
        if self.enable_kill_chain_prediction and self.correlator:
            # No se pasa self.anomaly_threshold: ese es el umbral de contaminación
            # del detector ("auto" incluido, puede ser None), un concepto
            # distinto del umbral 0..1 que build_findings necesita para decidir
            # qué anomalía es lo bastante severa como para ser un Finding.
            # Se deja el default de build_findings (0.6).
            findings = self.correlator.build_findings(todos_los_hits, resultados_anomalia)
            if findings:
                incidentes_kc = self.correlator.correlate(
                    findings, apt_flagged_entities=apt_flagged_entities)
                kill_chain_predictions = [
                    inc.to_dict() for inc in incidentes_kc if inc.prediction is not None
                ]
        tiempos_lote["kill_chain_batch"] = (_time.perf_counter() - _t) * 1000.0

        # --- Alertas proactivas por risk score (Fase 4-D, tarea D3) ----------
        # Antes de que exista un incidente: cualquier entidad que este lote
        # haya tocado y cuyo risk score acumulado cruce el umbral.
        for entidad in sorted(apt_flagged_entities | {r.evidence.entity for r in results}):
            if self.risk_tracker.due_proactive_alert(entidad):
                score = self.risk_tracker.score_for(entidad)
                alerta = {
                    "entity": entidad, "risk_score": round(score, 1),
                    "threshold": PROACTIVE_ALERT_THRESHOLD,
                    "message": (
                        f"{entidad} tiene risk score {score:.0f}/100, "
                        "recomendamos investigación proactiva."
                    ),
                }
                proactive_alerts.append(alerta)
                logger.warning("Alerta proactiva: %s", alerta["message"])
                if self.audit:
                    self.audit.record(actor="pipeline", action="proactive_risk_alert",
                                      detail=alerta)

        tiempos_lote["total"] = sum(tiempos_lote.values())

        # Persistir lo aprendido en este lote. `save()` no hace nada si no
        # hay baseline_path/risk_score_path configurado (solo en memoria).
        if self.enable_behavior and self.profiler:
            self.profiler.save()
        self.risk_tracker.save()

        return PipelineReport(
            total_events=len(events),
            total_findings=findings_count,
            results=results,
            anomaly_threshold_used=self.anomaly_threshold,
            run_id=self.run_id,
            component_status=dict(self.component_status),
            correlated_incidents=incidentes_correlados,
            kill_chain_predictions=kill_chain_predictions,
            proactive_alerts=proactive_alerts,
            batch_timings_ms=tiempos_lote,
        )

    def run_file(self, jsonl_path: str | Path) -> PipelineReport:
        events = self.normalizer.from_jsonl(jsonl_path)
        return self.run_events(events)
