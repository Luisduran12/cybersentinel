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

from .config import ROOT, Settings
from .correlation import mitre
from .cti.enrichment import CTIEnricher
from .cti.stix_ingestor import StixIngestor
from .detection.anomaly import AnomalyDetector
from .detection.hybrid import DetectionEvidence, RetrievedContext
from .detection.rules_engine import RuleHit, RulesEngine
from .detection.temporal import TemporalCorrelator
from .governance.audit import AuditLog
from .governance.dataset_manager import DatasetManager
from .governance.policy import GovernancePolicy
from .ingestion import Normalizer
from .llm.explainer import LLMExplainer
from .llm.providers import build_chat_model
from .observability import StageStatus, TraceContext, new_run_id
from .rag.embeddings import LocalLSAEmbeddings
from .rag.vector_store import RAGStore
from .response import ResponsePlanner
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
            "incidents": [r.to_dict() for r in self.results],
        }


class Pipeline:
    """Orquestador principal, con banderas de ablación para el benchmark."""

    def __init__(
        self,
        rules_dir: str | Path,
        settings: Settings | None = None,
        # Banderas de ablación
        enable_ml: bool = True,
        enable_temporal: bool = True,
        enable_cti: bool = True,
        enable_rag: bool = True,
        enable_llm: bool = True,
        anomaly_threshold: float | None = None,
        # Fuentes de datos (todas con valor por defecto en el repositorio)
        cti_dir: str | Path | None = None,
        knowledge_dir: str | Path | None = None,
        sequences_path: str | Path | None = None,
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
        self.anomaly_threshold = anomaly_threshold or self.settings.detection.anomaly_threshold

        self.component_status: dict[str, str] = {}

        self.normalizer = Normalizer()
        self.rules_engine = RulesEngine.from_directory(rules_dir)
        self.component_status["sigma"] = f"OK ({len(self.rules_engine.rules)} reglas)"

        self.anomaly_detector = AnomalyDetector() if enable_ml else None
        self.component_status["ml"] = "OK" if enable_ml else "DISABLED"

        self.stix_ingestor: StixIngestor | None = None
        self.temporal_correlator = self._build_temporal(sequences_path) if enable_temporal else None
        self.cti_enricher = self._build_cti(cti_dir) if enable_cti else None
        self.rag_store = self._build_rag(knowledge_dir, embeddings) if enable_rag else None
        self.llm_explainer = self._build_llm(chat_model) if enable_llm else None

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
        _t = _time.perf_counter()
        if self.enable_ml and self.anomaly_detector:
            from .ml.base import Dataset

            if not self.anomaly_detector.is_fitted:
                self.anomaly_detector.fit(Dataset(X=np.array([]), events=events))
            if self.anomaly_detector.is_fitted:
                for resultado in self.anomaly_detector.score(events):
                    puntuaciones[resultado.event.fingerprint()] = resultado.anomaly_score

        tiempos_lote["ml_batch"] = (_time.perf_counter() - _t) * 1000.0

        # --- Por evento -------------------------------------------------------
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
        tiempos_lote["total"] = sum(tiempos_lote.values())

        return PipelineReport(
            total_events=len(events),
            total_findings=findings_count,
            results=results,
            anomaly_threshold_used=self.anomaly_threshold,
            run_id=self.run_id,
            component_status=dict(self.component_status),
            correlated_incidents=incidentes_correlados,
            batch_timings_ms=tiempos_lote,
        )

    def run_file(self, jsonl_path: str | Path) -> PipelineReport:
        events = self.normalizer.from_jsonl(jsonl_path)
        return self.run_events(events)
