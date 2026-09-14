"""
Pipeline orquestador de CyberSentinel.

Une los módulos desacoplados en un flujo:

  ingesta -> detección (reglas + ML) -> correlación + predicción
          -> explicación -> gobernanza/recomendación -> auditoría

Cada incidente produce un objeto de resultado completo y trazable. Todo queda
registrado en el log de auditoría inmutable.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .ingestion import Normalizer
from .detection import RulesEngine, AnomalyDetector
from .correlation import Correlator, Incident
from .explanation import Explainer
from .governance import GovernancePolicy, AuditLog
from .response import ResponsePlanner, Recommendation
from .schema import SecurityEvent


@dataclass
class IncidentResult:
    incident: Incident
    narrative: Any
    recommendations: list[Recommendation]

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident": self.incident.to_dict(),
            "narrative": self.narrative.to_dict(),
            "recommendations": [r.to_dict() for r in self.recommendations],
        }


@dataclass
class PipelineReport:
    total_events: int
    total_findings: int
    results: list[IncidentResult] = field(default_factory=list)
    audit_integrity: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_events": self.total_events,
            "total_findings": self.total_findings,
            "num_incidents": len(self.results),
            "audit_integrity_ok": self.audit_integrity,
            "incidents": [r.to_dict() for r in self.results],
        }


class Pipeline:
    """Orquestador principal, configurable e inyectable (facilita las pruebas)."""

    def __init__(
        self,
        rules_dir: str | Path,
        policy: GovernancePolicy | None = None,
        audit_path: str | Path = "audit_log.jsonl",
        use_llm: bool = False,
        contamination: float = 0.08,
        time_window_minutes: int = 30,
        anomaly_threshold: float = 0.6,
    ) -> None:
        self.normalizer = Normalizer()
        self.rules_engine = RulesEngine.from_directory(rules_dir)
        self.anomaly_detector = AnomalyDetector(contamination=contamination)
        self.correlator = Correlator(time_window_minutes=time_window_minutes)
        self.explainer = Explainer(use_llm=use_llm)
        self.policy = policy or GovernancePolicy()
        self.planner = ResponsePlanner(self.policy)
        self.audit = AuditLog(audit_path)
        self.anomaly_threshold = anomaly_threshold

    def run_events(self, events: list[SecurityEvent]) -> PipelineReport:
        # 1. Detección por reglas
        rule_hits = self.rules_engine.evaluate(events)

        # 2. Detección de anomalías (entrena línea base con los mismos datos del lab)
        self.anomaly_detector.fit(events)
        anomalies = self.anomaly_detector.score(events)

        # 3. Correlación + predicción
        findings = self.correlator.build_findings(rule_hits, anomalies, self.anomaly_threshold)
        incidents = self.correlator.correlate(findings)

        # 4-6. Explicación, recomendación y auditoría por incidente
        results: list[IncidentResult] = []
        for inc in incidents:
            narrative = self.explainer.explain(inc)
            recs = self.planner.plan(inc)

            self.audit.record(
                actor="agent",
                action="incident_analyzed",
                detail={
                    "incident_id": inc.incident_id,
                    "entity": inc.entity,
                    "risk_score": inc.risk_score,
                    "techniques": inc.techniques,
                    "prediction": inc.prediction.to_dict() if inc.prediction else None,
                    "recommended_actions": [r.verdict.to_dict() for r in recs],
                },
            )
            results.append(IncidentResult(inc, narrative, recs))

        integrity, _ = self.audit.verify()
        return PipelineReport(
            total_events=len(events),
            total_findings=len(findings),
            results=results,
            audit_integrity=integrity,
        )

    def run_file(self, jsonl_path: str | Path) -> PipelineReport:
        events = self.normalizer.from_jsonl(jsonl_path)
        return self.run_events(events)
