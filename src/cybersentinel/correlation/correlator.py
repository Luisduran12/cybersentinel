"""
Correlación de hallazgos en incidentes + predicción de la fase siguiente.

Agrupa RuleHits y anomalías que comparten contexto (mismo host, usuario o IP y
proximidad temporal) en un Incident. Sobre cada incidente:

  - Reconstruye la secuencia de tácticas ATT&CK observadas.
  - Predice la(s) táctica(s) siguiente(s) probable(s) usando una matriz de
    transición (modelo tipo Markov) combinada con el orden canónico de la
    cadena de ataque.
  - Calcula una puntuación de riesgo agregada.

Esta es la parte diferenciadora del proyecto: pasar de "detecté X" a
"esto es la fase N de un ataque tipo Y y lo más probable es que siga Z".
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from ..detection.anomaly import AnomalyResult, severity_from_anomaly
from ..detection.rules_engine import RuleHit
from ..schema import SecurityEvent, Severity
from . import mitre


@dataclass
class Finding:
    """Hallazgo unificado: proviene de una regla o de una anomalía."""
    kind: str                       # "rule" | "anomaly"
    event: SecurityEvent
    severity: Severity
    confidence: float
    mitre_technique: str
    mitre_tactic: str
    title: str
    detail: str = ""

    @property
    def entity(self) -> str:
        """Entidad principal para agrupar (host > user > src_ip)."""
        return self.event.host or self.event.user or self.event.src_ip or "unknown"


@dataclass
class KillChainPrediction:
    """Predicción de la evolución del ataque."""
    current_tactic: str
    current_stage_index: int
    total_stages: int
    predicted_next: list[str]
    confidence: float
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "current_tactic": self.current_tactic,
            "current_tactic_es": mitre.TACTIC_LABELS_ES.get(self.current_tactic, self.current_tactic),
            "stage": f"{self.current_stage_index + 1}/{self.total_stages}",
            "predicted_next": [
                {"tactic": t, "tactic_es": mitre.TACTIC_LABELS_ES.get(t, t)}
                for t in self.predicted_next
            ],
            "confidence": round(self.confidence, 3),
            "rationale": self.rationale,
        }


@dataclass
class Incident:
    """Conjunto correlacionado de hallazgos que representan un posible ataque."""
    incident_id: str
    entity: str
    findings: list[Finding] = field(default_factory=list)
    prediction: KillChainPrediction | None = None

    @property
    def start(self):
        return min(f.event.timestamp for f in self.findings)

    @property
    def end(self):
        return max(f.event.timestamp for f in self.findings)

    @property
    def techniques(self) -> list[str]:
        seen, ordered = set(), []
        for f in sorted(self.findings, key=lambda x: x.event.timestamp):
            if f.mitre_technique not in seen and f.mitre_technique != "unknown":
                seen.add(f.mitre_technique)
                ordered.append(f.mitre_technique)
        return ordered

    @property
    def tactics(self) -> list[str]:
        seen, ordered = set(), []
        for f in sorted(self.findings, key=lambda x: x.event.timestamp):
            t = f.mitre_tactic
            if t not in seen and t not in ("unknown", ""):
                seen.add(t)
                ordered.append(t)
        return ordered

    @property
    def max_severity(self) -> Severity:
        return max((f.severity for f in self.findings), key=lambda s: s.score, default=Severity.INFO)

    @property
    def risk_score(self) -> int:
        """Riesgo agregado 0..100 (severidad + progresión en la cadena + volumen)."""
        if not self.findings:
            return 0
        sev = self.max_severity.score
        progression = 0
        if self.tactics:
            deepest = max(mitre.tactic_index(t) for t in self.tactics)
            progression = int((deepest / len(mitre.TACTIC_ORDER)) * 100) if deepest >= 0 else 0
        volume = min(len(self.findings) * 5, 30)
        return min(int(0.5 * sev + 0.35 * progression + 0.15 * volume), 100)

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "entity": self.entity,
            "start": self.start.isoformat(),
            "end": self.end.isoformat(),
            "num_findings": len(self.findings),
            "max_severity": self.max_severity.value,
            "risk_score": self.risk_score,
            "techniques": [
                {"id": t, "name": mitre.technique_name(t)} for t in self.techniques
            ],
            "tactics": self.tactics,
            "prediction": self.prediction.to_dict() if self.prediction else None,
        }


class Correlator:
    """Agrupa hallazgos en incidentes y predice la evolución de la cadena."""

    def __init__(self, time_window_minutes: int = 30) -> None:
        self.window = timedelta(minutes=time_window_minutes)

    def build_findings(
        self,
        rule_hits: list[RuleHit],
        anomalies: list[AnomalyResult],
        anomaly_threshold: float = 0.6,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for hit in rule_hits:
            findings.append(Finding(
                kind="rule",
                event=hit.event,
                severity=hit.rule.severity,
                confidence=hit.confidence,
                mitre_technique=hit.rule.mitre_technique,
                mitre_tactic=hit.rule.mitre_tactic,
                title=hit.rule.title,
                detail=hit.rule.description,
            ))
        for anom in anomalies:
            if anom.is_anomaly and anom.anomaly_score >= anomaly_threshold:
                feats = ", ".join(anom.top_features_es)
                findings.append(Finding(
                    kind="anomaly",
                    event=anom.event,
                    severity=severity_from_anomaly(anom.anomaly_score),
                    confidence=anom.anomaly_score,
                    mitre_technique="unknown",
                    mitre_tactic="unknown",
                    title="Comportamiento anómalo detectado por ML",
                    detail=(
                        f"Score {anom.anomaly_score:.2f} sobre un umbral de "
                        f"{anomaly_threshold:.2f}. Se desvía de la línea base en: {feats}."
                    ),
                ))
        return findings

    def correlate(self, findings: list[Finding]) -> list[Incident]:
        """Agrupa por entidad y ventana temporal."""
        by_entity: dict[str, list[Finding]] = defaultdict(list)
        for f in findings:
            by_entity[f.entity].append(f)

        incidents: list[Incident] = []
        counter = 1
        for entity, group in by_entity.items():
            group.sort(key=lambda x: x.event.timestamp)
            cluster: list[Finding] = []
            last_ts = None
            for f in group:
                if last_ts is not None and (f.event.timestamp - last_ts) > self.window:
                    incidents.append(self._make_incident(counter, entity, cluster))
                    counter += 1
                    cluster = []
                cluster.append(f)
                last_ts = f.event.timestamp
            if cluster:
                incidents.append(self._make_incident(counter, entity, cluster))
                counter += 1

        incidents.sort(key=lambda i: i.risk_score, reverse=True)
        return incidents

    def _make_incident(self, num: int, entity: str, findings: list[Finding]) -> Incident:
        inc = Incident(incident_id=f"INC-{num:04d}", entity=entity, findings=list(findings))
        inc.prediction = self._predict(inc)
        return inc

    def _predict(self, incident: Incident) -> KillChainPrediction | None:
        """Predice la fase siguiente combinando orden canónico + transiciones."""
        tactics = incident.tactics
        if not tactics:
            return None
        current = tactics[-1]
        idx = mitre.tactic_index(current)
        if idx == -1:
            return None

        predicted = mitre.next_tactics(current, k=2)

        # Confianza: sube con cuántas fases coherentes ya se observaron.
        observed_indices = [mitre.tactic_index(t) for t in tactics if mitre.tactic_index(t) >= 0]
        monotonic = all(x <= y for x, y in zip(observed_indices, observed_indices[1:]))
        base = 0.55 + 0.1 * min(len(tactics), 3)
        confidence = min(base + (0.1 if monotonic else 0.0), 0.95)

        chain_es = " → ".join(mitre.TACTIC_LABELS_ES.get(t, t) for t in tactics)
        if predicted:
            nxt_es = " o ".join(mitre.TACTIC_LABELS_ES.get(t, t) for t in predicted)
            rationale = (
                f"Se observó la progresión: {chain_es}. Según el orden típico de la "
                f"cadena de ataque (MITRE ATT&CK), la fase siguiente probable es: {nxt_es}."
            )
        else:
            rationale = (
                f"Se observó la progresión: {chain_es}. El ataque parece estar en su "
                f"fase final (impacto); prioriza contención inmediata."
            )

        return KillChainPrediction(
            current_tactic=current,
            current_stage_index=idx,
            total_stages=len(mitre.TACTIC_ORDER),
            predicted_next=predicted,
            confidence=confidence,
            rationale=rationale,
        )
