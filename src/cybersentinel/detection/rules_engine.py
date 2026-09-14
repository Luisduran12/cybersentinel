"""
Motor de reglas (inspirado en Sigma).

Evalúa cada SecurityEvent contra un conjunto de reglas declarativas en YAML.
No es un parser Sigma completo (eso es trabajo futuro), pero implementa el
subconjunto más útil: coincidencias por campo con operadores contains / equals /
regex / gt / lt, y combinación lógica AND entre condiciones.

Cada regla lleva su técnica MITRE ATT&CK asociada, lo que alimenta directamente
la fase de correlación y predicción.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..schema import SecurityEvent, Severity


@dataclass
class DetectionRule:
    """Regla declarativa de detección."""
    id: str
    title: str
    description: str
    severity: Severity
    mitre_technique: str          # p.ej. "T1110" (Brute Force)
    mitre_tactic: str             # p.ej. "credential-access"
    conditions: list[dict[str, Any]] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "DetectionRule":
        return DetectionRule(
            id=d["id"],
            title=d["title"],
            description=d.get("description", ""),
            severity=Severity(d.get("severity", "medium")),
            mitre_technique=d.get("mitre_technique", "unknown"),
            mitre_tactic=d.get("mitre_tactic", "unknown"),
            conditions=d.get("conditions", []),
            references=d.get("references", []),
        )


@dataclass
class RuleHit:
    """Resultado de una regla que coincidió con un evento."""
    rule: DetectionRule
    event: SecurityEvent
    confidence: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule.id,
            "title": self.rule.title,
            "severity": self.rule.severity.value,
            "mitre_technique": self.rule.mitre_technique,
            "mitre_tactic": self.rule.mitre_tactic,
            "confidence": round(self.confidence, 3),
            "event_fingerprint": self.event.fingerprint(),
        }


def _match_condition(event: SecurityEvent, cond: dict[str, Any]) -> bool:
    """Evalúa una condición individual sobre un campo del evento."""
    field_name = cond["field"]
    operator = cond.get("op", "contains")
    expected = cond.get("value")

    actual = getattr(event, field_name, None)
    if actual is None:
        actual = event.raw.get(field_name)
    if actual is None:
        return False

    actual_str = str(actual).lower()

    if operator == "equals":
        return actual_str == str(expected).lower()
    if operator == "contains":
        return str(expected).lower() in actual_str
    if operator == "contains_any":
        return any(str(v).lower() in actual_str for v in expected)
    if operator == "regex":
        return re.search(str(expected), str(actual), re.IGNORECASE) is not None
    if operator == "gt":
        try:
            return float(actual) > float(expected)
        except (ValueError, TypeError):
            return False
    if operator == "lt":
        try:
            return float(actual) < float(expected)
        except (ValueError, TypeError):
            return False
    return False


class RulesEngine:
    """Carga reglas YAML y las evalúa contra eventos."""

    def __init__(self, rules: list[DetectionRule] | None = None) -> None:
        self.rules: list[DetectionRule] = rules or []

    @classmethod
    def from_directory(cls, directory: str | Path) -> "RulesEngine":
        """Carga todas las reglas .yaml/.yml de un directorio."""
        engine = cls()
        directory = Path(directory)
        for file in sorted(directory.glob("*.y*ml")):
            with open(file, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
            if data:
                engine.rules.append(DetectionRule.from_dict(data))
        return engine

    def evaluate_event(self, event: SecurityEvent) -> list[RuleHit]:
        """Devuelve todas las reglas que coinciden con un evento (AND de condiciones)."""
        hits: list[RuleHit] = []
        for rule in self.rules:
            if not rule.conditions:
                continue
            if all(_match_condition(event, c) for c in rule.conditions):
                # Confianza base por severidad; la correlación puede ajustarla luego.
                confidence = 0.5 + (rule.severity.score / 200.0)
                hits.append(RuleHit(rule=rule, event=event, confidence=min(confidence, 0.99)))
        return hits

    def evaluate(self, events: list[SecurityEvent]) -> list[RuleHit]:
        hits: list[RuleHit] = []
        for event in events:
            hits.extend(self.evaluate_event(event))
        return hits
