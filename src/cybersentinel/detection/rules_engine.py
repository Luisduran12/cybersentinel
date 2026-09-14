"""
Motor de reglas (inspirado en Sigma).

Evalúa cada SecurityEvent contra un conjunto de reglas declarativas en YAML.
No es un parser Sigma completo (eso es la Fase 1), pero implementa el
subconjunto más útil:

  - Coincidencias por campo con operadores contains / contains_any / equals /
    in / regex / not_regex / gt / lt, combinadas con AND.
  - **Agregación temporal**: una regla puede exigir N coincidencias dentro de una
    ventana de tiempo, agrupadas por uno o varios campos. Sin esto, una regla
    titulada "múltiples fallos de login" dispararía con un solo fallo.

Cada regla lleva su técnica MITRE ATT&CK asociada, lo que alimenta directamente
la fase de correlación y predicción.
"""
from __future__ import annotations

import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

import yaml

from ..schema import SecurityEvent, Severity

logger = logging.getLogger(__name__)


@dataclass
class Aggregation:
    """
    Condición de volumen: `count` coincidencias dentro de `timeframe_minutes`,
    agrupadas por los campos de `group_by`.

    Modela lo que en Sigma se expresa como `| count() by campo > N` dentro de un
    `timeframe`. Es lo que convierte "un login fallido" en "fuerza bruta".
    """
    count: int
    timeframe_minutes: int
    group_by: list[str] = field(default_factory=list)

    @property
    def window(self) -> timedelta:
        return timedelta(minutes=self.timeframe_minutes)

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Aggregation":
        return Aggregation(
            count=int(d["count"]),
            timeframe_minutes=int(d.get("timeframe_minutes", 5)),
            group_by=list(d.get("group_by", [])),
        )


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
    aggregation: Aggregation | None = None
    false_positives: list[str] = field(default_factory=list)

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "DetectionRule":
        """
        Construye la regla y resuelve su táctica ATT&CK.

        La táctica se deriva de la técnica cuando la regla no la declara, y se
        comprueba cuando sí lo hace: tener el mismo dato escrito en dos sitios es
        la receta para que se desincronicen. Una discrepancia se avisa en vez de
        aceptarse en silencio, porque contamina la predicción de kill-chain.

        La comprobación es de **pertenencia**, no de igualdad: en ATT&CK una
        técnica puede estar en varias tácticas a la vez (T1053 está en ejecución,
        persistencia y escalada de privilegios), así que una regla que declare
        cualquiera de ellas es correcta.
        """
        # Import local: `correlation` importa este módulo, así que hacerlo arriba
        # crearía un ciclo. Aquí ya está todo cargado.
        from ..correlation import mitre

        technique = d.get("mitre_technique", "unknown")
        declared = d.get("mitre_tactic")
        posibles = mitre.tactics_of(technique)
        if declared and posibles and mitre.normalize_tactic(declared) not in posibles:
            logger.warning(
                "La regla %s declara la táctica '%s', pero %s pertenece a %s; "
                "se usa la declarada.",
                d.get("id"), declared, technique, ", ".join(posibles) or "ninguna",
            )
        tactic = declared or mitre.tactic_of(technique)

        agg = d.get("aggregation")
        return DetectionRule(
            id=d["id"],
            title=d["title"],
            description=d.get("description", ""),
            severity=Severity(d.get("severity", "medium")),
            mitre_technique=technique,
            mitre_tactic=tactic,
            conditions=d.get("conditions", []),
            references=d.get("references", []),
            aggregation=Aggregation.from_dict(agg) if agg else None,
            false_positives=d.get("false_positives", []),
        )


@dataclass
class RuleHit:
    """Resultado de una regla que coincidió."""
    rule: DetectionRule
    event: SecurityEvent
    confidence: float
    match_count: int = 1
    related_fingerprints: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule.id,
            "title": self.rule.title,
            "severity": self.rule.severity.value,
            "mitre_technique": self.rule.mitre_technique,
            "mitre_tactic": self.rule.mitre_tactic,
            "confidence": round(self.confidence, 3),
            "event_fingerprint": self.event.fingerprint(),
            "match_count": self.match_count,
            "related_fingerprints": self.related_fingerprints,
        }


def _field_value(event: SecurityEvent, field_name: str) -> Any:
    """Valor de un campo del evento, con los campos crudos como respaldo."""
    value = getattr(event, field_name, None)
    if value is None:
        value = event.raw.get(field_name)
    return value


def _match_condition(event: SecurityEvent, cond: dict[str, Any]) -> bool:
    """Evalúa una condición individual sobre un campo del evento."""
    field_name = cond["field"]
    operator = cond.get("op", "contains")
    expected = cond.get("value")

    actual = _field_value(event, field_name)
    if actual is None:
        # `not_regex` sobre un campo ausente se cumple: no hay nada que excluir.
        return operator == "not_regex"

    actual_str = str(actual).lower()

    if operator == "equals":
        return actual_str == str(expected).lower()
    if operator == "in":
        # Igualdad contra una lista. A diferencia de contains_any no hace
        # coincidencias parciales: el puerto 14444 no "es" el puerto 4444.
        return any(actual_str == str(v).lower() for v in expected)
    if operator == "contains":
        return str(expected).lower() in actual_str
    if operator == "contains_any":
        return any(str(v).lower() in actual_str for v in expected)
    if operator == "regex":
        return re.search(str(expected), str(actual), re.IGNORECASE) is not None
    if operator == "not_regex":
        return re.search(str(expected), str(actual), re.IGNORECASE) is None
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

    @property
    def stateless_rules(self) -> list[DetectionRule]:
        """Reglas que se deciden con un solo evento."""
        return [r for r in self.rules if r.conditions and r.aggregation is None]

    @property
    def aggregated_rules(self) -> list[DetectionRule]:
        """Reglas que exigen un volumen de coincidencias en una ventana."""
        return [r for r in self.rules if r.conditions and r.aggregation is not None]

    def _base_confidence(self, rule: DetectionRule) -> float:
        """
        Confianza base derivada de la severidad declarada.

        Es una heurística, no una probabilidad calibrada: mide cuánto "pesa" la
        regla según su autor, no cuántas veces acierta. La calibración real
        exige medir contra un dataset etiquetado (Fase 4).
        """
        return min(0.5 + (rule.severity.score / 200.0), 0.99)

    def evaluate_event(self, event: SecurityEvent) -> list[RuleHit]:
        """
        Reglas sin estado que coinciden con un evento (AND de condiciones).

        Las reglas con agregación no se evalúan aquí: necesitan ver la serie
        completa de eventos. Para esas, usa `evaluate`.
        """
        hits: list[RuleHit] = []
        for rule in self.stateless_rules:
            if all(_match_condition(event, c) for c in rule.conditions):
                hits.append(RuleHit(rule=rule, event=event,
                                    confidence=self._base_confidence(rule)))
        return hits

    def evaluate(self, events: list[SecurityEvent]) -> list[RuleHit]:
        """Evalúa reglas sin estado y con agregación sobre la serie completa."""
        hits: list[RuleHit] = []
        for event in events:
            hits.extend(self.evaluate_event(event))
        for rule in self.aggregated_rules:
            hits.extend(self._evaluate_aggregated(rule, events))
        return hits

    def _evaluate_aggregated(
        self, rule: DetectionRule, events: list[SecurityEvent]
    ) -> list[RuleHit]:
        """
        Emite UN hallazgo por cada ventana que alcanza el umbral de volumen.

        Las ventanas no se solapan: ocho fallos de login consecutivos con umbral
        cinco producen un hallazgo (no ocho, ni cuatro solapados). El hallazgo se
        ancla en el último evento de la ventana, que es el instante en el que la
        condición se cumple, y conserva las huellas de los demás como evidencia.
        """
        agg = rule.aggregation
        assert agg is not None

        matching = [e for e in events if all(_match_condition(e, c) for c in rule.conditions)]
        if not matching:
            return []

        groups: dict[tuple[Any, ...], list[SecurityEvent]] = defaultdict(list)
        for event in matching:
            key = tuple(_field_value(event, f) for f in agg.group_by)
            groups[key].append(event)

        hits: list[RuleHit] = []
        for group in groups.values():
            group.sort(key=lambda e: e.timestamp)
            window: list[SecurityEvent] = []
            for event in group:
                window.append(event)
                # Descarta por la izquierda lo que ya salió de la ventana.
                while window and (event.timestamp - window[0].timestamp) > agg.window:
                    window.pop(0)
                if len(window) >= agg.count:
                    hits.append(RuleHit(
                        rule=rule,
                        event=window[-1],
                        # El exceso sobre el umbral sube la confianza, con techo.
                        confidence=min(
                            self._base_confidence(rule) + 0.02 * (len(window) - agg.count),
                            0.99,
                        ),
                        match_count=len(window),
                        related_fingerprints=[e.fingerprint() for e in window[:-1]],
                    ))
                    window = []   # ventanas disjuntas: evita alertas duplicadas
        return hits
