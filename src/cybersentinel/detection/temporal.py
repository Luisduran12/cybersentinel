"""
Motor de agregación y correlación temporal (Fase 3).

Relaciona detecciones individuales (RuleHit) a lo largo del tiempo,
permitiendo identificar secuencias tácticas (ej. Ejecución -> C2 -> Exfiltración)
y comportamientos agregados. Prepara la estructura narrativa para ML.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

import yaml

from .rules_engine import RuleHit

logger = logging.getLogger(__name__)

@dataclass
class SequenceRule:
    """Regla para correlacionar secuencias temporales de técnicas ATT&CK."""
    name: str
    techniques_sequence: list[str]
    window_minutes: int
    group_by: list[str] = field(default_factory=lambda: ["host"])

@dataclass
class CorrelatedIncident:
    """Una secuencia de RuleHits que conforman un incidente mayor."""
    name: str
    hits: list[RuleHit]
    matched_sequence: list[str]
    confidence: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_name": self.name,
            "matched_sequence": self.matched_sequence,
            "confidence": round(self.confidence, 3),
            "hits": [h.to_dict() for h in self.hits],
            "start_time": self.hits[0].event.timestamp.isoformat(),
            "end_time": self.hits[-1].event.timestamp.isoformat()
        }

class TemporalCorrelator:
    """
    Abstracción ligera para agregación temporal y secuencias ATT&CK.
    """
    def __init__(self, rules: list[SequenceRule] | None = None):
        self.rules = rules or []
        self._history: list[RuleHit] = []

    @classmethod
    def from_yaml(cls, path: str | Path) -> "TemporalCorrelator":
        """
        Carga las reglas de secuencia desde YAML.

        Un correlador sin reglas nunca produce incidentes: `correlate()` recorre
        `self.rules`, y si está vacía devuelve siempre una lista vacía. Por eso la
        ausencia del archivo se avisa en lugar de degradar en silencio.
        """
        path = Path(path)
        if not path.exists():
            logger.warning(
                "No hay reglas de secuencia en %s: la correlacion temporal no "
                "producira incidentes.", path,
            )
            return cls([])

        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        rules = [
            SequenceRule(
                name=entry["name"],
                techniques_sequence=list(entry["techniques_sequence"]),
                window_minutes=int(entry.get("window_minutes", 30)),
                group_by=list(entry.get("group_by", ["host"])),
            )
            for entry in data.get("sequences", [])
        ]
        logger.info("Cargadas %d reglas de secuencia desde %s", len(rules), path)
        return cls(rules)

    def observe(self, hit: RuleHit) -> None:
        """Añade un hit al buffer de observación."""
        self._history.append(hit)

    def observe_batch(self, hits: list[RuleHit]) -> None:
        """Añade múltiples hits."""
        self._history.extend(hits)

    def correlate(self) -> list[CorrelatedIncident]:
        """Evalúa el historial actual contra las reglas de secuencia."""
        incidents = []
        for rule in self.rules:
            incidents.extend(self._evaluate_sequence(rule))
        return incidents
        
    def _evaluate_sequence(self, rule: SequenceRule) -> list[CorrelatedIncident]:
        """Busca secuencias que coincidan con la regla."""
        if not self._history:
            return []
            
        # Agrupar el historial por las claves de agrupación (ej. host, user)
        groups = {}
        for hit in self._history:
            key = tuple(self._extract_field(hit, f) for f in rule.group_by)
            groups.setdefault(key, []).append(hit)
            
        incidents = []
        window = timedelta(minutes=rule.window_minutes)
        
        for group in groups.values():
            group.sort(key=lambda h: h.event.timestamp)
            
            seq_idx = 0
            current_match: list[RuleHit] = []
            
            for hit in group:
                if current_match and (hit.event.timestamp - current_match[0].event.timestamp) > window:
                    # Timeout de ventana, reiniciar secuencia buscando desde el hit fallido
                    seq_idx = 0
                    current_match = []
                    
                if hit.rule.mitre_technique == rule.techniques_sequence[seq_idx]:
                    current_match.append(hit)
                    seq_idx += 1
                    
                    if seq_idx == len(rule.techniques_sequence):
                        # Se completó la secuencia
                        conf = min(1.0, sum(h.confidence for h in current_match) / len(current_match) + 0.2)
                        incidents.append(CorrelatedIncident(
                            name=rule.name,
                            hits=list(current_match),
                            matched_sequence=rule.techniques_sequence,
                            confidence=conf
                        ))
                        seq_idx = 0
                        current_match = []
        return incidents

    def _extract_field(self, hit: RuleHit, field_name: str) -> Any:
        from .rules_engine import _field_value
        return _field_value(hit.event, field_name)

    def clear(self) -> None:
        self._history.clear()
