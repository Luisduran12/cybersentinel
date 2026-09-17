"""
Risk score persistente por entidad (Fase 4-D, tarea D2).

Distinto de `Incident.risk_score` (correlation/correlator.py): aquel es
0..100 **por incidente**, se recalcula desde cero cada vez y no sabe nada de
lo que pasó ayer. Este vive por entidad (host o usuario), across incidentes,
y con memoria: sube con cada detección nueva, decae con el tiempo sin
incidentes, y se dispara si CTI confirma compromiso.

La "correlación sube más rápido" del prompt no necesita un parámetro
especial: como el score se acumula sobre lo que no ha decaído todavía, dos
detecciones cercanas en el tiempo (correlacionadas) se suman casi sin decaer
entre medio, mientras que dos separadas por semanas casi no dejan rastro la
una de la otra. Es una propiedad del diseño, no una regla aparte.
"""
from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

#: Puntos que se pierden por hora sin ninguna detección nueva para la entidad.
DEFAULT_DECAY_PER_HOUR = 5.0

#: Bonus mínimo garantizado cuando CTI confirma compromiso (nation-state, C2
#: conocido): "se dispara" significa que un único hit de este tipo por sí
#: solo debería acercar a la entidad al umbral de alerta proactiva.
CTI_CONFIRMED_MIN_BOOST = 60.0

#: A partir de qué score se considera candidato a alerta proactiva (Fase 4-D,
#: tarea D3). Mismo orden de magnitud que ALERT_THRESHOLD de hybrid_score,
#: porque ambos dicen "esto merece atención de un analista".
PROACTIVE_ALERT_THRESHOLD = 70.0


@dataclass
class EntityRisk:
    """Estado de riesgo acumulado de una entidad."""

    entity: str
    score: float = 0.0
    last_updated: str | None = None
    #: Si ya se disparó una alerta proactiva para el cruce actual del umbral.
    #: Evita reenviar la misma alerta en cada evento mientras el score se
    #: mantiene por encima; se vuelve a poder alertar tras bajar y volver a subir.
    proactively_alerted: bool = False
    history: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity": self.entity, "score": round(self.score, 2),
            "last_updated": self.last_updated,
            "proactively_alerted": self.proactively_alerted,
            "history": self.history[-20:],   # las últimas 20, no todo el historial
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "EntityRisk":
        return cls(entity=d["entity"], score=d.get("score", 0.0),
                   last_updated=d.get("last_updated"),
                   proactively_alerted=d.get("proactively_alerted", False),
                   history=d.get("history", []))


class RiskScoreTracker:
    """Lleva el risk score de cada entidad, con decaimiento temporal."""

    def __init__(self, decay_per_hour: float = DEFAULT_DECAY_PER_HOUR,
                path: str | Path | None = None) -> None:
        self.decay_per_hour = decay_per_hour
        self.path = Path(path) if path else None
        self._lock = threading.Lock()
        self._risks: dict[str, EntityRisk] = {}
        if self.path and self.path.exists():
            self._load()

    def _decay(self, risk: EntityRisk, ahora: datetime) -> None:
        if risk.last_updated is None:
            return
        transcurridas = (ahora - datetime.fromisoformat(risk.last_updated)).total_seconds() / 3600
        if transcurridas <= 0:
            return
        risk.score = max(0.0, risk.score - transcurridas * self.decay_per_hour)

    def record_detection(self, entity: str, hybrid_score: float, when: datetime,
                         cti_confirmed: bool = False, reason: str = "") -> float:
        """
        Registra una detección para la entidad y devuelve el score resultante.

        `hybrid_score` (0..100, el de `DetectionEvidence`) se pondera a un
        tercio: una sola detección aislada no debería, por sí sola, llevar a
        una entidad al umbral de alerta proactiva — para eso hacen falta
        varias, o una confirmación de CTI.
        """
        with self._lock:
            risk = self._risks.setdefault(entity, EntityRisk(entity=entity))
            self._decay(risk, when)
            incremento = hybrid_score / 3.0
            if cti_confirmed:
                incremento = max(incremento, CTI_CONFIRMED_MIN_BOOST)
            antes = risk.score
            risk.score = min(100.0, risk.score + incremento)
            risk.last_updated = when.isoformat()
            risk.history.append({
                "at": when.isoformat(), "delta": round(risk.score - antes, 2),
                "hybrid_score": round(hybrid_score, 2), "cti_confirmed": cti_confirmed,
                "reason": reason,
            })
            # Un cruce nuevo del umbral vuelve a habilitar la alerta proactiva.
            if risk.score < PROACTIVE_ALERT_THRESHOLD:
                risk.proactively_alerted = False
            return risk.score

    def score_for(self, entity: str, now: datetime | None = None) -> float:
        with self._lock:
            risk = self._risks.get(entity)
            if risk is None:
                return 0.0
            if now is not None:
                self._decay(risk, now)
            return risk.score

    def due_proactive_alert(self, entity: str) -> bool:
        """
        True si la entidad cruzó el umbral y todavía no se alertó por ese
        cruce. Marca la entidad como ya alertada (efecto secundario
        intencional: llamar dos veces no dispara la alerta dos veces).
        """
        with self._lock:
            risk = self._risks.get(entity)
            if risk is None or risk.score < PROACTIVE_ALERT_THRESHOLD:
                return False
            if risk.proactively_alerted:
                return False
            risk.proactively_alerted = True
            return True

    def snapshot(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            return {e: r.to_dict() for e, r in self._risks.items()}

    # --- Persistencia -------------------------------------------------------
    def save(self) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            datos = {e: r.to_dict() for e, r in self._risks.items()}
        self.path.write_text(json.dumps(datos, indent=2, ensure_ascii=False), encoding="utf-8")

    def _load(self) -> None:
        try:
            datos = json.loads(self.path.read_text(encoding="utf-8"))
            self._risks = {k: EntityRisk.from_dict(v) for k, v in datos.items()}
        except (json.JSONDecodeError, OSError, KeyError, ValueError):
            self._risks = {}
