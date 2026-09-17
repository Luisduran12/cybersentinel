"""
Contexto para la predicción de kill-chain (Fase 4-D, tarea D1).

El predictor (`sequence_model.py`) solo ve la secuencia de tácticas. Esto
añade contexto **sin tocar el modelo**: reordena/reescala las probabilidades
crudas que ya salieron de `predict_next`, igual que Sigma no se toca para
sumarle CTI en el `hybrid_score`.

Cuatro señales, cada una justificada por su propia razón operativa:

1. **Tipo de entidad.** Un servidor comprometido es un objetivo de fases
   tardías (exfiltración, impacto); una estación de trabajo es más típica de
   fases tempranas (acceso inicial, ejecución de payload).
2. **Severidad acumulada del incidente.** Un incidente que ya acumuló
   severidad alta tiene más probabilidad de progresar hacia el daño real
   que uno de baja severidad con la misma secuencia de tácticas.
3. **Velocidad del ataque.** Un atacante que genera muchos eventos por
   minuto está en modo activo, no reconociendo despacio: es más probable que
   la siguiente fase llegue pronto, no que el ataque se estanque.
4. **Contexto CTI.** Si la IP o el actor ya están confirmados como parte de
   una campaña conocida (APT, C2), las fases de post-explotación
   (movimiento lateral, C2, exfiltración) son más probables que si no hay
   ese contexto: un actor con infraestructura conocida ya demostró que sabe
   llegar hasta ahí.
"""
from __future__ import annotations

from dataclasses import dataclass

#: Tácticas que representan progreso avanzado en la cadena de ataque.
LATE_STAGE_TACTICS = {"exfiltration", "impact", "command-and-control", "collection"}
#: Tácticas típicas de una campaña ya con infraestructura identificada.
APT_ASSOCIATED_TACTICS = {"lateral-movement", "command-and-control", "exfiltration"}

_SERVER_PREFIXES = ("srv-", "db-", "web-", "app-", "dc-", "mail-", "sql-", "fs-")
_WORKSTATION_PREFIXES = ("wks-", "pc-", "laptop-", "desk-", "ws-")


def infer_entity_type(entity: str) -> str:
    """
    Heurística de nomenclatura, no un inventario de activos real.

    Sin un CMDB conectado (fuera del alcance de este agente), lo único
    disponible es el nombre de la entidad tal como llega en la telemetría.
    Es deliberadamente conservadora: si no reconoce el patrón, dice
    "unknown" en vez de adivinar.
    """
    e = (entity or "").lower()
    if e.startswith(_SERVER_PREFIXES):
        return "server"
    if e.startswith(_WORKSTATION_PREFIXES):
        return "workstation"
    if "@" in e:
        return "user"
    partes = e.split(".")
    if len(partes) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in partes):
        return "network_address"
    return "unknown"


@dataclass
class PredictionContext:
    """Lo que se sabe del incidente más allá de la secuencia de tácticas."""

    entity_type: str
    accumulated_severity: float      # 0..100, mismo rango que Incident.risk_score
    events_per_minute: float
    cti_flagged: bool

    def to_dict(self) -> dict[str, float | str | bool]:
        return {
            "entity_type": self.entity_type,
            "accumulated_severity": round(self.accumulated_severity, 2),
            "events_per_minute": round(self.events_per_minute, 3),
            "cti_flagged": self.cti_flagged,
        }


def reweight(ranked: list[tuple[str, float]],
            context: PredictionContext) -> list[tuple[str, float]]:
    """
    Ajusta las probabilidades crudas del modelo con los factores de contexto.

    No se renormaliza (mismo principio que `sequence_model.py`): cada
    probabilidad se multiplica por su factor y se acota a 1.0, sin forzar que
    la lista sume 1. Reordena por el valor ajustado, así que el contexto
    puede cambiar cuál es la hipótesis más probable, no solo su magnitud.
    """
    ajustadas: list[tuple[str, float]] = []
    for tactic, prob in ranked:
        factor = 1.0
        if context.entity_type == "server" and tactic in LATE_STAGE_TACTICS:
            factor *= 1.3
        if context.accumulated_severity >= 75.0 and tactic in LATE_STAGE_TACTICS:
            factor *= 1.2
        if context.events_per_minute >= 5.0:
            factor *= 1.15
        if context.cti_flagged and tactic in APT_ASSOCIATED_TACTICS:
            factor *= 1.4
        ajustadas.append((tactic, min(prob * factor, 1.0)))
    ajustadas.sort(key=lambda par: par[1], reverse=True)
    return ajustadas
