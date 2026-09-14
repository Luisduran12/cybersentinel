"""
Recomendación de contramedidas (respuesta).

A partir de un incidente, el agente PROPONE contramedidas priorizadas. Cada
propuesta pasa por la capa de gobernanza. En este entregable NADA se ejecuta de
verdad: las acciones "allowed" se simulan (dry-run) y las sensibles quedan a la
espera de aprobación humana. Conectar ejecutores reales (EDR, firewall) es
trabajo futuro y siempre debe mantener el human-in-the-loop.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..correlation.correlator import Incident
from ..governance.policy import GovernancePolicy, ProposedAction, PolicyVerdict, Decision


@dataclass
class Recommendation:
    verdict: PolicyVerdict
    priority: int             # 1 = más urgente

    def to_dict(self) -> dict[str, Any]:
        d = self.verdict.to_dict()
        d["priority"] = self.priority
        d["reason"] = self.verdict.action.reason
        return d


class ResponsePlanner:
    """Propone contramedidas para un incidente y las evalúa con la política."""

    def __init__(self, policy: GovernancePolicy) -> None:
        self.policy = policy

    def plan(self, incident: Incident) -> list[Recommendation]:
        proposals = self._propose(incident)
        recs: list[Recommendation] = []
        for i, action in enumerate(proposals, start=1):
            verdict = self.policy.evaluate(action)
            recs.append(Recommendation(verdict=verdict, priority=i))
        # Prohibidas al final; el resto por prioridad ya asignada.
        recs.sort(key=lambda r: (r.verdict.decision == Decision.PROHIBITED, r.priority))
        return recs

    def _propose(self, incident: Incident) -> list[ProposedAction]:
        """Heurística de propuesta según severidad y tácticas observadas."""
        actions: list[ProposedAction] = []
        entity = incident.entity
        iid = incident.incident_id
        risk = incident.risk_score
        tactics = set(incident.tactics)

        # Siempre: enriquecer y notificar (bajo impacto).
        actions.append(ProposedAction("enrich_context", entity,
                                       "Reunir contexto adicional del incidente.", iid))
        actions.append(ProposedAction("notify_analyst", entity,
                                       "Alertar al analista de guardia.", iid))

        # Credential-access / brute force -> proteger cuentas.
        if "credential-access" in tactics:
            actions.append(ProposedAction("disable_account", entity,
                                          "Posible compromiso de credenciales.", iid))
            actions.append(ProposedAction("reset_password", entity,
                                          "Rotar credenciales potencialmente expuestas.", iid))

        # C2 / exfiltración -> cortar la comunicación.
        if tactics & {"command-and-control", "exfiltration"}:
            actions.append(ProposedAction("block_ip", entity,
                                          "Cortar canal C2 / exfiltración.", iid))

        # Movimiento lateral o riesgo alto -> aislar.
        if "lateral-movement" in tactics or risk >= 70:
            actions.append(ProposedAction("isolate_host", entity,
                                          "Contener propagación en la red.", iid))

        # Siempre disponible: preservar evidencia.
        actions.append(ProposedAction("snapshot_evidence", entity,
                                       "Preservar evidencia forense antes de contener.", iid))
        return actions


def execute_allowed(recommendation: Recommendation) -> str:
    """
    Simula (dry-run) la ejecución de una acción permitida.
    NUNCA ejecuta acciones reales en este entregable.
    """
    if recommendation.verdict.decision != Decision.ALLOWED:
        return "No ejecutado: la acción no está en estado 'allowed'."
    a = recommendation.verdict.action
    return f"[DRY-RUN] Acción '{a.action_type}' sobre '{a.target}' simulada correctamente."
