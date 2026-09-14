"""
Capa de gobernanza ética.

Toda contramedida que el agente proponga pasa por aquí ANTES de poder ejecutarse.
La política clasifica cada acción en:

    ALLOWED           -> reversible, de bajo impacto (ejecutable tras registro)
    REQUIRES_APPROVAL -> impacto operativo (requiere human-in-the-loop)
    PROHIBITED        -> destructiva, ilegal o fuera de ámbito (nunca se ejecuta)

Principio rector: el agente NUNCA ejecuta acciones ofensivas, destructivas o
irreversibles por sí mismo. Las acciones sensibles siempre requieren aprobación
humana explícita. Esto es una salvaguarda de diseño, no una opción configurable
que se pueda desactivar para "ganar autonomía".
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml


class Decision(str, Enum):
    ALLOWED = "allowed"
    REQUIRES_APPROVAL = "requires_approval"
    PROHIBITED = "prohibited"


@dataclass
class ProposedAction:
    """Acción de respuesta propuesta por el agente."""
    action_type: str          # p.ej. "block_ip", "isolate_host", "notify_analyst"
    target: str
    reason: str
    incident_id: str
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyVerdict:
    action: ProposedAction
    decision: Decision
    matched_rule: str
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_type": self.action.action_type,
            "target": self.action.target,
            "incident_id": self.action.incident_id,
            "decision": self.decision.value,
            "matched_rule": self.matched_rule,
            "explanation": self.explanation,
        }


# Política por defecto embebida (se puede sobreescribir con un YAML externo).
DEFAULT_POLICY: dict[str, Any] = {
    "prohibited": [
        "delete_files", "wipe_disk", "format", "shutdown_production",
        "counter_attack", "hack_back", "deploy_exploit", "exfiltrate",
        "disable_backups", "modify_evidence",
    ],
    "requires_approval": [
        "isolate_host", "block_ip", "disable_account", "revoke_session",
        "kill_process", "quarantine_file", "reset_password",
    ],
    "allowed": [
        "notify_analyst", "enrich_context", "open_ticket", "tag_entity",
        "increase_logging", "snapshot_evidence",
    ],
}


class GovernancePolicy:
    """Evalúa acciones propuestas contra la política ética."""

    def __init__(self, policy: dict[str, Any] | None = None) -> None:
        self.policy = policy or DEFAULT_POLICY

    @classmethod
    def from_yaml(cls, path: str | Path) -> "GovernancePolicy":
        with open(path, "r", encoding="utf-8") as fh:
            return cls(yaml.safe_load(fh))

    def evaluate(self, action: ProposedAction) -> PolicyVerdict:
        at = action.action_type.lower()

        if at in self.policy.get("prohibited", []):
            return PolicyVerdict(
                action, Decision.PROHIBITED, at,
                "Acción prohibida por política: es destructiva, ofensiva o fuera del "
                "ámbito defensivo/legal. El agente no la ejecutará bajo ninguna circunstancia.",
            )
        if at in self.policy.get("requires_approval", []):
            return PolicyVerdict(
                action, Decision.REQUIRES_APPROVAL, at,
                "Acción con impacto operativo. Requiere aprobación humana explícita "
                "(human-in-the-loop) antes de ejecutarse.",
            )
        if at in self.policy.get("allowed", []):
            return PolicyVerdict(
                action, Decision.ALLOWED, at,
                "Acción reversible y de bajo impacto. Ejecutable tras registro en auditoría.",
            )
        # Desconocida -> por defecto, lo más seguro: requiere aprobación.
        return PolicyVerdict(
            action, Decision.REQUIRES_APPROVAL, "default-deny",
            "Acción no reconocida por la política. Por precaución (fail-safe) se "
            "requiere aprobación humana.",
        )
