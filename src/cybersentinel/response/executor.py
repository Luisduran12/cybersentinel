"""
Ejecutor de respuesta (Fase 4-E, tarea E1).

Valida, enruta y ejecuta acciones de respuesta. Reemplaza
`ExternalIntegrationMock` (100% simulado, sin importar el nivel) por
integraciones reales (`integrations.py`): Nivel 1 ejecuta de verdad
(webhook, email, ticket, bloqueo de IOC) sujeto a `dry_run`; Nivel 2 nunca
ejecuta contra un sistema externo real — solo genera el comando exacto y
espera aprobación humana, tal como pide el prompt.

Salvaguarda explícita: **el LLM no puede aprobar acciones.** `approve_action`
rechaza cualquier `approved_by` que no identifique a una persona real.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Optional

from ..governance.audit import AuditLog
from .integrations import EmailNotifier, IOCBlocklist, TicketWriter, WebhookNotifier
from .models import ActionStatus, ActionType, ResponseAction, _ahora
from .store import ResponseStore

logger = logging.getLogger(__name__)

#: Identidades que NUNCA pueden aprobar una acción sensible, sin importar lo
#: que diga el llamador. No es una lista exhaustiva de detección de IA —es
#: una última barrera explícita para el requisito "LLM no puede aprobar".
IDENTIDADES_NO_HUMANAS = {"llm", "agent", "agente", "system", "sistema", "ai", "ia", "bot", ""}


class UnauthorizedApproverError(Exception):
    """Se intentó aprobar una acción sensible con una identidad no humana."""


class ResponseExecutor:
    """Valida, enruta y ejecuta acciones de respuesta."""

    def __init__(self, store: ResponseStore, audit: AuditLog | None = None,
                webhook: WebhookNotifier | None = None,
                email: EmailNotifier | None = None,
                tickets: TicketWriter | None = None,
                blocklist: IOCBlocklist | None = None,
                tickets_dir: str | None = None,
                blocklist_path: str | None = None) -> None:
        self.store = store
        self.audit = audit
        # DRY_RUN=true por defecto siempre; solo se apaga con la variable
        # explícita en false/0/no.
        self.global_dry_run = os.environ.get("CYBERSENTINEL_DRY_RUN", "true").lower() in {
            "1", "true", "yes",
        }
        self.webhook = webhook or WebhookNotifier()
        self.email = email or EmailNotifier()
        self.tickets = tickets or TicketWriter(tickets_dir)
        self.blocklist = blocklist or IOCBlocklist(blocklist_path)

    def request_action(self, action: ResponseAction) -> ResponseAction:
        """
        Somete una acción. Nivel 1 (no requiere aprobación) se auto-aprueba
        y ejecuta ya mismo; Nivel 2 se queda en REQUESTED hasta que un
        humano la apruebe o la rechace vía `approve_action`/`reject_action`.
        """
        action.dry_run = self.global_dry_run
        action.command = action.command or self._generar_comando(action)

        if not action.action_type.requires_approval:
            action.status = ActionStatus.APPROVED
            self._execute_action(action)
        else:
            action.status = ActionStatus.REQUESTED
            self.store.create(action)
            self._audit_action(action, "action_requested")

        return action

    def approve_action(self, action_id: str, approved_by: str) -> Optional[ResponseAction]:
        """Aprueba una acción Nivel 2 y dispara su ejecución (Nivel 2 solo genera el comando)."""
        if approved_by.strip().lower() in IDENTIDADES_NO_HUMANAS:
            raise UnauthorizedApproverError(
                f"'{approved_by}' no es una identidad humana válida para aprobar una acción. "
                "El LLM y el propio sistema no pueden aprobar acciones sensibles."
            )

        action = self.store.get(action_id)
        if not action or action.status != ActionStatus.REQUESTED:
            return None

        action.status = ActionStatus.APPROVED
        action.approved_by = approved_by
        action.timestamp_approved = _ahora()

        self.store.update(action)
        self._audit_action(action, "action_approved")

        self._execute_action(action)
        return action

    def reject_action(self, action_id: str, rejected_by: str) -> Optional[ResponseAction]:
        """Rechaza una acción Nivel 2. Nunca se ejecuta."""
        action = self.store.get(action_id)
        if not action or action.status != ActionStatus.REQUESTED:
            return None

        action.status = ActionStatus.REJECTED
        action.approved_by = rejected_by
        action.timestamp_approved = _ahora()

        self.store.update(action)
        self._audit_action(action, "action_rejected")
        return action

    # --- Generación de comandos (Nivel 2: nunca se ejecutan solos) ----------
    def _generar_comando(self, action: ResponseAction) -> str | None:
        """
        El comando exacto que un operador ejecutaría manualmente, o que una
        integración real (firewall/EDR/IdP) tomaría como entrada. Se genera
        siempre, se apruebe o no, para que el analista vea qué se le pide
        aprobar — no una descripción vaga.
        """
        t = action.target
        if action.action_type == ActionType.BLOCK_IP:
            ip = t.get("ip") or t.get("target") or "<IP>"
            return f"iptables -A INPUT -s {ip} -j DROP  # o regla equivalente en el firewall perimetral"
        if action.action_type == ActionType.ISOLATE_HOST:
            host = t.get("host") or t.get("target") or "<HOST>"
            return f"# Aislar {host} de la red (ejemplo EDR): edr-cli isolate --host {host}"
        if action.action_type == ActionType.DISABLE_ACCOUNT:
            user = t.get("user") or t.get("target") or "<USUARIO>"
            return f"net user {user} /active:no  # Windows; usermod -L {user} en Linux"
        if action.action_type == ActionType.RESET_PASSWORD:
            user = t.get("user") or t.get("target") or "<USUARIO>"
            return f"net user {user} /random-password  # forzar cambio de contraseña"
        if action.action_type == ActionType.REVOKE_SESSION:
            user = t.get("user") or t.get("target") or "<USUARIO>"
            return f"# Revocar sesiones activas de {user} en el IdP (ej. Azure AD Revoke-AzureADUserAllRefreshToken)"
        if action.action_type == ActionType.QUARANTINE_FILE:
            ruta = t.get("path") or t.get("target") or "<RUTA>"
            return f"# Poner en cuarentena {ruta} vía el EDR/antivirus desplegado"
        return None

    def _execute_action(self, action: ResponseAction) -> None:
        """Ciclo de ejecución. Nunca lanza excepción hacia quien llama."""
        action.status = ActionStatus.EXECUTING
        if self.store.get(action.action_id) is None:
            self.store.create(action)
        else:
            self.store.update(action)
        self._audit_action(action, "action_executing")

        try:
            resultado = self._dispatch(action)
            action.result = resultado
            action.status = (
                ActionStatus.FAILED if resultado.get("status") == "ERROR"
                else ActionStatus.COMPLETED
            )
        except Exception as exc:  # noqa: BLE001 — un fallo de integración no debe tumbar el pipeline.
            logger.error("Fallo ejecutando la acción %s: %s", action.action_id, exc)
            action.result = {"status": "ERROR", "detail": str(exc)}
            action.status = ActionStatus.FAILED

        self.store.update(action)
        self._audit_action(action, f"action_{action.status.value}")

    def _dispatch(self, action: ResponseAction) -> dict[str, Any]:
        """Enruta la acción a su integración real, según su tipo."""
        dry_run = action.dry_run
        at = action.action_type

        if at == ActionType.SEND_WEBHOOK_ALERT:
            texto = f"[{action.incident_id}] {action.justification}"
            return self.webhook.send(texto, dry_run=dry_run)

        if at == ActionType.SEND_EMAIL_ALERT:
            return self.email.send(
                subject=f"CyberSentinel: acción sobre incidente {action.incident_id}",
                body=action.justification, dry_run=dry_run,
            )

        if at == ActionType.CREATE_TICKET:
            return self.tickets.create({
                "action_id": action.action_id, "incident_id": action.incident_id,
                "summary": action.justification, "target": action.target,
                "priority": "high",
            }, dry_run=dry_run)

        if at == ActionType.BLOCK_IOC_LOCAL:
            ioc_type = "ip" if "ip" in action.target else next(iter(action.target), "unknown")
            valor = action.target.get(ioc_type, action.target.get("target", "unknown"))
            return self.blocklist.add(ioc_type, str(valor), action.justification, dry_run=dry_run)

        if at.requires_approval:
            # Nivel 2, ya aprobado: se registra el comando generado como
            # resultado. Nunca se ejecuta contra un sistema real — no hay
            # integración de firewall/EDR/IdP en este proyecto, y añadir una
            # sin autorización explícita del operador estaría fuera de
            # alcance (ver restricciones del prompt).
            return {
                "status": "OK", "executed_against_real_system": False,
                "generated_command": action.command,
                "detail": (
                    "Comando generado y aprobado. Ejecutarlo requiere una "
                    "integración real con el firewall/EDR/IdP del entorno, "
                    "fuera del alcance de este agente."
                ),
                "at": _ahora(),
            }

        return {"status": "OK", "detail": "Sin integración real para este tipo; solo auditado.",
               "at": _ahora()}

    def _audit_action(self, action: ResponseAction, event_name: str) -> None:
        if not self.audit:
            return
        actor = action.approved_by if action.approved_by else action.requested_by
        detail = {
            "action_id": action.action_id, "incident_id": action.incident_id,
            "action_type": action.action_type.value, "status": action.status.value,
            "dry_run": action.dry_run, "command": action.command,
        }
        entry = self.audit.record(actor=actor, action=event_name, detail=detail)
        action.audit_record = entry.entry_hash
        self.store.update(action)
