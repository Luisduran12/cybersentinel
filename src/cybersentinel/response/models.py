import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class ActionStatus(str, Enum):
    REQUESTED = "requested"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"


class ActionType(str, Enum):
    # Nivel 1: automáticas, sin aprobación humana. Ejecutan de verdad
    # (Fase 4-E) — webhook/email reales si hay credenciales, ticket y bloqueo
    # de IOC locales siempre reales, sin necesitar ninguna credencial externa.
    CREATE_TICKET = "crear_ticket"
    SEND_ALERT = "enviar_alerta"
    SEND_WEBHOOK_ALERT = "enviar_webhook"
    SEND_EMAIL_ALERT = "enviar_email"
    BLOCK_IOC_LOCAL = "bloquear_ioc_local"
    ADD_RECOMMENDATION = "agregar_recomendación"
    MARK_HOST_SUSPICIOUS = "marcar_host_sospechoso"
    GENERATE_CONTAINMENT_PROCEDURE = "generar_procedimiento_contención"

    # Nivel 2: sensibles, requieren aprobación humana. Incluso aprobadas,
    # esto SOLO genera el comando exacto (`ResponseAction.command`) — no
    # existe integración real con un firewall/EDR/IdP en este proyecto, y
    # ejecutar contra uno sería una acción contra un sistema externo sin
    # autorización, prohibido explícitamente.
    BLOCK_IP = "bloquear_ip"
    ISOLATE_HOST = "aislar_host"
    DISABLE_ACCOUNT = "deshabilitar_cuenta"
    RESET_PASSWORD = "restablecer_contraseña"
    REVOKE_SESSION = "revocar_sesión"
    QUARANTINE_FILE = "poner_en_cuarentena_archivo"

    @property
    def requires_approval(self) -> bool:
        return self in {
            ActionType.BLOCK_IP,
            ActionType.ISOLATE_HOST,
            ActionType.DISABLE_ACCOUNT,
            ActionType.RESET_PASSWORD,
            ActionType.REVOKE_SESSION,
            ActionType.QUARANTINE_FILE,
        }


def _ahora() -> str:
    return datetime.now(timezone.utc).isoformat()


class ResponseAction(BaseModel):
    action_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str
    action_type: ActionType
    target: dict[str, Any]
    justification: str
    #: El comando/payload exacto que se ejecutaría (Nivel 2) o que ya se
    #: ejecutó (Nivel 1). Se rellena al construir la acción, no al
    #: ejecutarla: un analista debe poder ver qué se propone ANTES de aprobar.
    command: Optional[str] = None

    status: ActionStatus = ActionStatus.REQUESTED
    
    requested_by: str
    timestamp_requested: str = Field(default_factory=_ahora)
    
    approved_by: Optional[str] = None
    timestamp_approved: Optional[str] = None
    
    result: Optional[dict[str, Any]] = None
    dry_run: bool = True
    
    audit_record: Optional[str] = None
