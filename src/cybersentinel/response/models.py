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
    # Phase 1: Safe actions (No approval required)
    CREATE_TICKET = "crear_ticket"
    SEND_ALERT = "enviar_alerta"
    ADD_RECOMMENDATION = "agregar_recomendación"
    MARK_HOST_SUSPICIOUS = "marcar_host_sospechoso"
    GENERATE_CONTAINMENT_PROCEDURE = "generar_procedimiento_contención"

    # Phase 2: Sensitive actions (Approval required)
    BLOCK_IP = "bloquear_ip"
    ISOLATE_HOST = "aislar_host"
    DISABLE_ACCOUNT = "deshabilitar_cuenta"
    REVOKE_SESSION = "revocar_sesión"
    QUARANTINE_FILE = "poner_en_cuarentena_archivo"

    @property
    def requires_approval(self) -> bool:
        return self in {
            ActionType.BLOCK_IP,
            ActionType.ISOLATE_HOST,
            ActionType.DISABLE_ACCOUNT,
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
    
    status: ActionStatus = ActionStatus.REQUESTED
    
    requested_by: str
    timestamp_requested: str = Field(default_factory=_ahora)
    
    approved_by: Optional[str] = None
    timestamp_approved: Optional[str] = None
    
    result: Optional[dict[str, Any]] = None
    dry_run: bool = True
    
    audit_record: Optional[str] = None
