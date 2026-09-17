import logging
import os
import time
from typing import Any, Optional

from ..governance.audit import AuditLog
from .models import ActionStatus, ActionType, ResponseAction
from .store import ResponseStore

logger = logging.getLogger(__name__)


class ExternalIntegrationMock:
    """Mock for an external integration to showcase retry, timeout, and rollback."""
    
    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run

    def execute(self, action_type: str, target: dict[str, Any]) -> dict[str, Any]:
        """Simulate API call to external systems."""
        if self.dry_run:
            logger.info(f"[DRY RUN] Executing {action_type} on {target}")
            # Simulate network latency
            time.sleep(0.1)
            return {"status": "success", "message": f"[DRY RUN] {action_type} executed successfully", "dry_run": True}
        
        # In a real system, this would make an HTTP call or use an SDK
        logger.warning(f"[REAL RUN] Executing {action_type} on {target}")
        time.sleep(0.5)
        # Simulate some flakiness or real results
        return {"status": "success", "message": f"{action_type} executed successfully", "dry_run": False}


class ResponseExecutor:
    """
    Cerebro of the Response Layer. Validates, routes, and executes actions.
    """
    
    def __init__(self, store: ResponseStore, audit: AuditLog):
        self.store = store
        self.audit = audit
        # Global DRY_RUN flag defaults to True. Can be overridden in prod carefully.
        self.global_dry_run = os.environ.get("CYBERSENTINEL_DRY_RUN", "true").lower() in {"1", "true", "yes"}
        self.integration = ExternalIntegrationMock(dry_run=self.global_dry_run)

    def request_action(self, action: ResponseAction) -> ResponseAction:
        """
        Submits an action request.
        If it's a Phase 1 safe action, it can be executed immediately or transition to APPROVED.
        If it's Phase 2, it stays in REQUESTED.
        """
        action.dry_run = self.global_dry_run
        
        if not action.action_type.requires_approval:
            # Phase 1: Auto-approve
            action.status = ActionStatus.APPROVED
            # We execute it immediately for simplicity in this phase
            self._execute_action(action)
        else:
            action.status = ActionStatus.REQUESTED
            self.store.create(action)
            self._audit_action(action, "action_requested")
        
        return action

    def approve_action(self, action_id: str, approved_by: str) -> Optional[ResponseAction]:
        """Approve a Phase 2 action and trigger execution."""
        action = self.store.get(action_id)
        if not action or action.status != ActionStatus.REQUESTED:
            return None
            
        action.status = ActionStatus.APPROVED
        action.approved_by = approved_by
        from .models import _ahora
        action.timestamp_approved = _ahora()
        
        self.store.update(action)
        self._audit_action(action, "action_approved")
        
        # Trigger execution synchronously for now (could be async in future)
        self._execute_action(action)
        return action

    def reject_action(self, action_id: str, rejected_by: str) -> Optional[ResponseAction]:
        """Reject a Phase 2 action."""
        action = self.store.get(action_id)
        if not action or action.status != ActionStatus.REQUESTED:
            return None
            
        action.status = ActionStatus.REJECTED
        action.approved_by = rejected_by  # store the rejector here
        from .models import _ahora
        action.timestamp_approved = _ahora()
        
        self.store.update(action)
        self._audit_action(action, "action_rejected")
        return action

    def _execute_action(self, action: ResponseAction) -> None:
        """Handles the execution lifecycle of an action."""
        action.status = ActionStatus.EXECUTING
        # Si la acción acaba de ser creada y auto-aprobada (Fase 1), primero se guarda.
        # Si viene de `approve_action`, ya existe y usamos update.
        if self.store.get(action.action_id) is None:
            self.store.create(action)
        else:
            self.store.update(action)
            
        self._audit_action(action, "action_executing")

        try:
            # Simulate execution via the external integration mock
            result = self.integration.execute(action.action_type.value, action.target)
            action.result = result
            action.status = ActionStatus.COMPLETED
        except Exception as e:
            logger.error(f"Failed to execute action {action.action_id}: {e}")
            action.result = {"error": str(e)}
            action.status = ActionStatus.FAILED
            
        self.store.update(action)
        self._audit_action(action, f"action_{action.status.value}")

    def _audit_action(self, action: ResponseAction, event_name: str) -> None:
        """Records the action's transition in the cryptographic AuditLog."""
        if not self.audit:
            return
            
        actor = action.approved_by if action.approved_by else action.requested_by
        detail = {
            "action_id": action.action_id,
            "incident_id": action.incident_id,
            "action_type": action.action_type.value,
            "status": action.status.value,
            "dry_run": action.dry_run
        }
        
        # Log into the system audit log
        entry = self.audit.record(
            actor=actor,
            action=event_name,
            detail=detail
        )
        # Update the action record with the latest audit_record hash for cross-referencing
        action.audit_record = entry.entry_hash
        self.store.update(action)
