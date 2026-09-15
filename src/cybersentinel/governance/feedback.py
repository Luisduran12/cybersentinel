"""
Módulo de Feedback Humano (Fase 6).

Prepara la estructura para recibir, persistir y utilizar el feedback del analista
en futuros re-entrenamientos. Permite separar las falsas alarmas de las anomalías
benignas y los ataques reales, asegurando inmutabilidad (provenance) y trazabilidad.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
import json
import hashlib

class HumanDecision(str, Enum):
    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    BENIGN = "BENIGN"
    UNCERTAIN = "UNCERTAIN"

@dataclass(frozen=True)
class StructuredDecision:
    """
    Estructura inmutable que captura la decisión de un analista sobre una alerta.
    Garantiza que la evidencia que el humano observó (selected_evidence) quede
    sellada y no pueda mutar si las reglas cambian en el futuro.
    """
    detection_id: str
    event_id: str
    timestamp: datetime  # Original event timestamp (for data leakage prevention)
    analyst_decision: HumanDecision
    confidence: float
    reason: str
    selected_evidence: dict[str, Any]
    analyst_id: str
    model_version: str
    rule_version: str
    data_source: str
    created_at: datetime
    
    def fingerprint(self) -> str:
        """Firma única de esta decisión."""
        basis = f"{self.detection_id}|{self.analyst_id}|{self.created_at.isoformat()}"
        return hashlib.sha256(basis.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "detection_id": self.detection_id,
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "analyst_decision": self.analyst_decision.value,
            "confidence": round(self.confidence, 4),
            "reason": self.reason,
            "selected_evidence": self.selected_evidence,
            "analyst_id": self.analyst_id,
            "model_version": self.model_version,
            "rule_version": self.rule_version,
            "data_source": self.data_source,
            "created_at": self.created_at.isoformat(),
            "fingerprint": self.fingerprint()
        }
