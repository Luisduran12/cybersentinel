"""
Gestor de Datasets de Feedback (Fase 6).

Controla la ingesta de decisiones humanas, validación, resolución de conflictos,
y previene el data leakage garantizando que los splits temporales usen el timestamp
original del evento y no el momento en que se etiquetó.
"""
import json
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Any
from .feedback import StructuredDecision, HumanDecision

logger = logging.getLogger(__name__)

class DatasetManager:
    def __init__(self, store_path: "str | Path | None" = None):
        """
        `store_path` habilita la persistencia en JSON Lines.

        Sin ella el registro vive solo en memoria y las decisiones del analista
        se pierden al terminar el proceso, lo que hace inútil el bucle de
        retroalimentación: el feedback tiene que sobrevivir a la sesión para
        poder alimentar un modelo supervisado más adelante.
        """
        # detection_id -> dict[analyst_id, StructuredDecision]
        self._decisions: dict[str, dict[str, StructuredDecision]] = {}
        # event_id -> final label (resolved if multiple analysts agree, else CONFLICT/UNCERTAIN)
        self._event_labels: dict[str, str] = {}
        self.store_path = Path(store_path) if store_path else None
        if self.store_path and self.store_path.exists():
            self._load()

    def _load(self) -> None:
        """Recarga las decisiones previamente registradas."""
        from .feedback import HumanDecision

        for line in self.store_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
                decision = StructuredDecision(
                    detection_id=raw["detection_id"],
                    event_id=raw["event_id"],
                    timestamp=datetime.fromisoformat(raw["timestamp"]),
                    analyst_decision=HumanDecision(raw["analyst_decision"]),
                    confidence=float(raw["confidence"]),
                    reason=raw.get("reason", ""),
                    selected_evidence=raw.get("selected_evidence", {}),
                    analyst_id=raw["analyst_id"],
                    model_version=raw.get("model_version", ""),
                    rule_version=raw.get("rule_version", ""),
                    data_source=raw.get("data_source", ""),
                    created_at=datetime.fromisoformat(raw["created_at"]),
                )
            except (KeyError, ValueError) as exc:
                logger.warning("Decision ilegible en %s, se omite: %s", self.store_path, exc)
                continue
            self._decisions.setdefault(decision.detection_id, {})[decision.analyst_id] = decision
            self._resolve_event_label(decision.event_id)

    def _persist(self, decision: StructuredDecision) -> None:
        """Anexa la decisión al almacén, si hay uno configurado."""
        if not self.store_path:
            return
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.store_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(decision.to_dict(), ensure_ascii=False) + "\n")

    def submit_decision(self, decision: StructuredDecision) -> bool:
        """
        Recibe una decisión. Verifica validez básica.
        """
        if not (0.0 <= decision.confidence <= 1.0):
            logger.error("Confidence debe estar entre 0.0 y 1.0")
            return False
            
        if not decision.event_id or not decision.detection_id:
            logger.error("Decision debe tener event_id y detection_id")
            return False
            
        # Ingesta
        if decision.detection_id not in self._decisions:
            self._decisions[decision.detection_id] = {}
            
        self._decisions[decision.detection_id][decision.analyst_id] = decision
        self._resolve_event_label(decision.event_id)
        self._persist(decision)
        return True
        
    def _resolve_event_label(self, event_id: str) -> None:
        """
        Calcula el consenso para un evento en base a todas las decisiones que lo referencian.
        """
        decisions_for_event = []
        for det_dict in self._decisions.values():
            for dec in det_dict.values():
                if dec.event_id == event_id:
                    decisions_for_event.append(dec)
                    
        if not decisions_for_event:
            return
            
        # Colectar todos los labels únicos emitidos (excluyendo UNCERTAIN por diseño)
        labels = {d.analyst_decision for d in decisions_for_event if d.analyst_decision != HumanDecision.UNCERTAIN}
        
        if len(labels) == 0:
            # Todos dijeron UNCERTAIN
            self._event_labels[event_id] = "UNCERTAIN"
        elif len(labels) == 1:
            # Consenso unánime
            self._event_labels[event_id] = labels.pop().value
        else:
            # Conflicto (ej. uno dice TP, otro FP)
            self._event_labels[event_id] = "CONFLICT"
            
    def get_labeled_dataset(self, cutoff_date: datetime) -> dict[str, list[StructuredDecision]]:
        """
        Prepara el dataset etiquetado asegurando separación temporal (Data Leakage Prevention).
        Usa el `timestamp` original del evento (cuándo ocurrió), NO el `created_at` (cuándo se etiquetó).
        
        Solo incluye eventos con consenso claro (descarta CONFLICT y UNCERTAIN).
        """
        dataset: dict[str, list[StructuredDecision]] = {
            "TRAIN": [],
            "VALIDATION": [],
            "TEST": []
        }
        
        # Para evitar contar eventos múltiples veces si tienen varios detection_id,
        # recolectaremos solo una decisión representante (la más reciente o de mayor confianza).
        # Por simplicidad, tomamos la primera que concuerde con el label resuelto.
        
        processed_events = set()
        
        for det_dict in self._decisions.values():
            for dec in det_dict.values():
                if dec.event_id in processed_events:
                    continue
                    
                final_label = self._event_labels.get(dec.event_id, "UNCERTAIN")
                if final_label in ("UNCERTAIN", "CONFLICT"):
                    continue
                    
                # Si el analista actual dio la decisión que resultó en consenso, lo usamos
                if dec.analyst_decision.value == final_label:
                    processed_events.add(dec.event_id)
                    
                    # Temporal Split (Data Leakage Protection)
                    if dec.timestamp < cutoff_date:
                        dataset["TRAIN"].append(dec)
                    elif dec.timestamp == cutoff_date:
                        dataset["VALIDATION"].append(dec)
                    else:
                        dataset["TEST"].append(dec)
                        
        return dataset
        
    def get_metrics(self) -> dict[str, Any]:
        """
        Retorna métricas sobre el estado de la retroalimentación.
        """
        total_decisions = sum(len(d) for d in self._decisions.values())
        unique_events = len(self._event_labels)
        
        counts = {"TRUE_POSITIVE": 0, "FALSE_POSITIVE": 0, "BENIGN": 0, "UNCERTAIN": 0, "CONFLICT": 0}
        for label in self._event_labels.values():
            if label in counts:
                counts[label] += 1
                
        return {
            "total_decisions_submitted": total_decisions,
            "unique_events_reviewed": unique_events,
            "resolved_distribution": counts,
            "ready_for_training": counts["TRUE_POSITIVE"] > 1000 and counts["FALSE_POSITIVE"] > 1000 # Dummy threshold
        }
