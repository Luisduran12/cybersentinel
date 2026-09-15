"""
Tests para Fase 6: Human-in-the-Loop y Dataset de Feedback.
"""
import pytest
from datetime import datetime, timezone, timedelta
from cybersentinel.governance.feedback import StructuredDecision, HumanDecision
from cybersentinel.governance.dataset_manager import DatasetManager

def test_structured_decision_immutability():
    dec = StructuredDecision(
        detection_id="d1",
        event_id="e1",
        timestamp=datetime.now(timezone.utc),
        analyst_decision=HumanDecision.TRUE_POSITIVE,
        confidence=0.9,
        reason="Looks bad",
        selected_evidence={"ip": "1.1.1.1"},
        analyst_id="A1",
        model_version="1.0",
        rule_version="1.0",
        data_source="fw",
        created_at=datetime.now(timezone.utc)
    )
    
    # Probar que es inmutable (frozen dataclass)
    with pytest.raises(Exception): # dataclass.FrozenInstanceError
        dec.confidence = 1.0

def test_dataset_manager_conflict_resolution():
    manager = DatasetManager()
    now = datetime.now(timezone.utc)
    
    # Analista 1 dice FP
    d1 = StructuredDecision("d1", "e1", now, HumanDecision.FALSE_POSITIVE, 0.9, "", {}, "A1", "1", "1", "s", now)
    manager.submit_decision(d1)
    assert manager._event_labels["e1"] == "FALSE_POSITIVE"
    
    # Analista 2 dice TP (Conflicto!)
    d2 = StructuredDecision("d1", "e1", now, HumanDecision.TRUE_POSITIVE, 0.9, "", {}, "A2", "1", "1", "s", now)
    manager.submit_decision(d2)
    assert manager._event_labels["e1"] == "CONFLICT"
    
    # Evento con UNCERTAIN
    d3 = StructuredDecision("d2", "e2", now, HumanDecision.UNCERTAIN, 0.5, "", {}, "A1", "1", "1", "s", now)
    manager.submit_decision(d3)
    assert manager._event_labels["e2"] == "UNCERTAIN"
    
    # Si Analista 2 viene y dice BENIGN, se resuelve como BENIGN (UNCERTAIN se ignora)
    d4 = StructuredDecision("d2", "e2", now, HumanDecision.BENIGN, 0.9, "", {}, "A2", "1", "1", "s", now)
    manager.submit_decision(d4)
    assert manager._event_labels["e2"] == "BENIGN"

def test_data_leakage_temporal_split():
    manager = DatasetManager()
    
    # Cutoff date (ej. Hoy a las 12:00)
    cutoff = datetime(2026, 9, 14, 12, 0, tzinfo=timezone.utc)
    
    # Evento viejo (Ocurrió hace 2 días, pero el analista lo etiqueta HOY despues del cutoff)
    event_time_old = cutoff - timedelta(days=2)
    eval_time_new = cutoff + timedelta(days=1)
    
    d1 = StructuredDecision("d1", "e1", event_time_old, HumanDecision.TRUE_POSITIVE, 0.9, "", {}, "A1", "1", "1", "s", eval_time_new)
    manager.submit_decision(d1)
    
    # Evento del futuro (Ocurrió mañana, etiquetado mañana)
    event_time_future = cutoff + timedelta(days=1)
    d2 = StructuredDecision("d2", "e2", event_time_future, HumanDecision.FALSE_POSITIVE, 0.9, "", {}, "A1", "1", "1", "s", event_time_future)
    manager.submit_decision(d2)
    
    dataset = manager.get_labeled_dataset(cutoff)
    
    # El evento viejo debe ir a TRAIN porque ocurrió antes del cutoff, 
    # sin importar que el label fue asignado después del cutoff.
    assert len(dataset["TRAIN"]) == 1
    assert dataset["TRAIN"][0].event_id == "e1"
    
    # El evento futuro va a TEST
    assert len(dataset["TEST"]) == 1
    assert dataset["TEST"][0].event_id == "e2"
    assert len(dataset["VALIDATION"]) == 0
