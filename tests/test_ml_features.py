"""
Tests for ML Features extraction and stability (Phase 4.1).
"""
import numpy as np
import pytest
from datetime import datetime, timezone

from cybersentinel.schema import SecurityEvent
from cybersentinel.detection.anomaly import AnomalyDetector
from cybersentinel.ml.base import Dataset

def test_zero_variance_feature_does_not_explode():
    """
    Test que verifica la regla de estabilidad matemática:
    Si una característica es constante en el entrenamiento (varianza 0), 
    su división en la estandarización no debe producir Inf, NaN o valores del orden de 1e9.
    """
    detector = AnomalyDetector()
    
    # Train events (all have same port = constant feature, variance = 0)
    train_events = [
        SecurityEvent(event_id=f"t{i}", timestamp=datetime(2026, 1, 1, i, tzinfo=timezone.utc), 
                      source="net", category="network", action="connection", dst_port=80) 
        for i in range(10)
    ]
    
    detector.fit(Dataset(X=np.array([]), events=train_events))
    
    # The 'is_rare_port' and 'port_rarity' features will be exactly the same for all train events.
    # We send a test event with a different port.
    test_events = [
        SecurityEvent(event_id="test", timestamp=datetime(2026, 1, 2, 0, tzinfo=timezone.utc), 
                      source="net", category="network", action="connection", dst_port=4444)
    ]
    
    test_X = detector.extractor.extract_batch(test_events)
    # Estandarizar manualmente como lo hace el predictor
    test_Xn = (test_X - detector._means) / detector._stds
    
    # Comprobar que no haya NaNs, Infs, o valores absolutos mayores a 1e5
    assert not np.isnan(test_Xn).any()
    assert not np.isinf(test_Xn).any()
    assert np.max(np.abs(test_Xn)) < 1e5, f"Encontrados valores atípicamente altos: {test_Xn}"

def test_transformation_is_consistent():
    """Verifica que transformaciones sean consistentes"""
    detector = AnomalyDetector()
    train_events = [
        SecurityEvent(event_id="t1", timestamp=datetime(2026, 1, 1, 1, tzinfo=timezone.utc), 
                      source="sys", category="process", action="process_create", command_line="cmd.exe"),
        SecurityEvent(event_id="t2", timestamp=datetime(2026, 1, 1, 2, tzinfo=timezone.utc), 
                      source="sys", category="process", action="process_create", command_line="powershell.exe -enc")
    ]
    
    detector.fit(Dataset(X=np.array([]), events=train_events))
    
    X1 = detector.extractor.extract_batch(train_events)
    X2 = detector.extractor.extract_batch(train_events)
    
    np.testing.assert_allclose(X1, X2)
