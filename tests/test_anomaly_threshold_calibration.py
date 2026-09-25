"""
Fix del hallazgo H-08 de la auditoría de producción: el umbral de decisión
del detector de anomalías (`anomaly_score >= 0.5`, hardcodeado en cuatro
sitios distintos) generaba 78% de falsos positivos en el test de carga real.

Se calibró un umbral real (`scripts/calibrate_anomaly_threshold.py`,
metodología train/validation/test sin fuga de datos, ver
`reports/anomaly_threshold_calibration.json`) y se centralizó en
`DEFAULT_ANOMALY_THRESHOLD` (config.py, configurable con
`CYBERSENTINEL_ANOMALY_THRESHOLD`). Estas pruebas verifican que el nuevo
umbral está realmente conectado en los cuatro sitios que antes tenían un
0.5 independiente — no solo documentado.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cybersentinel.config import DEFAULT_ANOMALY_THRESHOLD, DetectionSettings  # noqa: E402
from cybersentinel.correlation.correlator import Correlator  # noqa: E402
from cybersentinel.detection.anomaly import AnomalyResult  # noqa: E402
from cybersentinel.detection.hybrid import DetectionEvidence  # noqa: E402
from cybersentinel.schema import SecurityEvent  # noqa: E402


def test_umbral_calibrado_ya_no_es_el_0_5_original():
    """
    Guarda de regresión directa del hallazgo: el umbral sin calibrar (0.5)
    medía 30.5% de FPR en validación — muy por encima del 15% objetivo.
    """
    assert DEFAULT_ANOMALY_THRESHOLD != 0.5
    assert 0.55 <= DEFAULT_ANOMALY_THRESHOLD <= 0.65, (
        f"umbral calibrado fuera del rango esperado por la auditoría: {DEFAULT_ANOMALY_THRESHOLD}"
    )


def test_detection_settings_usa_el_umbral_calibrado_por_defecto():
    assert DetectionSettings().anomaly_threshold == DEFAULT_ANOMALY_THRESHOLD


def test_detection_status_usa_el_umbral_calibrado_no_0_5():
    """
    Un anomaly_score que antes cruzaba el 0.5 pero no cruza el umbral
    calibrado ya no debe contar como ANOMALY_ONLY.
    """
    score_intermedio = (0.5 + DEFAULT_ANOMALY_THRESHOLD) / 2
    ev = DetectionEvidence(event_id="e1", anomaly_score=score_intermedio)
    assert ev.detection_status == "NO_DETECTION", (
        f"anomaly_score={score_intermedio} está entre 0.5 y el umbral calibrado "
        f"({DEFAULT_ANOMALY_THRESHOLD}); con el fix ya no debe marcarse como anomalía."
    )

    ev_por_encima = DetectionEvidence(event_id="e2", anomaly_score=DEFAULT_ANOMALY_THRESHOLD + 0.05)
    assert ev_por_encima.detection_status == "ANOMALY_ONLY"


def test_hybrid_score_ml_boost_usa_el_umbral_calibrado():
    ev = DetectionEvidence(event_id="e1", anomaly_score=0.85)
    esperado = max(0.0, (0.85 - DEFAULT_ANOMALY_THRESHOLD) * 40.0)
    assert ev.hybrid_score == pytest.approx(esperado, abs=1e-6)


def test_correlator_build_findings_usa_el_umbral_calibrado_por_defecto():
    evento = SecurityEvent(event_id="e1", timestamp=__import__("datetime").datetime.now(
        tz=__import__("datetime").timezone.utc), source="sysmon", category="process", action="x")
    score_intermedio = (0.5 + DEFAULT_ANOMALY_THRESHOLD) / 2
    resultado = AnomalyResult(event=evento, is_anomaly=True, anomaly_score=score_intermedio,
                              top_features=[])
    findings = Correlator().build_findings([], [resultado])
    assert findings == [], (
        "build_findings sigue usando el umbral 0.6 sin calibrar en vez del "
        f"umbral real ({DEFAULT_ANOMALY_THRESHOLD})"
    )


def test_informe_de_calibracion_existe_y_documenta_ambos_umbrales():
    """El informe de calibración debe existir y ser consistente con el config."""
    ruta = ROOT / "reports" / "anomaly_threshold_calibration.json"
    assert ruta.exists(), "falta reports/anomaly_threshold_calibration.json"
    datos = json.loads(ruta.read_text(encoding="utf-8"))

    assert datos["umbral_anterior_0_5"]["umbral"] == 0.5
    assert datos["umbral_calibrado"]["umbral"] == DEFAULT_ANOMALY_THRESHOLD
    assert datos["umbral_calibrado"]["cumple_ambos_objetivos_en_validation"] is True
    # Los objetivos del prompt: FPR<15%, Recall>60%, verificados en el holdout de test.
    assert datos["umbral_calibrado"]["fpr_test_holdout"] < 0.15
    assert datos["umbral_calibrado"]["recall_test_holdout"] > 0.60
