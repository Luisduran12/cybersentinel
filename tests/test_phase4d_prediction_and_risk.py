"""
Pruebas de Fase 4-D: predicción con contexto, risk score y alertas proactivas.

Auditoría relevante: `Correlator`/`KillChainPrediction` (correlation/correlator.py)
ya existían, probados, pero **nunca se invocaban desde `Pipeline`** — un
hallazgo del mismo tipo que las reglas Sigma huérfanas de la Fase 4-A. Esta
fase los conecta y les agrega contexto, sin tocar el modelo de secuencia.
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cybersentinel.analytics.risk_score import (  # noqa: E402
    PROACTIVE_ALERT_THRESHOLD, RiskScoreTracker,
)
from cybersentinel.config import DEFAULT_RULES_DIR  # noqa: E402
from cybersentinel.correlation.prediction_context import (  # noqa: E402
    PredictionContext, infer_entity_type, reweight,
)
from cybersentinel.pipeline import Pipeline  # noqa: E402
from cybersentinel.schema import SecurityEvent  # noqa: E402

BASE = datetime(2025, 3, 10, 10, tzinfo=timezone.utc)


# --------------------------- prediction_context.py ---------------------------
@pytest.mark.parametrize("entity,esperado", [
    ("SRV-DB", "server"), ("srv-app-01", "server"), ("DB-PROD", "server"),
    ("WKS-01", "workstation"), ("pc-marketing", "workstation"),
    ("ana@empresa.com", "user"), ("8.8.8.8", "network_address"),
    ("host-generico", "unknown"), ("", "unknown"),
])
def test_infer_entity_type(entity, esperado):
    assert infer_entity_type(entity) == esperado


def test_reweight_favorece_fases_tardias_en_servidores():
    ranked = [("discovery", 0.3), ("exfiltration", 0.2)]
    contexto_servidor = PredictionContext("server", 0.0, 0.0, False)
    ajustado = reweight(ranked, contexto_servidor)
    # exfiltration parte más abajo pero un servidor la favorece: puede subir
    # de posición, o al menos su score sube más que el de discovery.
    exfil_ajustado = dict(ajustado)["exfiltration"]
    assert exfil_ajustado > 0.2


def test_reweight_es_neutro_sin_ningun_factor():
    ranked = [("discovery", 0.4), ("persistence", 0.3)]
    contexto_neutro = PredictionContext("unknown", 0.0, 0.0, False)
    ajustado = reweight(ranked, contexto_neutro)
    assert ajustado == ranked


def test_reweight_cti_flagged_favorece_tacticas_de_apt():
    ranked = [("discovery", 0.3), ("lateral-movement", 0.25)]
    contexto = PredictionContext("unknown", 0.0, 0.0, True)
    ajustado = reweight(ranked, contexto)
    lateral_ajustado = dict(ajustado)["lateral-movement"]
    assert lateral_ajustado == pytest.approx(0.25 * 1.4)


def test_reweight_no_supera_1_0():
    ranked = [("exfiltration", 0.9)]
    contexto = PredictionContext("server", 100.0, 10.0, True)
    ajustado = reweight(ranked, contexto)
    assert ajustado[0][1] <= 1.0


# ------------------------------- risk_score.py -------------------------------
def test_risk_score_sube_con_deteccion():
    tracker = RiskScoreTracker()
    antes = tracker.score_for("SRV-DB")
    despues = tracker.record_detection("SRV-DB", hybrid_score=90.0, when=BASE)
    assert antes == 0.0
    assert despues > antes


def test_risk_score_decae_con_el_tiempo():
    tracker = RiskScoreTracker(decay_per_hour=10.0)
    tracker.record_detection("SRV-DB", hybrid_score=90.0, when=BASE)
    inmediato = tracker.score_for("SRV-DB", now=BASE)
    diez_horas_despues = tracker.score_for("SRV-DB", now=BASE + timedelta(hours=10))
    assert diez_horas_despues < inmediato
    assert diez_horas_despues == 0.0  # 10h * 10/h = 100 puntos perdidos


def test_risk_score_cti_confirmado_dispara_boost_minimo():
    tracker = RiskScoreTracker()
    score = tracker.record_detection("SRV-DB", hybrid_score=10.0, when=BASE, cti_confirmed=True)
    assert score >= 60.0  # CTI_CONFIRMED_MIN_BOOST, aunque hybrid_score sea bajo


def test_detecciones_correlacionadas_en_el_tiempo_se_acumulan_mas_rapido():
    """
    Dos detecciones separadas por minutos apenas decaen entre sí y se
    acumulan casi por completo; las mismas dos separadas por días casi no
    dejan rastro la una de la otra.
    """
    cercanas = RiskScoreTracker(decay_per_hour=5.0)
    cercanas.record_detection("A", 60.0, when=BASE)
    score_cercano = cercanas.record_detection("A", 60.0, when=BASE + timedelta(minutes=5))

    lejanas = RiskScoreTracker(decay_per_hour=5.0)
    lejanas.record_detection("B", 60.0, when=BASE)
    score_lejano = lejanas.record_detection("B", 60.0, when=BASE + timedelta(days=5))

    assert score_cercano > score_lejano


def test_alerta_proactiva_se_dispara_una_sola_vez_por_cruce():
    tracker = RiskScoreTracker()
    # hybrid_score se pondera a 1/3: hacen falta varias detecciones seguidas
    # (o una confirmada por CTI) para cruzar el umbral, a propósito.
    for _ in range(3):
        tracker.record_detection("SRV-DB", hybrid_score=100.0, when=BASE)
    assert tracker.score_for("SRV-DB") >= PROACTIVE_ALERT_THRESHOLD
    assert tracker.due_proactive_alert("SRV-DB") is True
    assert tracker.due_proactive_alert("SRV-DB") is False  # ya se avisó


def test_alerta_proactiva_se_puede_rearmar_tras_bajar_y_volver_a_subir():
    tracker = RiskScoreTracker(decay_per_hour=1000.0)  # decae casi instantáneo
    for _ in range(3):
        tracker.record_detection("SRV-DB", hybrid_score=100.0, when=BASE)
    assert tracker.due_proactive_alert("SRV-DB") is True
    # Decae por completo...
    tracker.score_for("SRV-DB", now=BASE + timedelta(hours=1))
    tracker.record_detection("SRV-DB", hybrid_score=0.01, when=BASE + timedelta(hours=1))
    assert tracker.score_for("SRV-DB") < PROACTIVE_ALERT_THRESHOLD
    # ...y vuelve a subir: debe poder alertar de nuevo.
    for _ in range(3):
        tracker.record_detection("SRV-DB", hybrid_score=100.0, when=BASE + timedelta(hours=1, minutes=1))
    assert tracker.due_proactive_alert("SRV-DB") is True


def test_risk_score_persiste_y_se_recarga(tmp_path):
    ruta = tmp_path / "risk.json"
    tracker = RiskScoreTracker(path=ruta)
    tracker.record_detection("SRV-DB", hybrid_score=80.0, when=BASE)
    tracker.save()

    recargado = RiskScoreTracker(path=ruta)
    # `to_dict()` redondea a 2 decimales para que el JSON sea legible a ojo;
    # la comparación tolera esa pérdida de precisión, no es un bug.
    assert recargado.score_for("SRV-DB") == pytest.approx(tracker.score_for("SRV-DB"), abs=0.01)


# --------------------- integración con el pipeline real ---------------------
def test_pipeline_produce_kill_chain_prediction_real():
    """
    Fase 4-D: el `Correlator` huérfano ahora corre dentro de `Pipeline`.
    Una cadena de ataque real (fuerza bruta -> PowerShell ofuscado) debe
    producir una predicción de kill-chain de verdad, no solo detecciones
    sueltas.
    """
    pipeline = Pipeline(rules_dir=DEFAULT_RULES_DIR, enable_rag=False, enable_llm=False,
                       enable_cti=False, enable_temporal=False)
    eventos = [
        SecurityEvent(event_id=f"bf-{i}", timestamp=BASE + timedelta(seconds=i * 10),
                     source="auth", category="authentication", action="user_login",
                     host="SRV-APP", user="admin", src_ip="203.0.113.66", outcome="failure")
        for i in range(6)
    ]
    eventos.append(SecurityEvent(
        event_id="ps-1", timestamp=BASE + timedelta(seconds=120),
        source="sysmon", category="process", action="process_create",
        host="SRV-APP", user="admin",
        command_line="powershell.exe -nop -w hidden -enc SQBFAFgA",
        process_name="powershell.exe", outcome="success",
    ))

    reporte = pipeline.run_events(eventos)
    assert reporte.kill_chain_predictions, "no se produjo ninguna prediccion de kill-chain"
    prediccion = reporte.kill_chain_predictions[0]["prediction"]
    assert prediccion is not None
    assert prediccion["predicted_next"]
    assert "context" in prediccion


def test_pipeline_genera_alerta_proactiva_por_risk_score():
    """
    Una detección aislada no debe disparar una alerta proactiva por sí sola
    (hybrid_score se pondera a 1/3 justo por eso); varias detecciones
    críticas seguidas contra el mismo host sí deben acumularse hasta
    cruzar el umbral, dentro del mismo lote.
    """
    pipeline = Pipeline(rules_dir=DEFAULT_RULES_DIR, enable_rag=False, enable_llm=False,
                       enable_cti=False, enable_temporal=False, enable_behavior=False)
    # Usa el patrón de RULE-0002 (config/rules/encoded_powershell.yaml), que
    # sí está cargado por defecto en un Pipeline construido sin sigma_rules_dir.
    eventos = [
        SecurityEvent(
            event_id=f"crit-{i}", timestamp=BASE + timedelta(seconds=i),
            source="sysmon", category="process", action="process_create",
            host="SRV-DB", user="ana",
            command_line="powershell.exe -nop -w hidden -enc SQBFAFgA",
            process_name="powershell.exe", outcome="success",
        )
        for i in range(5)
    ]
    reporte = pipeline.run_events(eventos)
    assert reporte.proactive_alerts, "varias detecciones críticas seguidas no dispararon alerta proactiva"
    alerta = reporte.proactive_alerts[0]
    assert alerta["entity"] == "SRV-DB"
    assert "investigación proactiva" in alerta["message"]
    assert pipeline.risk_tracker.score_for("SRV-DB") >= PROACTIVE_ALERT_THRESHOLD


def test_evento_benigno_no_genera_alerta_proactiva():
    pipeline = Pipeline(rules_dir=DEFAULT_RULES_DIR, enable_rag=False, enable_llm=False,
                       enable_cti=False, enable_temporal=False, enable_behavior=False)
    benigno = SecurityEvent(
        event_id="ok-1", timestamp=BASE, source="sysmon", category="process",
        action="process_create", host="WKS-01", user="ana",
        command_line="chrome.exe --tab 1", process_name="chrome.exe", outcome="success",
    )
    reporte = pipeline.run_events([benigno])
    assert reporte.proactive_alerts == []
