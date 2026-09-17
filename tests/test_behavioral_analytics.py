"""
Pruebas de Behavioral Analytics (Fase 4-B).

Tres capas, de abajo hacia arriba:

- **Unitarias sobre baseline.py/deviation.py**: con datos sintéticos que
  demuestran que una desviación real se detecta y una normal no dispara nada.
- **Persistencia**: el baseline sobrevive un ciclo guardar/cargar.
- **Integración con el pipeline real**: una desviación de comportamiento
  atraviesa `DetectionEvidence` y puede convertirse en hallazgo (incidente),
  usando el mismo `Pipeline` que Sigma y ML — no un pipeline paralelo.
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cybersentinel.analytics.baseline import BaselineStore, EntityBaseline  # noqa: E402
from cybersentinel.analytics.deviation import DeviationDetector, MIN_OBSERVATIONS_FOR_ALERT  # noqa: E402
from cybersentinel.analytics.profiler import EntityProfiler  # noqa: E402
from cybersentinel.config import DEFAULT_RULES_DIR  # noqa: E402
from cybersentinel.pipeline import ALERT_THRESHOLD, Pipeline  # noqa: E402
from cybersentinel.schema import SecurityEvent  # noqa: E402

BASE = datetime(2025, 3, 10, 10, tzinfo=timezone.utc)   # 10:00 UTC


def _evento(segundos: int = 0, **kw) -> SecurityEvent:
    base = dict(
        event_id=f"e{segundos}", timestamp=BASE + timedelta(seconds=segundos),
        source="sysmon", category="process", action="process_create",
        host="WKS-01", user="ana", process_name="chrome.exe",
        src_ip="10.0.0.5", dst_ip="10.0.0.1", outcome="success",
    )
    base.update(kw)
    return SecurityEvent(**base)


# ------------------------------- baseline.py --------------------------------
def test_baseline_aprende_horas_ips_y_procesos():
    store = BaselineStore()
    for i in range(20):
        store.learn_user("ana", hour=10, ip="10.0.0.5", process="chrome.exe",
                         bytes_out=1000.0, when=BASE + timedelta(minutes=i))
    baseline = store.user("ana")
    assert baseline.n_events == 20
    assert 10 in baseline.typical_hours
    assert "10.0.0.5" in baseline.ips_seen
    assert "chrome.exe" in baseline.processes_seen


def test_confianza_escala_con_observaciones():
    store = BaselineStore()
    store.learn_user("ana", hour=10, ip="1.1.1.1", process="x", bytes_out=1.0, when=BASE)
    baja = store.user("ana").confidence
    for i in range(60):
        store.learn_user("ana", hour=10, ip="1.1.1.1", process="x", bytes_out=1.0,
                         when=BASE + timedelta(minutes=i))
    alta = store.user("ana").confidence
    assert 0.0 < baja < alta <= 1.0


def test_persistencia_baseline_sobrevive_guardar_y_cargar(tmp_path):
    store = BaselineStore()
    for i in range(15):
        store.learn_host("SRV-DB", hour=14, ip="8.8.8.8", process="sqlservr.exe",
                         bytes_out=5000.0, when=BASE + timedelta(minutes=i))
    ruta = store.save(tmp_path / "baselines.json")

    recargado = BaselineStore.load(ruta)
    baseline = recargado.host("SRV-DB")
    assert baseline is not None
    assert baseline.n_events == 15
    assert "sqlservr.exe" in baseline.processes_seen
    assert 14 in baseline.typical_hours


def test_baseline_store_load_de_ruta_inexistente_devuelve_vacio(tmp_path):
    store = BaselineStore.load(tmp_path / "no-existe.json")
    assert store.user("nadie") is None
    assert store.host("nadie") is None


# ------------------------------ deviation.py --------------------------------
def _baseline_de_ana(n: int = 30) -> BaselineStore:
    store = BaselineStore()
    for i in range(n):
        # Actividad de oficina: 9am-6pm, siempre desde la misma IP.
        hora = 9 + (i % 9)
        store.learn_user("ana", hour=hora, ip="10.0.0.5", process="chrome.exe",
                         bytes_out=1000.0 + i, when=BASE + timedelta(minutes=i))
    return store


def _baseline_de_host(n: int = 30) -> BaselineStore:
    store = BaselineStore()
    for i in range(n):
        # Volumen realista: 1000-1400 bytes, no una franja artificialmente
        # estrecha — si no, cualquier variación normal parecería anómala.
        store.learn_host("WKS-01", hour=10, ip="10.0.0.1", process="chrome.exe",
                         bytes_out=1000.0 + (i * 37) % 400, when=BASE + timedelta(minutes=i))
    return store


def test_hora_inusual_se_detecta_y_se_explica():
    profiler = EntityProfiler(store=_baseline_de_ana())
    evento = _evento(timestamp=BASE.replace(hour=3, minute=17))
    detector = DeviationDetector()
    desviaciones = detector.evaluate(evento, profiler)
    horas = [d for d in desviaciones if d.kind == "unusual_hour"]
    assert horas, "no se detectó la hora inusual"
    d = horas[0]
    assert d.entity == "ana"
    assert "normalmente está activo" in d.explanation
    assert "03:xx" in d.explanation
    assert d.mitre_technique == "T1078"
    assert 0.0 < d.confidence <= 1.0


def test_ip_nunca_contactada_se_detecta():
    profiler = EntityProfiler(store=_baseline_de_ana())
    evento = _evento(src_ip="203.0.113.66", timestamp=BASE.replace(hour=10))
    desviaciones = DeviationDetector().evaluate(evento, profiler)
    ips = [d for d in desviaciones if d.kind == "unknown_ip"]
    assert ips, "no se detectó la IP desconocida"
    assert "203.0.113.66" in ips[0].explanation


def test_proceso_nunca_visto_en_el_host_se_detecta():
    profiler = EntityProfiler(store=_baseline_de_host())
    evento = _evento(process_name="mimikatz.exe", timestamp=BASE.replace(hour=10))
    desviaciones = DeviationDetector().evaluate(evento, profiler)
    procesos = [d for d in desviaciones if d.kind == "unknown_process"]
    assert procesos, "no se detectó el proceso nunca visto"
    assert procesos[0].entity == "WKS-01"
    assert procesos[0].entity_type == "host"


def test_volumen_anormal_se_detecta_por_zscore():
    profiler = EntityProfiler(store=_baseline_de_host())
    # Baseline: ~1000-1020 bytes. Un salto a 500,000 debe marcar desviación.
    evento = _evento(bytes_out=500_000.0, timestamp=BASE.replace(hour=10))
    desviaciones = DeviationDetector().evaluate(evento, profiler)
    volumen = [d for d in desviaciones if d.kind == "unusual_volume"]
    assert volumen, "no se detectó el volumen anormal"
    assert volumen[0].score > 50.0


def test_evento_normal_no_dispara_ninguna_desviacion():
    profiler = EntityProfiler(store=_baseline_de_ana())
    normal = _evento(timestamp=BASE.replace(hour=10), src_ip="10.0.0.5",
                     process_name="chrome.exe", bytes_out=1050.0, host="WKS-01")
    profiler.store.by_host["WKS-01"] = _baseline_de_host().host("WKS-01")
    desviaciones = DeviationDetector().evaluate(normal, profiler)
    assert desviaciones == [], f"un evento normal no debería desviar: {desviaciones}"


def test_baseline_con_pocas_observaciones_no_alerta():
    """
    Menos de MIN_OBSERVATIONS_FOR_ALERT observaciones: "nunca visto" no
    significa nada todavía, así que no se genera ninguna desviación.
    """
    store = BaselineStore()
    for i in range(MIN_OBSERVATIONS_FOR_ALERT - 3):
        store.learn_user("nuevo", hour=10, ip="10.0.0.5", process="chrome.exe",
                         bytes_out=1000.0, when=BASE + timedelta(minutes=i))
    profiler = EntityProfiler(store=store)
    evento = _evento(user="nuevo", src_ip="1.2.3.4", timestamp=BASE.replace(hour=3))
    desviaciones = DeviationDetector().evaluate(evento, profiler)
    assert desviaciones == []


def test_sin_baseline_previo_no_hay_desviacion():
    """La primera vez que se ve a alguien, no hay nada contra qué comparar."""
    profiler = EntityProfiler(store=BaselineStore())
    evento = _evento()
    assert DeviationDetector().evaluate(evento, profiler) == []


# --------------------- integración con el pipeline real ---------------------
def test_desviacion_alimenta_detectionevidence_y_se_vuelve_hallazgo():
    """
    Fase 4-B, tarea B3: la desviación no crea un pipeline paralelo. Se
    establece un baseline de comportamiento de oficina **plenamente
    confiable** (60+ eventos, así confidence≈1.0 y no se diluye la señal)
    con eventos reales a través de `Pipeline.run_events`, y luego un evento
    claramente anómalo (proceso nunca visto Y a las 3am) debe: (a) traer
    `behavioral_deviations` en su `DetectionEvidence`, y (b) cruzar
    `ALERT_THRESHOLD` por la combinación de ambas señales, exactamente como
    lo haría una regla Sigma.
    """
    pipeline = Pipeline(rules_dir=DEFAULT_RULES_DIR, enable_rag=False,
                       enable_llm=False, enable_cti=False, enable_temporal=False)

    normales = [
        SecurityEvent(
            event_id=f"normal-{i}", timestamp=BASE + timedelta(minutes=i % 480),
            source="sysmon", category="process", action="process_create",
            host="SRV-DB", user="ana", process_name="chrome.exe",
            src_ip="10.0.0.5", outcome="success",
        )
        for i in range(60)
    ]
    reporte_baseline = pipeline.run_events(normales)
    assert reporte_baseline.total_events == 60
    assert pipeline.profiler.profile_host("SRV-DB").confidence == 1.0

    anomalo = SecurityEvent(
        event_id="anomalo-1", timestamp=BASE.replace(hour=3, minute=17),
        source="sysmon", category="process", action="process_create",
        host="SRV-DB", user="ana", process_name="mimikatz.exe",
        src_ip="10.0.0.5", outcome="success",
    )
    reporte = pipeline.run_events([anomalo])
    evidencia = reporte.results[0].evidence

    assert evidencia.behavioral_deviations, "el evento anómalo no generó desviaciones"
    kinds = {d.kind for d in evidencia.behavioral_deviations}
    assert "unknown_process" in kinds

    assert evidencia.hybrid_score >= ALERT_THRESHOLD, (
        f"la desviación no cruzó el umbral de alerta: {evidencia.hybrid_score}"
    )
    assert reporte.findings, "el hallazgo por comportamiento no llegó a incidente"
    # El estado exacto depende de si ML también marcó el evento como anómalo
    # (aquí sí: un proceso nunca visto en producción es estadísticamente raro
    # para el propio Isolation Forest); lo que importa es que no sea NO_DETECTION.
    assert evidencia.detection_status != "NO_DETECTION"


def test_evento_de_oficina_normal_no_genera_hallazgo_por_comportamiento():
    """Control: seguir el patrón aprendido no debe generar ruido."""
    pipeline = Pipeline(rules_dir=DEFAULT_RULES_DIR, enable_rag=False,
                       enable_llm=False, enable_cti=False, enable_temporal=False)
    normales = [
        SecurityEvent(
            event_id=f"n-{i}", timestamp=BASE + timedelta(minutes=i),
            source="sysmon", category="process", action="process_create",
            host="SRV-DB", user="ana", process_name="chrome.exe",
            src_ip="10.0.0.5", outcome="success",
        )
        for i in range(15)
    ]
    pipeline.run_events(normales)

    tipico = SecurityEvent(
        event_id="tipico-1", timestamp=BASE + timedelta(minutes=16),
        source="sysmon", category="process", action="process_create",
        host="SRV-DB", user="ana", process_name="chrome.exe",
        src_ip="10.0.0.5", outcome="success",
    )
    reporte = pipeline.run_events([tipico])
    assert reporte.results[0].evidence.behavioral_deviations == []
