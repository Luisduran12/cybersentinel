"""
Pruebas del banco de rendimiento y ablación.

Un banco de pruebas que se degrada en silencio es peor que no tenerlo: sigue
produciendo tablas con aspecto de medición. Estas pruebas fijan las propiedades
de las que depende que sus números signifiquen algo.

Se ejecuta con escenarios diminutos —el banco real tarda ~90 s— porque lo que se
verifica aquí es la corrección del instrumento, no el rendimiento de la máquina.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from benchmark_enterprise import (  # noqa: E402
    CONFIGURACIONES,
    ESCENARIOS,
    MonitorRecursos,
    _atribucion,
    _estadisticas,
    analiza_falsos_positivos,
    construye_conjunto,
    experimento_ablacion,
    experimento_carga,
)
from cybersentinel.pipeline import ALERT_THRESHOLD, Pipeline  # noqa: E402

RULES = ROOT / "config" / "rules"


# ----------------------------- verdad-terreno --------------------------------
def test_el_conjunto_tiene_ambas_clases_y_casos_dificiles():
    conjunto = construye_conjunto(n_benignos=100)
    etiquetas = {x.label for x in conjunto}
    assert etiquetas == {0, 1}, "un conjunto de una sola clase no mide nada"
    escenarios = {x.scenario for x in conjunto}
    assert any(e.startswith("benigno_dificil") for e in escenarios), (
        "sin benignos difíciles, una tasa de falsos positivos baja no dice nada"
    )
    assert sum(1 for e in escenarios if e.startswith("ataque")) >= 5


def test_el_conjunto_es_reproducible():
    """Misma semilla, mismo conjunto: si no, dos ejecuciones no son comparables."""
    a = construye_conjunto(n_benignos=50, seed=7)
    b = construye_conjunto(n_benignos=50, seed=7)
    assert [x.event.command_line for x in a] == [x.event.command_line for x in b]
    assert [x.label for x in a] == [x.label for x in b]


def test_la_etiqueta_no_viene_de_ningun_detector():
    """
    La verdad-terreno la fija el generador, no el sistema.

    Usar la salida de un componente como etiqueta de otro produce números que
    solo miden el acuerdo entre ambos. Esta prueba comprueba que el fichero del
    banco no importa el motor de detección para etiquetar.
    """
    import ast

    arbol = ast.parse((ROOT / "scripts" / "benchmark_enterprise.py").read_text("utf-8"))
    funcion = next(n for n in ast.walk(arbol)
                   if isinstance(n, ast.FunctionDef) and n.name == "construye_conjunto")
    for nodo in ast.walk(funcion):
        assert not isinstance(nodo, (ast.Import, ast.ImportFrom)), (
            "el generador de verdad-terreno no debe importar nada del detector"
        )


def test_los_fallos_de_autenticacion_benignos_son_realmente_aislados():
    """
    Regresión: el escenario decía "aislado" pero generaba 30 fallos seguidos del
    mismo usuario desde la misma IP, que es justo lo que una regla de fuerza
    bruta debe detectar. Producía 6 falsos positivos que eran errores de
    etiquetado, no del detector.
    """
    conjunto = construye_conjunto(n_benignos=60)
    aislados = [x.event for x in conjunto
                if x.scenario == "benigno_dificil_fallo_aislado"]
    assert aislados
    for campo in ("user", "src_ip"):
        valores = [getattr(e, campo) for e in aislados]
        assert len(set(valores)) == len(valores), (
            f"los fallos 'aislados' comparten {campo}: acumulan en la agregación"
        )


# ------------------------------- estadística ---------------------------------
def test_las_estadisticas_vacias_no_se_rellenan_con_ceros():
    """Un percentil de una muestra vacía es NOT EVALUABLE, no 0.0."""
    assert _estadisticas([])["status"] == "NOT EVALUABLE"


def test_los_percentiles_estan_ordenados():
    datos = [float(i) for i in range(1, 101)]
    r = _estadisticas(datos)
    assert r["p50"] <= r["p95"] <= r["p99"] <= r["max"]
    assert r["samples"] == 100


def test_la_atribucion_declara_lo_que_no_explica():
    """Un desglose que no suma el total debe decir cuánto le falta."""
    r = _atribucion({"a": [1.0], "b": [2.0]}, [10.0])
    assert r["attributed_ms"] == 3.0
    assert r["unattributed_ms"] == 7.0
    assert r["coverage"] == 0.3


# -------------------------------- recursos -----------------------------------
def test_el_monitor_de_recursos_siempre_mide_algo():
    """Sin psutil se degrada a `resource`, no a NOT EVALUABLE."""
    with MonitorRecursos(intervalo=0.01):
        sum(range(200_000))
    # El backend real depende del entorno; ambos deben producir un resumen.


def test_el_monitor_declara_con_que_midio():
    with MonitorRecursos(intervalo=0.01) as m:
        sum(range(200_000))
    resumen = m.resumen()
    assert resumen["backend"] in ("psutil", "resource")
    if resumen["status"] == "OK":
        assert "cpu_percent" in resumen and "rss_mb" in resumen


# --------------------------------- carga -------------------------------------
def test_la_carga_distingue_servicio_de_respuesta():
    """
    Bajo saturación el servicio se mantiene plano y la respuesta crece. Si el
    banco reportara solo el servicio, un sistema saturado parecería sano.
    """
    conjunto = construye_conjunto(n_benignos=40)
    r = experimento_carga(conjunto, objetivo=200, segundos=1)
    assert r["service_latency_ms"]["samples"] > 0
    assert r["response_latency_ms"]["samples"] > 0
    assert r["response_latency_ms"]["p50"] >= r["service_latency_ms"]["p50"]
    assert "saturated" in r and "max_backlog_s" in r


def test_la_carga_reporta_recursos_y_errores():
    conjunto = construye_conjunto(n_benignos=40)
    r = experimento_carga(conjunto, objetivo=200, segundos=1)
    assert r["resources"]["status"] in ("OK", "NOT EVALUABLE")
    assert isinstance(r["errors_by_type"], dict)
    assert r["events_processed"] > 0
    assert r["warmup_events"] > 0, "el arranque debe excluirse y declararse"


def test_el_desglose_por_lote_cubre_el_tiempo_real():
    """
    Regresión: la traza por evento solo cronometraba la consulta al resultado
    ya calculado y atribuía el 3 % del tiempo de servicio. El trabajo ocurre en
    las fases por lote, que ahora se miden.
    """
    conjunto = construye_conjunto(n_benignos=100)
    r = experimento_carga(conjunto, objetivo=500, segundos=1)
    cobertura = r["attribution"]["coverage"]
    assert cobertura != "NOT EVALUABLE"
    assert cobertura > 0.5, f"el desglose solo explica el {cobertura:.1%} del tiempo"


def test_el_pipeline_publica_los_tiempos_por_lote():
    conjunto = construye_conjunto(n_benignos=30)
    pipeline = Pipeline(rules_dir=RULES, enable_rag=False, enable_llm=False)
    reporte = pipeline.run_events([x.event for x in conjunto])
    for fase in ("sigma_batch", "temporal_batch", "ml_batch", "per_event_loop"):
        assert fase in reporte.batch_timings_ms
    assert reporte.batch_timings_ms["total"] > 0
    assert "batch_timings_ms" in reporte.to_dict()


def test_los_cinco_escenarios_exigidos_estan_definidos():
    assert ESCENARIOS == [100, 500, 1_000, 5_000, 10_000]


# ------------------------------- ablación ------------------------------------
@pytest.fixture(scope="module")
def ablacion():
    return experimento_ablacion(construye_conjunto(n_benignos=150))


def test_las_siete_configuraciones_se_evaluan(ablacion):
    assert len(CONFIGURACIONES) == 7
    assert set(ablacion) == set(CONFIGURACIONES)


def test_la_matriz_de_confusion_cuadra(ablacion):
    for nombre, r in ablacion.items():
        total = r["TP"] + r["FP"] + r["TN"] + r["FN"]
        assert total == len(r["_pred"]), f"{nombre}: la matriz no suma el total"


def test_las_metricas_indefinidas_no_se_inventan(ablacion):
    """Sin detecciones no hay precisión: es NOT EVALUABLE, no 0.0 ni 1.0."""
    for nombre, r in ablacion.items():
        if r["TP"] + r["FP"] == 0:
            assert r["precision"] == "NOT EVALUABLE", nombre


def test_se_declara_que_configuraciones_son_ciegas_por_construccion(ablacion):
    """
    Sin Sigma, la puntuación híbrida no alcanza el umbral bajo ninguna
    telemetría: el ML aporta como máximo 20 puntos y la correlación 30, frente a
    los 50 de una regla. Un recall de 0 en esas configuraciones mide la capa de
    puntuación, no la señal, y el banco debe decirlo en lugar de dejar un cero
    sin explicación.
    """
    ciegas = {n for n, r in ablacion.items()
              if r["score_distribution"]["structurally_blind"]}
    assert ciegas, (
        "ninguna configuración marcada como ciega: si la capa de puntuación ha "
        "cambiado, revise docs/BENCHMARK.md sección 3 antes de tocar esta prueba"
    )
    for nombre in ciegas:
        assert ablacion[nombre]["score_distribution"]["max_observed"] < ALERT_THRESHOLD
        assert ablacion[nombre]["detections"] == 0


def test_el_recall_se_reporta_por_evento_y_por_incidente(ablacion):
    """
    Las reglas agregadas detectan la secuencia, no cada evento que la compone.
    Contar solo por evento las penaliza por hacer lo que deben.
    """
    for nombre, r in ablacion.items():
        inc = r["incident_level"]
        assert inc["total"] >= 5
        assert 0 <= inc["detected"] <= inc["total"]
        if r["detections"] > 0:
            assert inc["detected"] > 0, nombre


def test_todas_las_configuraciones_ven_los_mismos_datos(ablacion):
    tamanos = {len(r["_pred"]) for r in ablacion.values()}
    assert len(tamanos) == 1, "comparar configuraciones sobre datos distintos no mide nada"


# --------------------------- falsos positivos --------------------------------
def test_el_analisis_de_falsos_positivos_atribuye_una_causa():
    conjunto = construye_conjunto(n_benignos=150)
    r = analiza_falsos_positivos(conjunto, {})
    assert r["threshold"] == ALERT_THRESHOLD
    assert r["benign_events"] > 0
    assert sum(r["by_scenario"].values()) == r["total_false_positives"]
    assert sum(r["by_cause"].values()) == r["total_false_positives"]
    for ejemplo in r["examples"]:
        assert ejemplo["cause"]
        assert ejemplo["hybrid_score"] >= ALERT_THRESHOLD


# ------------------------------ persistencia ---------------------------------
def test_el_banco_persiste_los_cinco_ficheros(tmp_path, monkeypatch):
    """La entrega exige cinco ficheros con nombre fijo en results/benchmark_<run_id>/."""
    import benchmark_enterprise as bench

    monkeypatch.setattr(bench, "RESULTS", tmp_path)
    monkeypatch.setattr(sys, "argv", ["benchmark", "--only-ablation", "--benign", "60"])
    assert bench.main() == 0

    destinos = list(tmp_path.glob("benchmark_*"))
    assert len(destinos) == 1
    for nombre in ("metrics.json", "ablation.json", "latency_breakdown.json",
                   "false_positive_analysis.json", "run_metadata.json"):
        ruta = destinos[0] / nombre
        assert ruta.exists(), f"falta {nombre}"
        json.loads(ruta.read_text(encoding="utf-8"))

    meta = json.loads((destinos[0] / "run_metadata.json").read_text(encoding="utf-8"))
    for clave in ("run_id", "timestamp", "seed", "dataset", "config", "versions"):
        assert clave in meta
    assert meta["dataset"]["malicious"] > 0 and meta["dataset"]["benign"] > 0


def test_lo_persistido_no_arrastra_campos_internos(tmp_path, monkeypatch):
    """`_pred` es de uso interno: no debe acabar en el artefacto publicado."""
    import benchmark_enterprise as bench

    monkeypatch.setattr(bench, "RESULTS", tmp_path)
    monkeypatch.setattr(sys, "argv", ["benchmark", "--only-ablation", "--benign", "60"])
    bench.main()
    destino = next(tmp_path.glob("benchmark_*"))
    datos = json.loads((destino / "ablation.json").read_text(encoding="utf-8"))
    for r in datos.values():
        assert not any(k.startswith("_") for k in r)
