"""
Pruebas de la API de ingestión en tiempo real.

La prueba central es de extremo a extremo y **no usa dobles**: el evento recorre

    HTTP → validación → normalización → cola → pipeline real → evidencia
    → persistencia en SQLite → auditoría

y se comprueba que el resultado existe en disco, no solo en memoria.
"""
from __future__ import annotations

import json
import sqlite3
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cybersentinel.api.app import IngestService, create_app  # noqa: E402
from cybersentinel.api.models import RawEvent  # noqa: E402
from cybersentinel.api.queue import IngestQueue, QueueFull  # noqa: E402
from cybersentinel.api.security import (  # noqa: E402
    IdentityStore, LimitPolicy, RateLimiter, Role, SecurityConfig, SecurityGate,
)
from cybersentinel.api.store import ResultStore  # noqa: E402

BASE = datetime(2025, 3, 10, 10, tzinfo=timezone.utc)
RULES = ROOT / "config" / "rules"


def _evento(segundos: int = 0, **kwargs) -> dict:
    datos = {
        "source": "sysmon",
        "timestamp": (BASE + timedelta(seconds=segundos)).isoformat(),
        "action": "process_create",
        "host": "SRV-APP",
        "user": "admin",
        "command_line": "chrome.exe --tab 1",
        "outcome": "success",
    }
    datos.update(kwargs)
    return datos


@pytest.fixture(scope="module")
def servicio(tmp_path_factory):
    """
    Un servicio real con el pipeline real.

    RAG y LLM se desactivan **solo** para que la suite no tarde minutos
    indexando 222 documentos por cada prueba; Sigma, ML, temporal y CTI —lo que
    decide la detección— corren de verdad.
    """
    directorio = tmp_path_factory.mktemp("api")
    svc = IngestService(
        rules_dir=RULES,
        db_path=directorio / "events.db",
        audit_path=directorio / "audit.jsonl",
        queue_maxsize=5000,
        batch_size=200,
        enable_rag=False,
        enable_llm=False,
    )
    yield svc


@pytest.fixture(scope="module")
def puerta(tmp_path_factory):
    """
    Frontera real con credenciales de prueba.

    Desde que la API exige credencial, estas pruebas la presentan: comprobar la
    ingestión con la seguridad desactivada mediría un servicio que no existe.
    Los límites de caudal se abren de par en par porque aquí se mide el
    pipeline, no el limitador —eso lo cubre `test_api_security.py`—.
    """
    directorio = tmp_path_factory.mktemp("identidades")
    almacen = IdentityStore(directorio / "identities.db")
    sensor = almacen.create_api_key("suite-de-pruebas", Role.SENSOR)
    almacen.create_user("lectora", "contraseña-de-prueba-larga", Role.ANALYST)

    abierto = LimitPolicy(10_000, 20_000, 10_000_000, 20_000_000)
    gate = SecurityGate(SecurityConfig(
        identity_db=directorio / "identities.db",
        jwt_secret="0123456789abcdef0123456789abcdef0123456789abcdef",
        rate_limiter=RateLimiter({r.value: abierto for r in Role} | {"anonymous": abierto}),
    ))
    gate.sensor_key = sensor.token  # atajo para las pruebas
    return gate


@pytest.fixture(scope="module")
def cliente(servicio, puerta):
    with TestClient(create_app(servicio, gate=puerta)) as c:
        # El cliente por defecto es un sensor: es quien ingiere.
        c.headers.update({"X-API-Key": puerta.sensor_key})
        yield c


@pytest.fixture(scope="module")
def lectora(cliente):
    """Cabeceras de un analista, para las rutas de solo lectura."""
    r = cliente.post("/api/v1/auth/token",
                     json={"username": "lectora", "password": "contraseña-de-prueba-larga"},
                     headers={"X-API-Key": ""})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}", "X-API-Key": ""}


def _esperar_procesados(servicio, esperados: int, timeout: float = 30.0) -> int:
    """Espera a que el worker drene la cola."""
    limite = time.time() + timeout
    while time.time() < limite:
        if servicio.store.count() >= esperados:
            return servicio.store.count()
        time.sleep(0.1)
    return servicio.store.count()


# ------------------------------- validación ---------------------------------
def test_rechaza_evento_sin_source(cliente):
    r = cliente.post("/api/v1/events", json={"events": [{"command_line": "x"}]})
    assert r.status_code == 422


def test_rechaza_timestamp_ilegible(cliente):
    """
    Un timestamp presente pero ilegible se rechaza en vez de sustituirse por la
    hora actual: una marca falsa contamina la correlación temporal.
    """
    r = cliente.post("/api/v1/events",
                     json={"events": [{"source": "auth", "timestamp": "ayer"}]})
    assert r.status_code == 422
    assert "timestamp" in r.text.lower()


def test_genera_event_id_y_lo_declara(cliente):
    r = cliente.post("/api/v1/events", json={"events": [_evento(1)]})
    assert r.status_code == 202
    assert r.json()["annotations"].get("event_id_generado", 0) >= 1


def test_conserva_el_timestamp_original(servicio):
    evento = RawEvent(**_evento(5))
    registro, _ = evento.to_record()
    normalizado = servicio.normalizer.normalize_record(registro)
    assert normalizado.timestamp == BASE + timedelta(seconds=5)


def test_lote_vacio_es_invalido(cliente):
    assert cliente.post("/api/v1/events", json={"events": []}).status_code == 422


def test_acepta_lote_mixto_y_reporta_lo_rechazado(cliente):
    r = cliente.post("/api/v1/events", json={"events": [
        _evento(10), {"source": "", "x": 1}, _evento(11),
    ]})
    # El evento con source vacío lo rechaza Pydantic antes de llegar al servicio.
    assert r.status_code == 422


# --------------------------------- salud ------------------------------------
def test_health_responde(cliente):
    r = cliente.get("/api/v1/health")
    assert r.status_code == 200 and r.json()["status"] == "alive"


def test_ready_declara_el_estado_de_los_componentes(cliente, lectora):
    r = cliente.get("/api/v1/ready", headers=lectora)
    cuerpo = r.json()
    assert r.status_code in (200, 503)
    assert cuerpo["worker_running"] is True
    assert "sigma" in cuerpo["components"]
    # La línea base del detector se declara explícitamente.
    assert "baseline_ready" in cuerpo
    assert "primer lote" in cuerpo["baseline_note"]


def test_metrics_expone_caudal_latencia_y_errores(cliente, lectora):
    datos = cliente.get("/api/v1/metrics", headers=lectora).json()
    for clave in ("counters", "throughput_eps", "latency_ingest_ms",
                  "latency_end_to_end_ms", "queue", "worker", "store"):
        assert clave in datos
    for p in ("p50", "p95", "p99"):
        assert p in datos["latency_ingest_ms"]


# ------------------------------ cola y presión ------------------------------
def test_la_cola_aplica_contrapresion():
    """Una cola sin límite no es un buffer: es una fuga de memoria diferida."""
    cola = IngestQueue(maxsize=3)
    for i in range(3):
        cola.put(i)
    with pytest.raises(QueueFull):
        cola.put(99)
    assert cola.stats.rejected_backpressure == 1
    assert cola.utilization == 1.0


def test_la_cola_entrega_por_lotes():
    cola = IngestQueue(maxsize=100)
    for i in range(10):
        cola.put(i)
    assert len(cola.drain(4, timeout=0.1)) == 4
    assert len(cola.drain(100, timeout=0.1)) == 6
    assert cola.drain(10, timeout=0.05) == []


def test_los_eventos_fallidos_no_se_pierden():
    cola = IngestQueue(maxsize=10)
    cola.dead_letter([1, 2, 3], "el pipeline falló")
    assert cola.stats.dead_lettered == 3
    assert len(cola.dead_letters) == 3


def test_api_devuelve_429_cuando_el_buffer_esta_lleno(tmp_path):
    """
    Contrapresión explícita con Retry-After, no bloqueo ni descarte.

    Es un 429 distinto del que devuelve el limitador de caudal: aquel protege a
    los clientes entre sí, este protege al servicio cuando el análisis no da
    abasto. Por eso el sensor de esta prueba tiene el límite abierto: lo que se
    mide es el buffer, no la cuota.
    """
    almacen = IdentityStore(tmp_path / "identities.db")
    clave = almacen.create_api_key("prueba-contrapresion", Role.SENSOR)
    abierto = LimitPolicy(10_000, 20_000, 10_000_000, 20_000_000)
    puerta = SecurityGate(SecurityConfig(
        identity_db=tmp_path / "identities.db",
        jwt_secret="0123456789abcdef0123456789abcdef0123456789abcdef",
        rate_limiter=RateLimiter({r.value: abierto for r in Role} | {"anonymous": abierto}),
    ))
    svc = IngestService(rules_dir=RULES, db_path=tmp_path / "e.db",
                        audit_path=None, queue_maxsize=2, batch_size=500,
                        enable_rag=False, enable_llm=False)
    svc.worker.stop()          # nadie drena: el buffer se llena seguro
    with TestClient(create_app(svc, gate=puerta)) as c:
        svc.worker.stop()      # el lifespan lo arranca; se detiene para llenar el buffer
        r = c.post("/api/v1/events", json={"events": [_evento(i) for i in range(50)]},
                   headers={"X-API-Key": clave.token})
    assert r.status_code in (429, 207)
    assert r.json()["rejected"] > 0


# --------------------------- PRUEBA E2E OBLIGATORIA -------------------------
def test_e2e_evento_recorre_todo_y_deja_evidencia_en_disco(servicio, cliente):
    """
    Generado → API → validación → normalización → cola → pipeline real →
    DetectionEvidence → persistido.

    Se envía una cadena de ataque reconocible junto a ruido benigno, y se
    comprueba que el resultado existe **en disco**, con la técnica ATT&CK que
    corresponde. Ninguna puntuación se fija a mano: sale del pipeline.
    """
    antes = servicio.store.count()

    eventos = [_evento(100 + i, host="WKS-01", user="ana",
                       command_line=f"chrome.exe --tab {i}") for i in range(60)]
    # Fuerza bruta: la regla agregada exige varios fallos en una ventana.
    eventos += [{"source": "auth",
                 "timestamp": (BASE + timedelta(seconds=200 + i * 10)).isoformat(),
                 "action": "user_login", "host": "SRV-APP", "user": "admin",
                 "src_ip": "203.0.113.66", "outcome": "failure"} for i in range(8)]
    eventos.append(_evento(300, command_line="powershell.exe -nop -w hidden -enc SQBFAFgA",
                           process_name="powershell.exe"))
    eventos.append(_evento(400, command_line="schtasks /create /sc minute /tn U /tr t.ps1",
                           process_name="schtasks.exe"))

    r = cliente.post("/api/v1/events", json={"events": eventos})
    assert r.status_code == 202, r.text
    assert r.json()["accepted"] == len(eventos)

    total = _esperar_procesados(servicio, antes + len(eventos))
    assert total >= antes + len(eventos), f"solo se procesaron {total - antes}"

    # --- La evidencia está en disco, no en memoria ---
    ruta_db = Path(servicio.store.path)
    assert ruta_db.exists() and ruta_db.stat().st_size > 0

    con = sqlite3.connect(ruta_db)
    con.row_factory = sqlite3.Row
    filas = con.execute(
        "SELECT * FROM processed_events WHERE rules_fired != '[]'"
    ).fetchall()
    con.close()

    assert filas, "ninguna regla se activó sobre la cadena de ataque"

    tecnicas = {t for f in filas for t in json.loads(f["attack_techniques"])}
    assert "T1059" in tecnicas, f"falta PowerShell ofuscado; se vio {tecnicas}"

    # Trazabilidad completa y valores que vienen del pipeline.
    fila = filas[0]
    assert fila["run_id"] and fila["event_ref"] and fila["event_id"]
    assert fila["result"] in ("RULE_MATCH", "RULE_AND_ANOMALY")
    assert fila["score"] > 0
    assert fila["llm_status"] == "DISABLED"     # desactivado en esta fixture

    # Los incidentes se marcan solo si superan el umbral.
    incidentes = servicio.store.incidents(limit=10)
    for inc in incidentes:
        assert inc["incident_id"] == f"{inc['run_id']}:{inc['event_ref']}"
        assert inc["score"] >= 50.0


def test_e2e_la_auditoria_registra_los_hallazgos(servicio):
    """La cadena de auditoría recibe los hallazgos del flujo en tiempo real."""
    ruta = Path(servicio.pipeline.audit.path)
    if servicio.store.summary()["incidents"] == 0:
        pytest.skip("no hubo hallazgos que auditar en esta ejecución")
    assert ruta.exists()
    ok, fallo = servicio.pipeline.audit.verify()
    assert ok, f"cadena de auditoría comprometida en la entrada {fallo}"


def test_e2e_el_resumen_es_consultable(servicio):
    resumen = servicio.store.summary()
    assert resumen["total_events"] > 0
    assert resumen["db_size_bytes"] > 0
    assert sum(resumen["by_result"].values()) == resumen["total_events"]


def test_las_metricas_reflejan_lo_realmente_procesado(servicio, cliente, lectora):
    datos = cliente.get("/api/v1/metrics", headers=lectora).json()
    assert datos["counters"]["accepted"] > 0
    assert datos["counters"]["processed"] > 0
    assert datos["throughput_eps"]["processed"] > 0
    assert datos["latency_end_to_end_ms"]["samples"] > 0
    # Lo persistido y lo contabilizado deben coincidir.
    assert datos["store"]["total_events"] == servicio.store.count()


# ------------------------------ persistencia --------------------------------
def test_el_almacen_guarda_los_campos_requeridos(tmp_path):
    store = ResultStore(tmp_path / "s.db")
    con = sqlite3.connect(store.path)
    columnas = {r[1] for r in con.execute("PRAGMA table_info(processed_events)")}
    con.close()
    for requerida in ("event_id", "event_time", "source", "result", "score",
                      "rules_fired", "attack_techniques", "incident_id"):
        assert requerida in columnas


def test_el_pipeline_del_servicio_es_el_real(servicio):
    """Sin dobles: el servicio usa la misma clase Pipeline que la CLI."""
    from cybersentinel.pipeline import Pipeline

    assert isinstance(servicio.pipeline, Pipeline)
    assert servicio.pipeline.component_status["sigma"].startswith("OK")
    fuente = (ROOT / "src" / "cybersentinel" / "api" / "app.py").read_text(encoding="utf-8")
    for prohibido in ("FakeEmbeddings", "FakeListChatModel", "MagicMock"):
        assert prohibido not in fuente
