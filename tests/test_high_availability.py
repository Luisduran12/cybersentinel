"""
Alta disponibilidad: qué sobrevive a un fallo y qué no.

La pregunta que responden estas pruebas es la que motivó el trabajo: **si el
proceso muere ahora mismo, ¿qué se pierde?** Antes, todo lo que estuviera en la
cola en memoria: el emisor tenía un 202 en su registro y el sistema no tenía el
evento. Eso es peor que perderlo a secas, porque nadie sabe que falta.

Se prueban cuatro cosas distintas y conviene no confundirlas:

1. Que un 202 signifique que el evento está en disco (registro anticipado).
2. Que al arrancar se recupere lo aceptado y no procesado.
3. Que el apagado ordenado deje de atraer tráfico antes de vaciarse.
4. Que el estado que **tiene** que ser compartido —la cadena de auditoría y la
   revocación de tokens— lo sea de verdad entre procesos, no solo dentro de uno.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cybersentinel.api.app import IngestService, create_app  # noqa: E402
from cybersentinel.api.queue import IngestQueue  # noqa: E402
from cybersentinel.api.security import (  # noqa: E402
    IdentityStore, LimitPolicy, RateLimiter, Role, SecurityConfig,
    SecurityGate,
)
from cybersentinel.api.wal import WalLocked, WriteAheadLog  # noqa: E402
from cybersentinel.governance import AuditLog  # noqa: E402

RULES = ROOT / "config" / "rules"
BASE = datetime(2025, 5, 1, 8, tzinfo=timezone.utc)
SECRETO = "0123456789abcdef0123456789abcdef0123456789abcdef"
CLAVE = "contraseña-de-prueba-larga"


def _evento(n: int = 0) -> dict:
    return {"source": "sysmon", "timestamp": (BASE + timedelta(seconds=n)).isoformat(),
            "action": "process_create", "host": "SRV-APP", "user": "admin",
            "command_line": f"chrome.exe --tab {n}", "process_name": "chrome.exe",
            "outcome": "success"}


def _morir(objeto) -> None:
    """
    Simula la muerte del proceso: suelta el candado del registro y nada más.

    El sistema operativo libera `flock` cuando el proceso desaparece, así que un
    `kill -9` deja el directorio disponible para el siguiente arranque con el
    registro exactamente como estaba: sin cerrar, sin punto de control nuevo y
    con todo lo aceptado dentro. Eso es lo que se quiere reproducir aquí, no un
    apagado ordenado.
    """
    wal = getattr(objeto, "wal", objeto)
    wal._soltar_propiedad()


def _servicio(directorio: Path, **kwargs) -> IngestService:
    opciones = dict(
        rules_dir=RULES, db_path=directorio / "events.db",
        incidents_path=directorio / "incidents.db",
        feedback_store=directorio / "decisions.jsonl",
        wal_dir=directorio / "wal", audit_path=None,
        queue_maxsize=1000, batch_size=200, enable_rag=False, enable_llm=False,
    )
    opciones.update(kwargs)
    return IngestService(**opciones)


# ============================ registro anticipado ===========================
def test_lo_aceptado_queda_en_disco_antes_de_responder(tmp_path):
    """
    El contrato del 202: si respondemos «aceptado», está escrito.

    Se comprueba leyendo el archivo desde fuera, no preguntándole al objeto que
    acaba de escribirlo.
    """
    wal = WriteAheadLog(tmp_path / "wal", fsync_policy="always")
    seqs = wal.append([({"source": "sysmon", "a": 1}, "sysmon"),
                       ({"source": "auth", "b": 2}, "auth")])
    assert seqs == [1, 2]

    lineas = []
    for segmento in sorted((tmp_path / "wal").glob("wal-*.jsonl")):
        lineas += [json.loads(l) for l in segmento.read_text().splitlines() if l.strip()]
    assert [l["seq"] for l in lineas] == [1, 2]
    assert lineas[0]["record"]["a"] == 1


def test_el_punto_de_control_marca_hasta_donde_se_proceso(tmp_path):
    wal = WriteAheadLog(tmp_path / "wal")
    wal.append([({"n": i}, "sysmon") for i in range(5)])
    assert [e.seq for e in wal.replay()] == [1, 2, 3, 4, 5]

    wal.checkpoint(3)
    assert [e.seq for e in wal.replay()] == [4, 5]
    assert wal.pending() == 2


def test_la_secuencia_no_se_reinicia_tras_un_reinicio(tmp_path):
    """
    Reutilizar números de secuencia haría que el punto de control diera por
    procesados eventos nuevos.
    """
    primero = WriteAheadLog(tmp_path / "wal")
    primero.append([({"n": i}, "s") for i in range(3)])
    primero.release()

    segundo = WriteAheadLog(tmp_path / "wal")
    assert segundo.append([({"n": 99}, "s")]) == [4]


def test_una_linea_truncada_no_se_lleva_por_delante_al_resto(tmp_path):
    """
    Muerte a mitad de escritura. Perder un evento por una línea truncada es
    malo; perder los diez mil de detrás porque uno estaba roto es mucho peor.
    """
    wal = WriteAheadLog(tmp_path / "wal")
    wal.append([({"n": i}, "s") for i in range(4)])
    wal.release()

    segmento = sorted((tmp_path / "wal").glob("wal-*.jsonl"))[0]
    with open(segmento, "a", encoding="utf-8") as fh:
        fh.write('{"seq": 5, "record": {"n": 4}, "sour')  # cortado a la mitad

    recuperado = WriteAheadLog(tmp_path / "wal")
    assert [e.seq for e in recuperado.replay()] == [1, 2, 3, 4]


def test_un_punto_de_control_ilegible_reprocesa_en_vez_de_perder(tmp_path):
    """Ante la duda, reprocesar. Ver dos veces un evento es un problema menor."""
    wal = WriteAheadLog(tmp_path / "wal")
    wal.append([({"n": i}, "s") for i in range(3)])
    wal.checkpoint(2)
    (tmp_path / "wal" / "checkpoint.json").write_text("{roto", encoding="utf-8")
    wal.release()

    recuperado = WriteAheadLog(tmp_path / "wal")
    assert [e.seq for e in recuperado.replay()] == [1, 2, 3]


def test_los_segmentos_procesados_se_borran(tmp_path):
    """Sin compactación, el registro crece para siempre."""
    wal = WriteAheadLog(tmp_path / "wal", segment_max_records=10)
    wal.append([({"n": i}, "s") for i in range(35)])
    assert len(list((tmp_path / "wal").glob("wal-*.jsonl"))) >= 4

    wal.checkpoint(30)
    quedan = list((tmp_path / "wal").glob("wal-*.jsonl"))
    assert len(quedan) <= 2, "los segmentos por debajo del punto de control sobran"
    assert [e.seq for e in wal.replay()] == [31, 32, 33, 34, 35]


def test_dos_procesos_no_comparten_el_mismo_registro(tmp_path):
    """
    Compartirlo no perdería eventos: haría algo peor. Dos escritores calcularían
    la misma secuencia siguiente, escribirían eventos distintos con el mismo
    número y al recuperar reproducirían las mismas entradas los dos. El segundo
    no arranca, y dice por qué.
    """
    duenno = WriteAheadLog(tmp_path / "wal")
    with pytest.raises(WalLocked, match="un solo escritor"):
        WriteAheadLog(tmp_path / "wal")

    # Al morir el dueño, el siguiente puede tomarlo sin intervención manual.
    _morir(duenno)
    assert WriteAheadLog(tmp_path / "wal") is not None


def test_politica_de_fsync_desconocida_se_rechaza(tmp_path):
    with pytest.raises(ValueError, match="fsync"):
        WriteAheadLog(tmp_path / "wal", fsync_policy="a_veces")


def test_la_durabilidad_se_declara(tmp_path):
    """Que nadie elija la política por lo que suena el nombre."""
    for politica, esperado in [("always", "corte de corriente"),
                               ("interval", "ventana"),
                               ("never", "no a la del equipo")]:
        wal = WriteAheadLog(tmp_path / f"wal-{politica}", fsync_policy=politica)
        assert esperado in wal.stats()["durability_note"]


# =============================== recuperación ===============================
def test_un_kill_no_pierde_lo_aceptado(tmp_path):
    """
    **La prueba que justifica todo este módulo.**

    Se acepta un lote, el proceso muere sin apagado ordenado —no se llama a
    `stop()`, no se drena, no se cierra nada— y el siguiente arranque tiene que
    encontrar exactamente lo mismo.
    """
    muerto = _servicio(tmp_path)
    respuesta = muerto.ingest([type("E", (), {})()] * 0 or _crudos(12))
    assert respuesta.accepted == 12
    assert muerto.store.count() == 0, "nada se ha procesado todavía"
    # Aquí muere el proceso: ni stop(), ni drenado, ni cierre del registro.
    _morir(muerto)

    resucitado = _servicio(tmp_path)
    assert resucitado.wal.pending() == 12
    assert resucitado.recover() == 12
    assert resucitado.queue.size == 12

    resucitado.worker.start()
    limite = time.time() + 30
    while time.time() < limite and resucitado.store.count() < 12:
        time.sleep(0.1)
    resucitado.worker.stop()
    assert resucitado.store.count() == 12, "se perdieron eventos ya aceptados"


def test_lo_ya_procesado_no_se_reprocesa_al_arrancar(tmp_path):
    svc = _servicio(tmp_path)
    svc.ingest(_crudos(5))
    svc.worker.start()
    limite = time.time() + 30
    while time.time() < limite and svc.store.count() < 5:
        time.sleep(0.1)
    svc.stop()
    assert svc.store.count() == 5

    siguiente = _servicio(tmp_path)
    assert siguiente.wal.pending() == 0
    assert siguiente.recover() == 0


def test_la_recuperacion_normaliza_por_el_mismo_camino(tmp_path):
    """
    Se guarda el registro crudo, no el evento ya normalizado: así la
    recuperación no puede divergir de la ingestión cuando un parser cambie.
    """
    svc = _servicio(tmp_path)
    svc.ingest(_crudos(1))
    _morir(svc)
    otro = _servicio(tmp_path)
    otro.recover()
    encolado = otro.queue.drain(1, timeout=1)[0]
    assert encolado.event.host == "SRV-APP"
    assert encolado.event.process_name == "chrome.exe"
    assert encolado.seq == 1


def test_si_no_se_puede_registrar_no_se_acepta(tmp_path, monkeypatch):
    """
    Un 503 honesto es mejor que un 202 que miente. Si el disco falla, el emisor
    tiene que enterarse y reintentar, no quedarse con un acuse falso.
    """
    svc = _servicio(tmp_path)

    def _falla(*_a, **_k):
        raise OSError("disco lleno")

    monkeypatch.setattr(svc.wal, "append", _falla)
    respuesta = svc.ingest(_crudos(3))
    assert respuesta.accepted == 0
    assert respuesta.rejected == 3
    assert "registro" in respuesta.errors[0]["error"]
    # Y el hueco reservado se devuelve: no se queda ocupado para siempre.
    assert svc.queue.reserved == 0


def test_la_contrapresion_se_decide_antes_de_escribir(tmp_path):
    """
    Sin reserva solo quedan dos malas opciones: escribir y descubrir que no
    cabe, o comprobar el hueco y perderlo en la milésima siguiente.
    """
    svc = _servicio(tmp_path, queue_maxsize=5)
    primero = svc.ingest(_crudos(5))
    assert primero.accepted == 5

    segundo = svc.ingest(_crudos(3))
    assert segundo.accepted == 0
    assert any(e["error"] == "buffer lleno" for e in segundo.errors)
    # Lo rechazado no llegó a escribirse: la secuencia no avanzó.
    assert svc.wal.stats()["last_seq"] == 5


def test_la_reserva_cuenta_como_ocupacion():
    cola = IngestQueue(maxsize=4)
    assert cola.reserve(3) is True
    assert cola.reserved == 3
    assert cola.utilization == 0.75
    assert cola.reserve(2) is False, "no debe prometer sitio que no tiene"
    cola.release(3)
    assert cola.reserved == 0


def test_los_fallidos_se_escriben_en_disco(tmp_path):
    """
    La cola de fallidos vivía solo en memoria: contabilizaba la pérdida pero no
    la conservaba, y un reinicio borraba la evidencia de que había ocurrido.
    """
    svc = _servicio(tmp_path)
    svc.ingest(_crudos(2))

    def _revienta(*_a, **_k):
        raise RuntimeError("el pipeline se rompió")

    svc.worker.pipeline.run_events = _revienta
    svc.worker.max_retries = 0
    lote = svc.queue.drain(10, timeout=1)
    svc.worker._procesar(lote)

    fallidos = tmp_path / "wal" / "dead-letters.jsonl"
    assert fallidos.exists()
    registros = [json.loads(l) for l in fallidos.read_text().splitlines() if l.strip()]
    assert len(registros) == 2
    assert "se rompió" in registros[0]["reason"]
    # Y el punto de control avanza: si no, este lote se reprocesaría y volvería
    # a fallar en cada arranque, y el registro crecería para siempre.
    assert svc.wal.pending() == 0


# ============================ apagado ordenado ==============================
@pytest.fixture(scope="module")
def desplegado(tmp_path_factory):
    directorio = tmp_path_factory.mktemp("ha")
    almacen = IdentityStore(directorio / "identities.db")
    sensor = almacen.create_api_key("sensor-ha", Role.COLLECTOR)
    almacen.create_user("admina", CLAVE, Role.ADMIN)
    abierto = LimitPolicy(10_000, 20_000, 10_000_000, 20_000_000)
    puerta = SecurityGate(SecurityConfig(
        identity_db=directorio / "identities.db", jwt_secret=SECRETO,
        rate_limiter=RateLimiter({r.value: abierto for r in Role} | {"anonymous": abierto}),
    ))
    svc = _servicio(directorio)
    with TestClient(create_app(svc, gate=puerta),
                    base_url="https://testserver") as cliente:
        yield {"cliente": cliente, "svc": svc, "sensor": sensor, "puerta": puerta,
               "dir": directorio, "almacen": almacen}


def _admin(cliente) -> dict[str, str]:
    r = cliente.post("/api/v1/auth/token", json={"username": "admina", "password": CLAVE})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_drenar_saca_el_proceso_de_rotacion(desplegado):
    """
    La mitad que falta de un apagado ordenado. Con SIGTERM a secas, el proceso
    deja de escuchar de golpe y el balanceador le sigue mandando tráfico
    durante los segundos que tarda en enterarse.
    """
    cliente = desplegado["cliente"]
    assert cliente.get("/api/v1/ready").json()["ready"] is True

    r = cliente.post("/api/v1/drain", headers=_admin(cliente))
    assert r.status_code == 200 and r.json()["draining"] is True

    despues = cliente.get("/api/v1/ready")
    assert despues.status_code == 503
    cuerpo = despues.json()
    assert cuerpo["ready"] is False
    # La distinción importa: «me estoy apagando» no es «me he roto», y
    # confundirlas hace que el orquestador reinicie un proceso que terminaba bien.
    assert cuerpo["draining"] is True

    desplegado["svc"].draining = False  # no contaminar las pruebas siguientes


def test_solo_un_administrador_puede_drenar(desplegado):
    cliente = desplegado["cliente"]
    r = cliente.post("/api/v1/drain", headers={"X-API-Key": desplegado["sensor"].token})
    assert r.status_code == 403


def test_las_metricas_publican_el_estado_del_registro(desplegado):
    datos = desplegado["cliente"].get("/api/v1/metrics",
                                      headers=_admin(desplegado["cliente"])).json()
    for clave in ("last_seq", "checkpoint_seq", "pending", "fsync_policy",
                  "durability_note"):
        assert clave in datos["wal"]


# ======================= estado compartido entre procesos ===================
def test_la_auditoria_aguanta_dos_procesos(tmp_path):
    """
    El candado de hilo resuelve varias instancias dentro de un proceso. No
    resuelve dos trabajadores de uvicorn, ni la CLI escribiendo mientras corre
    el servicio, y ahí el fallo es el mismo: dos cadenas entrelazadas.
    """
    ruta = tmp_path / "multiproceso.jsonl"
    guion = (
        "import sys; sys.path.insert(0, %r)\n"
        "from cybersentinel.governance import AuditLog\n"
        "log = AuditLog(%r, secret_key='k')\n"
        "for i in range(25):\n"
        "    log.record(f'proceso-{sys.argv[1]}', 'evento', {'i': i})\n"
    ) % (str(ROOT / "src"), str(ruta))

    entorno = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    procesos = [subprocess.Popen([sys.executable, "-c", guion, str(n)], env=entorno)
                for n in range(3)]
    for p in procesos:
        assert p.wait(timeout=120) == 0

    final = AuditLog(ruta, secret_key="k")
    assert len(final.entries) == 75
    ok, indice, detalle = final.verify_detailed()
    assert ok, f"cadena rota en {indice}: {detalle}"
    assert [e.index for e in final.entries] == list(range(75))


def test_la_revocacion_de_un_token_vale_en_todas_las_replicas(tmp_path):
    """
    Una revocación que depende de a qué réplica caiga la petición no es una
    revocación: el balanceador encaminará la siguiente a la otra.
    """
    almacen = IdentityStore(tmp_path / "identities.db")
    almacen.create_user("ana", CLAVE, Role.ANALYST)

    config = dict(identity_db=tmp_path / "identities.db", jwt_secret=SECRETO)
    replica_a = SecurityGate(SecurityConfig(**config))
    replica_b = SecurityGate(SecurityConfig(**config))

    token, claims = replica_a.signer.issue("ana", "analyst")
    assert replica_b.signer.verify(token)["sub"] == "ana"

    replica_a.revoke_token(claims["jti"], expires_at=claims["exp"], subject="ana")
    assert replica_b.store.is_token_revoked(claims["jti"]) is True

    # Y sobrevive al reinicio: una réplica nueva también lo rechaza.
    replica_c = SecurityGate(SecurityConfig(**config))
    assert replica_c.store.is_token_revoked(claims["jti"]) is True


def test_las_revocaciones_caducadas_se_limpian(tmp_path):
    """Sin limpieza, la tabla crece sin límite y la consulta por token se degrada."""
    almacen = IdentityStore(tmp_path / "identities.db")
    almacen.revoke_token("viejo", expires_at=1_000_000, subject="ana")
    almacen.revoke_token("vigente", expires_at=int(time.time()) + 3600, subject="ana")

    assert almacen.purge_revoked_tokens() == 1
    assert almacen.is_token_revoked("viejo") is False
    assert almacen.is_token_revoked("vigente") is True


def test_logout_en_una_replica_cierra_la_sesion_en_la_otra(tmp_path):
    """La misma propiedad, pero a través de la API."""
    almacen = IdentityStore(tmp_path / "identities.db")
    almacen.create_user("ana", CLAVE, Role.ANALYST)
    abierto = LimitPolicy(10_000, 20_000, 10_000_000, 20_000_000)
    config = dict(identity_db=tmp_path / "identities.db", jwt_secret=SECRETO,
                  rate_limiter=RateLimiter({r.value: abierto for r in Role}
                                           | {"anonymous": abierto}))

    svc_a, svc_b = _servicio(tmp_path / "a"), _servicio(tmp_path / "b")
    app_a = create_app(svc_a, gate=SecurityGate(SecurityConfig(**config)))
    app_b = create_app(svc_b, gate=SecurityGate(SecurityConfig(**config)))

    with TestClient(app_a, base_url="https://testserver") as a, \
         TestClient(app_b, base_url="https://testserver") as b:
        token = a.post("/api/v1/auth/token",
                       json={"username": "ana", "password": CLAVE}).json()["access_token"]
        cab = {"Authorization": f"Bearer {token}"}
        assert b.get("/api/v1/auth/whoami", headers=cab).status_code == 200

        assert a.post("/api/v1/auth/logout", headers=cab).json()["revoked"] is True
        r = b.get("/api/v1/auth/whoami", headers=cab)
        assert r.status_code == 401 and "revocado" in r.text


# --------------------------------- utilidades -------------------------------
def _crudos(n: int):
    from cybersentinel.api.models import RawEvent

    return [RawEvent(**_evento(i)) for i in range(n)]


def test_dos_replicas_comparten_la_vista_de_incidentes(tmp_path):
    """
    Sin esto, tener réplicas no sirve de nada para investigar: el panel de una
    no vería lo que detectó la otra, y el analista tendría media verdad según a
    qué máquina le tocara entrar.

    Cada réplica tiene su **propio** registro anticipado —admite un solo
    escritor— pero comparten la base de eventos e incidentes. SQLite en modo WAL
    permite que varios procesos escriban mientras otros leen.
    """
    compartido = tmp_path / "compartido"
    compartido.mkdir()
    a = _servicio(tmp_path / "a", db_path=compartido / "events.db",
                  incidents_path=compartido / "incidents.db")
    b = _servicio(tmp_path / "b", db_path=compartido / "events.db",
                  incidents_path=compartido / "incidents.db")

    a.ingest(_crudos(4))
    b.ingest(_crudos(4))
    a.worker.start()
    b.worker.start()
    limite = time.time() + 40
    while time.time() < limite and a.store.count() < 8:
        time.sleep(0.1)
    a.stop()
    b.stop()

    assert a.store.count() == 8, "las dos réplicas escriben en la misma base"
    # Y cualquiera de las dos ve el total, no solo lo suyo.
    assert b.store.count() == a.store.count()


def test_el_modo_wal_esta_activo(tmp_path):
    """Sin WAL, dos réplicas sobre el mismo archivo se bloquean entre sí."""
    import sqlite3

    svc = _servicio(tmp_path)
    for ruta in (svc.store.path, svc.incidents.path):
        modo = sqlite3.connect(ruta).execute("PRAGMA journal_mode").fetchone()[0]
        assert modo.lower() == "wal", f"{ruta} no está en modo WAL: {modo}"


def test_supervisor_restarts_dead_worker(tmp_path):
    """
    Si el hilo del worker muere por un error no capturado,
    el supervisor lo detecta y lo vuelve a arrancar.
    """
    svc = _servicio(tmp_path)
    svc.start()
    
    assert svc.worker.is_running is True
    
    # Matamos el hilo artificialmente (simulando un crash) sin activar draining
    svc.worker._parar.set()
    svc.worker._hilo.join()
    assert svc.worker.is_running is False
    assert svc.draining is False
    
    # El supervisor debería detectarlo y rearrancarlo
    # time.sleep en supervisor es de 5s, esperamos hasta 10s
    limite = time.time() + 10
    while time.time() < limite and not svc.worker.is_running:
        time.sleep(0.5)
        
    assert svc.worker.is_running is True, "El supervisor no reinició el worker"
    svc.stop()


def test_duplicate_event_idempotency(tmp_path, monkeypatch):
    """
    Si el mismo evento llega dos veces, no se crean dos incidentes.
    La idempotencia se garantiza usando el event_id.
    """
    svc = _servicio(tmp_path)
    
    # Modificamos la puntuación híbrida para forzar que supere el umbral
    def _run_events(eventos):
        from cybersentinel.pipeline import PipelineReport, IncidentResult
        from cybersentinel.detection.hybrid import DetectionEvidence
        from cybersentinel.observability import TraceContext
        
        class MockEvidence(DetectionEvidence):
            @property
            def hybrid_score(self) -> float:
                return 95.0
            @property
            def detection_status(self) -> str:
                return "RULE_AND_ANOMALY"

        res = []
        for e in eventos:
            evidence = MockEvidence(
                run_id="run-1", event_ref="ref-1", event_id="evt-1",
                entity="h1", llm_status="none", fallback_used=False
            )
            res.append(IncidentResult(evidence=evidence, narrative="", trace=TraceContext(event_id="evt-1"), recommendations=[]))
        return PipelineReport(total_events=1, total_findings=1, run_id="run-1", results=res)
        
    monkeypatch.setattr(svc.pipeline, "run_events", _run_events)
    
    eventos = _crudos(1)
    svc.ingest(eventos)
    lote1 = svc.queue.drain(1)
    # Primera pasada
    svc.worker._procesar(lote1)
    
    # Segunda pasada (mismo lote, simula duplicado procesado)
    svc.worker._procesar(lote1)
    
    # Revisamos incidentes
    import sqlite3
    con = sqlite3.connect(svc.incidents.path)
    cuenta = con.execute("SELECT COUNT(*) FROM incidents WHERE incident_id = 'evt-1'").fetchone()[0]
    assert cuenta == 1, "La idempotencia falló: se duplicó el incidente"
    con.close()
