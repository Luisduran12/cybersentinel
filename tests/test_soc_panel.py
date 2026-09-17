"""
Pruebas del panel SOC: entidad incidente, ciclo de vida y lo que el panel sirve.

La pregunta que responden no es «¿se pinta la página?», sino **«¿puede un
analista investigar con esto?»**: que la evidencia que justifica la alerta esté
persistida y no solo en memoria, que el ciclo de vida no acepte cualquier
cambio, que la cronología no se pueda reescribir, y que el rol que solo lee no
pueda escribir por mucho que el navegador le enseñe un botón.

Los incidentes salen del pipeline real. Ninguno se fabrica a mano: si el motor
dejara de detectar la cadena, estas pruebas fallarían, que es justo lo que se
quiere.
"""
from __future__ import annotations

import json
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cybersentinel.api.app import IngestService, create_app  # noqa: E402
from cybersentinel.api.incidents import (  # noqa: E402
    IncidentError, IncidentStore, Filtro, severidad_de,
)
from cybersentinel.api.security import (  # noqa: E402
    IdentityStore, LimitPolicy, RateLimiter, Role, SecurityConfig, SecurityGate,
)

RULES = ROOT / "config" / "rules"
PANEL = ROOT / "src" / "cybersentinel" / "api" / "panel"
BASE = datetime(2025, 4, 2, 9, tzinfo=timezone.utc)
CLAVE = "contraseña-de-prueba-larga"
SECRETO = "0123456789abcdef0123456789abcdef0123456789abcdef"


def _sysmon(segundos: int, **kwargs) -> dict:
    datos = {"source": "sysmon", "timestamp": (BASE + timedelta(seconds=segundos)).isoformat(),
             "action": "process_create", "host": "SRV-APP", "user": "admin",
             "command_line": "chrome.exe --tab 1", "process_name": "chrome.exe",
             "outcome": "success"}
    datos.update(kwargs)
    return datos


@pytest.fixture(scope="module")
def soc(tmp_path_factory):
    """Servicio real + panel + credenciales, con al menos un incidente dentro."""
    directorio = tmp_path_factory.mktemp("soc")

    almacen = IdentityStore(directorio / "identities.db")
    sensor = almacen.create_api_key("sensor-soc", Role.COLLECTOR)
    almacen.create_user("ana", CLAVE, Role.VIEWER)        # solo lee
    almacen.create_user("rosa", CLAVE, Role.ANALYST)      # lee y escribe
    almacen.create_user("aitor", CLAVE, Role.VIEWER)      # lee, incluida auditoría

    abierto = LimitPolicy(10_000, 20_000, 10_000_000, 20_000_000)
    puerta = SecurityGate(SecurityConfig(
        identity_db=directorio / "identities.db", jwt_secret=SECRETO,
        rate_limiter=RateLimiter({r.value: abierto for r in Role} | {"anonymous": abierto}),
    ))
    svc = IngestService(
        rules_dir=RULES, db_path=directorio / "events.db",
        incidents_path=directorio / "incidents.db",
        feedback_store=directorio / "decisions.jsonl", wal_dir=directorio / "wal",
        audit_path=directorio / "audit.jsonl", queue_maxsize=2000, batch_size=200,
        enable_rag=False, enable_llm=False,
    )

    with TestClient(create_app(svc, gate=puerta),
                    base_url="https://testserver") as cliente:
        eventos = [_sysmon(i) for i in range(20)]
        eventos.append(_sysmon(300, process_name="powershell.exe",
                               command_line="powershell.exe -nop -w hidden -enc SQBFAFgA"))
        eventos.append(_sysmon(400, process_name="schtasks.exe",
                               command_line="schtasks /create /sc minute /tn U /tr t.ps1"))
        r = cliente.post("/api/v1/events", json={"events": eventos},
                         headers={"X-API-Key": sensor.token})
        assert r.status_code == 202, r.text

        limite = time.time() + 30
        while time.time() < limite and svc.incidents.stats()["total"] == 0:
            time.sleep(0.1)

        yield {"cliente": cliente, "svc": svc, "dir": directorio, "sensor": sensor}


def _cab(cliente, usuario: str) -> dict[str, str]:
    r = cliente.post("/api/v1/auth/token", json={"username": usuario, "password": CLAVE})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _primer_incidente(soc, usuario="rosa") -> dict:
    r = soc["cliente"].get("/api/v1/incidents", headers=_cab(soc["cliente"], usuario))
    assert r.status_code == 200, r.text
    lista = r.json()["incidents"]
    assert lista, "el pipeline no produjo ningún incidente"
    return lista[0]


# ------------------------- el incidente existe y es útil --------------------
def test_el_pipeline_crea_incidentes_persistentes(soc):
    """
    Antes de esto el resultado era efímero. La comprobación es que sobrevive
    **en disco**, no en la memoria del proceso.
    """
    assert soc["svc"].incidents.stats()["total"] > 0
    ruta = Path(soc["dir"] / "incidents.db")
    assert ruta.exists() and ruta.stat().st_size > 0

    otro = IncidentStore(ruta)  # un proceso distinto leyendo el mismo archivo
    assert otro.list(Filtro())["total"] > 0


def test_el_detalle_trae_lo_que_justifica_la_alerta(soc):
    """
    Un panel que enseña «puntuación 73» y nada más no permite investigar: el
    analista necesita la regla, el evento crudo y la explicación.
    """
    inc = _primer_incidente(soc)
    r = soc["cliente"].get(f"/api/v1/incidents/{inc['incident_id']}",
                           headers=_cab(soc["cliente"], "ana"))
    assert r.status_code == 200
    d = r.json()

    assert d["rules"], "sin la regla que disparó, no hay nada que investigar"
    assert d["rules"][0]["rule_id"]
    assert d["raw_event"].get("command_line"), "falta el evento normalizado"
    assert d["narrative"], "falta la explicación"
    assert d["llm_status"], "no se declara de dónde salió la narrativa"
    assert d["detection_status"] in {"RULE_MATCH", "RULE_AND_ANOMALY", "ANOMALY_ONLY"}
    assert any(t["kind"] == "created" for t in d["timeline"])


def test_el_incidente_nace_sin_asignar_y_en_nuevo(soc):
    inc = _primer_incidente(soc)
    assert inc["state"] == "new"
    assert inc["owner"] is None


def test_incidente_inexistente_da_404(soc):
    r = soc["cliente"].get("/api/v1/incidents/no-existe",
                           headers=_cab(soc["cliente"], "ana"))
    assert r.status_code == 404


def test_stats_no_se_confunde_con_un_identificador(soc):
    """
    `/incidents/stats` va declarada antes que `/incidents/{id}`. Sin ese orden,
    «stats» se interpreta como el identificador de un incidente y devuelve 404.
    """
    r = soc["cliente"].get("/api/v1/incidents/stats", headers=_cab(soc["cliente"], "ana"))
    assert r.status_code == 200
    datos = r.json()
    for clave in ("total", "open", "unassigned", "critical_open", "by_state",
                  "by_severity", "top_techniques", "threshold"):
        assert clave in datos


# ------------------------------- RBAC del panel -----------------------------
def test_el_analista_lee_pero_no_escribe(soc):
    """El botón se oculta por comodidad; la autorización está en la API."""
    cliente, inc = soc["cliente"], _primer_incidente(soc)
    ana = _cab(cliente, "ana")

    assert cliente.get("/api/v1/incidents", headers=ana).json()["can_write"] is False
    assert cliente.patch(f"/api/v1/incidents/{inc['incident_id']}",
                         json={"state": "triaged"}, headers=ana).status_code == 403
    assert cliente.post(f"/api/v1/incidents/{inc['incident_id']}/notes",
                        json={"text": "no debería poder"}, headers=ana).status_code == 403
    assert cliente.post(f"/api/v1/incidents/{inc['incident_id']}/triage",
                        json={"action": "CONFIRM", "reason": "no debería poder"},
                        headers=ana).status_code == 403


def test_el_sensor_no_ve_el_panel(soc):
    """La credencial de un colector no abre la consola de investigación."""
    r = soc["cliente"].get("/api/v1/incidents",
                           headers={"X-API-Key": soc["sensor"].token})
    assert r.status_code == 403


def test_el_auditor_lee_y_no_escribe(soc):
    cliente, inc = soc["cliente"], _primer_incidente(soc)
    aitor = _cab(cliente, "aitor")
    assert cliente.get(f"/api/v1/incidents/{inc['incident_id']}",
                       headers=aitor).status_code == 200
    assert cliente.patch(f"/api/v1/incidents/{inc['incident_id']}",
                         json={"owner": "aitor"}, headers=aitor).status_code == 403


# ------------------------------ ciclo de vida -------------------------------
def test_ciclo_de_vida_completo(soc):
    cliente, inc = soc["cliente"], _primer_incidente(soc)
    rosa = _cab(cliente, "rosa")
    ruta = f"/api/v1/incidents/{inc['incident_id']}"

    d = cliente.patch(ruta, json={"owner": "rosa", "state": "triaged"}, headers=rosa).json()
    assert d["owner"] == "rosa" and d["state"] == "triaged"

    d = cliente.patch(ruta, json={"state": "confirmed"}, headers=rosa).json()
    assert d["state"] == "confirmed"

    d = cliente.patch(ruta, json={"state": "resolved", "resolution": "true_positive"},
                      headers=rosa).json()
    assert d["state"] == "resolved" and d["resolution"] == "true_positive"
    assert d["closed_at"]


def test_cerrar_sin_resolucion_se_rechaza(soc, tmp_path):
    """Un incidente cerrado sin motivo no enseña nada a quien venga después."""
    almacen = IncidentStore(tmp_path / "ciclo.db")
    _sembrar(almacen, "r1:e1")
    with pytest.raises(IncidentError, match="resolución"):
        almacen.update("r1:e1", "rosa", state="resolved")


def test_transicion_invalida_se_rechaza_con_422(soc, tmp_path):
    """
    Un ciclo de vida que acepta cualquier cambio no es un ciclo de vida.
    Reabrir vuelve a triaje, no a «en curso».
    """
    almacen = IncidentStore(tmp_path / "transiciones.db")
    _sembrar(almacen, "r1:e1")
    almacen.update("r1:e1", "rosa", state="resolved", resolution="benign")
    with pytest.raises(IncidentError, match="no se puede pasar"):
        almacen.update("r1:e1", "rosa", state="confirmed")

    reabierto = almacen.update("r1:e1", "rosa", state="triaged")
    assert reabierto["state"] == "triaged"
    # Reabrir limpia la resolución: dejarla haría creer que ya está concluido.
    assert reabierto["resolution"] is None
    assert reabierto["closed_at"] is None


def test_la_api_traduce_la_transicion_invalida_a_422(soc):
    cliente, inc = soc["cliente"], _primer_incidente(soc)
    rosa = _cab(cliente, "rosa")
    r = cliente.patch(f"/api/v1/incidents/{inc['incident_id']}",
                      json={"state": "inventado"}, headers=rosa)
    assert r.status_code == 422
    assert "estado desconocido" in r.text


def test_la_cronologia_solo_crece(soc, tmp_path):
    """Un panel que deja reescribir la historia no sirve como registro."""
    almacen = IncidentStore(tmp_path / "crono.db")
    _sembrar(almacen, "r1:e1")
    almacen.update("r1:e1", "rosa", owner="rosa")
    almacen.update("r1:e1", "rosa", state="triaged")
    almacen.add_note("r1:e1", "rosa", "he comprobado el hash del binario")
    almacen.update("r1:e1", "rosa", owner="luis")

    crono = almacen.timeline("r1:e1")
    clases = [e["kind"] for e in crono]
    assert clases == ["created", "owner", "state", "note", "owner"]
    # El propietario anterior sigue en la historia aunque ya no sea el actual.
    assert any(e["payload"].get("from") == "rosa" for e in crono if e["kind"] == "owner")


def test_el_ajuste_manual_de_severidad_queda_marcado(soc, tmp_path):
    """
    Sin esta marca nadie sabría después si el orden del panel refleja el modelo
    o el criterio de una persona.
    """
    almacen = IncidentStore(tmp_path / "sev.db")
    _sembrar(almacen, "r1:e1", score=72.0)
    assert almacen.get("r1:e1")["severity"] == "high"
    almacen.update("r1:e1", "rosa", severity="critical")
    entrada = [e for e in almacen.timeline("r1:e1") if e["kind"] == "severity"][0]
    assert "ajustada por una persona" in entrada["text"]
    assert entrada["payload"]["derived_from_score"] == "high"


def test_reprocesar_no_duplica_ni_pisa_el_trabajo(soc, tmp_path):
    """
    Reenviar el mismo lote no puede crear incidentes nuevos ni devolver a
    «nuevo» algo que un analista ya estaba investigando.
    """
    almacen = IncidentStore(tmp_path / "dup.db")
    resultados = [_resultado("r1", "e1", 80.0)]
    assert almacen.save_batch(resultados, umbral=50.0) == 1
    almacen.update("r1:e1", "rosa", owner="rosa", state="triaged")

    assert almacen.save_batch(resultados, umbral=50.0) == 0
    d = almacen.get("r1:e1")
    assert d["state"] == "triaged" and d["owner"] == "rosa"
    assert sum(1 for e in d["timeline"] if e["kind"] == "created") == 1


def test_lo_que_no_supera_el_umbral_no_es_incidente(soc, tmp_path):
    """Confundir evento analizado con incidente infla la cuenta del producto."""
    almacen = IncidentStore(tmp_path / "umbral.db")
    creados = almacen.save_batch(
        [_resultado("r1", "bajo", 12.0), _resultado("r1", "alto", 90.0)], umbral=50.0)
    assert creados == 1
    assert almacen.list(Filtro())["total"] == 1


def test_severidad_derivada_del_score():
    assert severidad_de(90) == "critical"
    assert severidad_de(72) == "high"
    assert severidad_de(56) == "medium"
    assert severidad_de(51) == "low"


# --------------------------------- filtros ----------------------------------
def test_filtros_de_la_lista(soc, tmp_path):
    almacen = IncidentStore(tmp_path / "filtros.db")
    almacen.save_batch([_resultado("r1", "a", 90.0, entidad="SRV-A", tecnicas=["T1059"]),
                        _resultado("r1", "b", 60.0, entidad="SRV-B", tecnicas=["T1046"]),
                        _resultado("r1", "c", 95.0, entidad="SRV-A", tecnicas=["T1059"])],
                       umbral=50.0)
    almacen.update("r1:b", "rosa", owner="rosa")

    assert almacen.list(Filtro(severity="critical"))["total"] == 2
    assert almacen.list(Filtro(owner="rosa"))["total"] == 1
    assert almacen.list(Filtro(unassigned=True))["total"] == 2
    assert almacen.list(Filtro(entity="SRV-A"))["total"] == 2
    assert almacen.list(Filtro(technique="T1046"))["total"] == 1
    assert almacen.list(Filtro(query="SRV-B"))["total"] == 1
    assert almacen.list(Filtro(state="new"))["total"] == 3


def test_los_cerrados_van_al_final(soc, tmp_path):
    """El orden por defecto de un panel es una decisión de producto."""
    almacen = IncidentStore(tmp_path / "orden.db")
    almacen.save_batch([_resultado("r1", "critico", 95.0),
                        _resultado("r1", "medio", 60.0)], umbral=50.0)
    almacen.update("r1:critico", "rosa", state="resolved", resolution="false_positive")
    orden = [i["incident_id"] for i in almacen.list(Filtro())["incidents"]]
    assert orden == ["r1:medio", "r1:critico"]


def test_la_paginacion_esta_acotada(soc, tmp_path):
    almacen = IncidentStore(tmp_path / "pag.db")
    almacen.save_batch([_resultado("r1", f"e{i}", 90.0) for i in range(30)], umbral=50.0)
    pagina = almacen.list(Filtro(limit=10, offset=0))
    assert len(pagina["incidents"]) == 10 and pagina["total"] == 30
    assert len(almacen.list(Filtro(limit=100000))["incidents"]) == 30  # tope interno


# ------------------------------ notas y veredicto ---------------------------
def test_las_notas_se_anaden(soc):
    cliente, inc = soc["cliente"], _primer_incidente(soc)
    rosa = _cab(cliente, "rosa")
    r = cliente.post(f"/api/v1/incidents/{inc['incident_id']}/notes",
                     json={"text": "El hash coincide con una herramienta legítima."},
                     headers=rosa)
    assert r.status_code == 201
    assert any(e["kind"] == "note" and "hash" in e["text"]
               for e in r.json()["timeline"])


def test_el_veredicto_alimenta_el_mismo_almacen_que_la_cli(soc):
    """
    Dos fuentes de verdad sobre lo que un humano decidió son cero fuentes de
    verdad: el panel escribe en el almacén de `cybersentinel decide`.
    """
    cliente, svc = soc["cliente"], soc["svc"]
    # Se siembra un incidente propio en vez de consumir uno del pipeline: así
    # la prueba no depende de cuántos produjo el motor ni del orden en que se
    # ejecuten las demás.
    objetivo = "prueba-veredicto:tp"
    _sembrar(svc.incidents, objetivo)

    r = cliente.post(f"/api/v1/incidents/{objetivo}/triage",
                     json={"action": "REJECT", "reason": "script de inventario"},
                     headers=_cab(cliente, "rosa"))
    assert r.status_code == 201, r.text
    cuerpo = r.json()

    # La decisión se persiste en el JSONL del gestor de dataset.
    ruta = Path(svc.feedback.store_path)
    assert ruta.exists()
    lineas = [json.loads(l) for l in ruta.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert any(d["detection_id"] == objetivo and d["analyst_decision"] == "FALSE_POSITIVE"
               for d in lineas)

    # La evidencia queda sellada dentro de la decisión.
    sellada = next(d for d in lineas if d["detection_id"] == objetivo)["selected_evidence"]
    assert sellada["score"] and "rules" in sellada

    # Y el incidente refleja el veredicto en su estado.
    assert cuerpo["incident"]["state"] == "false_positive"
    assert any(e["kind"] == "decision" for e in cuerpo["incident"]["timeline"])


def test_un_veredicto_dudoso_no_cierra_el_incidente(soc):
    """Cerrar un incidente sobre el que el analista duda lo esconde sin resolverlo."""
    cliente = soc["cliente"]
    objetivo = "prueba-veredicto:dudoso"
    _sembrar(soc["svc"].incidents, objetivo)

    r = cliente.post(f"/api/v1/incidents/{objetivo}/triage",
                     json={"action": "UNCERTAIN", "reason": "falta contexto"},
                     headers=_cab(cliente, "rosa"))
    assert r.status_code == 201
    assert r.json()["incident"]["state"] == "uncertain"


def test_veredicto_desconocido_se_rechaza(soc):
    cliente, inc = soc["cliente"], _primer_incidente(soc)
    r = cliente.post(f"/api/v1/incidents/{inc['incident_id']}/triage",
                     json={"action": "ME_LO_INVENTO"}, headers=_cab(cliente, "rosa"))
    assert r.status_code == 422
    assert "desconocida" in r.text


# --------------------------------- el panel ---------------------------------
def test_el_panel_se_sirve(soc):
    r = soc["cliente"].get("/soc/")
    assert r.status_code == 200
    assert "CyberSentinel" in r.text
    for recurso in ("/soc/panel.css", "/soc/panel.js"):
        assert soc["cliente"].get(recurso).status_code == 200


def test_la_raiz_lleva_al_panel(soc):
    r = soc["cliente"].get("/", follow_redirects=False)
    assert r.status_code in (307, 308)
    assert r.headers["location"] == "/soc/"


def test_cabeceras_de_seguridad(soc):
    """
    El panel muestra telemetría que escribe el atacante. Una política de
    contenido estricta convierte un descuido futuro en un error de consola en
    lugar de en ejecución de código en el navegador del analista.
    """
    csp = soc["cliente"].get("/soc/").headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "script-src 'self'" in csp
    cabeceras = soc["cliente"].get("/soc/").headers
    assert cabeceras["X-Content-Type-Options"] == "nosniff"
    assert cabeceras["X-Frame-Options"] == "DENY"


def test_el_panel_no_inserta_html_del_servidor():
    """
    Una línea de comandos con `<img onerror=...>` se ejecutaría en el navegador
    del analista que la investiga. Por eso el panel usa `textContent`.
    """
    js = _codigo(PANEL / "panel.js")
    for prohibido in ("innerHTML", "outerHTML", "document.write", "eval(", "insertAdjacentHTML"):
        assert prohibido not in js, f"el panel usa {prohibido}"


def test_el_panel_no_usa_dialogos_nativos():
    """
    `prompt`, `alert` y `confirm` congelan la pestaña entera hasta que alguien
    los cierra: las peticiones en vuelo se quedan colgadas y el analista no
    puede ni cancelar. Se comprobó en un navegador real, donde un `prompt`
    bloqueó la página hasta tener que cerrarla.
    """
    js = _codigo(PANEL / "panel.js")
    for prohibido in ("prompt(", "alert(", "confirm("):
        assert prohibido not in js, f"el panel usa {prohibido}"


def test_el_panel_no_depende_de_la_red():
    """
    Sin descargas externas: un centro de operaciones puede estar en una red
    aislada, y un panel que pide una fuente a un CDN se queda en blanco.

    Se buscan **referencias**, no la cadena «https» suelta: el propio panel
    menciona el esquema al avisar de que la conexión no está cifrada, y una
    comprobación por subcadena confundiría ese aviso con una dependencia.
    """
    patrones = [
        r'(?:src|href)\s*=\s*["\']https?://',   # <script>, <link>, <img>
        r'url\(\s*["\']?(?:https?:)?//',        # @import y url() en CSS
        r'(?:fetch|import)\s*\(\s*["\']https?://',  # peticiones desde el JS
        r'["\']//[a-z0-9.-]+\.[a-z]{2,}/',       # rutas relativas al protocolo
    ]
    for archivo in ("index.html", "panel.css", "panel.js"):
        contenido = (PANEL / archivo).read_text(encoding="utf-8")
        for patron in patrones:
            encontrado = re.search(patron, contenido, re.I)
            assert not encontrado, f"{archivo} referencia algo externo: {encontrado.group(0)}"


def test_el_panel_guarda_el_token_en_sessionstorage():
    """`localStorage` sobreviviría al cierre de la pestaña en un puesto compartido."""
    js = _codigo(PANEL / "panel.js")
    assert "sessionStorage" in js
    assert "localStorage" not in js


def _codigo(ruta: Path) -> str:
    """
    El JavaScript sin comentarios.

    Sin esto, la prueba fallaría por la línea del encabezado que **explica** por
    qué no se usa `innerHTML`: se comprueba el código, no la prosa.
    """
    texto = re.sub(r"/\*.*?\*/", "", ruta.read_text(encoding="utf-8"), flags=re.S)
    return re.sub(r"^\s*//.*$", "", texto, flags=re.M)


# ------------------------------- utilidades ---------------------------------
class _ReglaFalsa:
    def __init__(self, rid: str) -> None:
        self.id, self.title = rid, f"Regla {rid}"


class _HitFalso:
    def __init__(self, rid: str) -> None:
        self.rule = _ReglaFalsa(rid)

    def to_dict(self) -> dict:
        return {"rule_id": self.rule.id, "title": self.rule.title, "confidence": 0.9}


class _EvidenciaFalsa:
    """
    Evidencia mínima para probar el **almacén**, no la detección.

    La detección real ya la cubre la parte de arriba de este archivo, que usa el
    pipeline sin dobles. Aquí interesa el ciclo de vida, y fabricar la evidencia
    hace las pruebas deterministas y rápidas.
    """

    def __init__(self, run_id, ref, score, entidad, tecnicas):
        # `event_id` es lo que `IncidentStore.save_batch` usa como
        # `incident_id`: debe llevar el mismo valor que usan las pruebas
        # (`f"{run_id}:{ref}"`), no solo `ref`.
        self.run_id, self.event_ref, self.event_id = run_id, ref, f"{run_id}:{ref}"
        self.hybrid_score, self.anomaly_score = score, 0.4
        self.entity = entidad
        self.mitre_context, self.mitre_tactics = tecnicas, ["execution"]
        self.rule_matches = [_HitFalso("RULE-0001")]
        self.cti_hits, self.rag_context = [], []
        self.created_at = "2025-04-02T09:00:00+00:00"
        self.detection_status, self.llm_status = "RULE_MATCH", "DISABLED"
        self.fallback_used = True


class _ResultadoFalso:
    def __init__(self, evidencia):
        self.evidence, self.narrative, self.recommendations = evidencia, "narrativa", []
        self.source = "sysmon"


def _resultado(run_id, ref, score, entidad="SRV-A", tecnicas=("T1059",)):
    return _ResultadoFalso(_EvidenciaFalsa(run_id, ref, score, entidad, list(tecnicas)))


def _sembrar(almacen: IncidentStore, incident_id: str, score: float = 90.0) -> None:
    run_id, ref = incident_id.split(":", 1)
    almacen.save_batch([_resultado(run_id, ref, score)], umbral=50.0)
