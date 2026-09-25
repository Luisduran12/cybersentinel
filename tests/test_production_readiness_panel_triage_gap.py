"""
Fix de un hallazgo CRÍTICO de la auditoría de producción real (Fase 1/6):
el panel SOC real, probado a mano en el navegador, respondía **404** al
pulsar cualquiera de los cuatro botones de veredicto ("Verdadero positivo",
"Falso positivo", "Benigno", "Dudoso").

`panel.js` llamaba a `POST /api/v1/incidents/{id}/decision` — un endpoint
que **nunca existió** en el backend (quedó documentado en un comentario del
router y en un diccionario muerto, `RESOLUCION_POR_VEREDICTO`, pero jamás se
implementó la ruta). El endpoint real, probado desde hace tiempo por
`tests/test_soc_panel.py`, es `POST /api/v1/incidents/{id}/triage` con un
campo `action` (no `decision`). Ningún test lo detectó porque nada ejecutaba
el JavaScript del panel — hacía falta abrir un navegador de verdad.

Estas pruebas cierran dos huecos:
1. Una prueba **estructural**: cada endpoint que `panel.js` invoca debe
   corresponder a una ruta real registrada en la app — así una futura
   ruptura de contrato se detecta en `pytest`, no en un navegador.
2. Una prueba **funcional de extremo a extremo**: los cuatro veredictos,
   contra la API real (TestClient), verificando el efecto persistido.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
PANEL_JS = ROOT / "src" / "cybersentinel" / "api" / "panel" / "panel.js"


def _rutas_de_panel_js() -> set[str]:
    """
    Extrae los patrones de endpoint que `panel.js` invoca vía `api(...)`,
    normalizados a la forma que usa FastAPI (`{id}` en vez de una
    interpolación de JS). Cubre las dos formas que usa el archivo:
    template literals (`` `/incidents/${encodeURIComponent(id)}/triage` ``)
    y concatenación (`"/incidents/" + encodeURIComponent(id)`).
    """
    texto = PANEL_JS.read_text(encoding="utf-8")
    normalizadas = set()

    for ruta in re.findall(r'api\(\s*`([^`]+)`', texto):
        ruta = re.sub(r"\$\{encodeURIComponent\([^)]+\)\}", "{id}", ruta.split("?")[0])
        normalizadas.add("/api/v1" + ruta)

    for prefijo, sufijo in re.findall(
        r'api\(\s*"([^"]*)"\s*\+\s*encodeURIComponent\([^)]+\)\s*(?:\+\s*"([^"]*)")?',
        texto,
    ):
        normalizadas.add("/api/v1" + prefijo + "{id}" + sufijo)

    return normalizadas


def test_panel_js_no_referencia_el_endpoint_decision_que_nunca_existio():
    """Guarda de regresión directa del bug encontrado: no debe reaparecer."""
    texto = PANEL_JS.read_text(encoding="utf-8")
    assert "/decision" not in texto, (
        "panel.js vuelve a referenciar '/decision', el endpoint que nunca "
        "existió en el backend (el real es /triage)."
    )


def test_todas_las_rutas_que_llama_panel_js_existen_en_la_api_real():
    """
    Prueba estructural genérica: si algún endpoint de `panel.js` deja de
    existir en el backend (se renombra, se borra), esto falla en pytest en
    vez de esperar a que alguien lo note a mano en el navegador — que es
    exactamente como se encontró el bug de /decision.
    """
    from cybersentinel.api.app import create_app, IngestService
    from cybersentinel.config import DEFAULT_RULES_DIR

    app = create_app(IngestService(rules_dir=DEFAULT_RULES_DIR, enable_rag=False, enable_llm=False))
    rutas_reales = {
        re.sub(r"\{[^}]+\}", "{id}", r.path)
        for r in app.routes if hasattr(r, "path")
    }

    llamadas = _rutas_de_panel_js()
    faltantes = {r for r in llamadas if r not in rutas_reales}
    assert not faltantes, (
        f"panel.js llama a endpoints que no existen en la API real: {faltantes}. "
        f"Rutas disponibles con esa forma: "
        f"{sorted(r for r in rutas_reales if r.startswith('/api/v1/incidents'))}"
    )


# --------------------- flujo funcional de extremo a extremo -----------------
from datetime import datetime, timedelta, timezone  # noqa: E402

from fastapi.testclient import TestClient  # noqa: E402

from cybersentinel.api.app import IngestService, create_app  # noqa: E402
from cybersentinel.api.security import (  # noqa: E402
    IdentityStore, LimitPolicy, RateLimiter, Role, SecurityConfig, SecurityGate,
)

RULES = ROOT / "config" / "rules"
BASE = datetime(2025, 3, 10, 10, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def panel_client(tmp_path_factory):
    directorio = tmp_path_factory.mktemp("panel_triage_gap")
    svc = IngestService(
        rules_dir=RULES, db_path=directorio / "events.db", wal_dir=directorio / "wal",
        audit_path=directorio / "audit.jsonl", queue_maxsize=5000, batch_size=200,
        enable_rag=False, enable_llm=False,
    )
    almacen = IdentityStore(directorio / "identities.db")
    sensor = almacen.create_api_key("suite-panel-gap", Role.COLLECTOR)
    almacen.create_user("analista", "contraseña-de-prueba-larga", Role.ANALYST)
    abierto = LimitPolicy(10_000, 20_000, 10_000_000, 20_000_000)
    gate = SecurityGate(SecurityConfig(
        identity_db=directorio / "identities.db", jwt_secret="b" * 48,
        rate_limiter=RateLimiter({r.value: abierto for r in Role} | {"anonymous": abierto}),
    ))
    with TestClient(create_app(svc, gate=gate), base_url="https://testserver") as c:
        c.headers.update({"X-API-Key": sensor.token})
        r = c.post("/api/v1/auth/token",
                   json={"username": "analista", "password": "contraseña-de-prueba-larga"},
                   headers={"X-API-Key": ""})
        token = r.json()["access_token"]
        yield c, svc, {"Authorization": f"Bearer {token}", "X-API-Key": ""}


def _crear_incidente(c, svc, event_id: str) -> str:
    c.post("/api/v1/events", json={"events": [{
        "source": "sysmon", "event_id": event_id, "timestamp": BASE.isoformat(),
        "EventID": 1, "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgA",
        "Computer": "SRV-PANEL-GAP",
    }]})
    import time
    limite = time.time() + 10
    while time.time() < limite and svc.incidents.get(event_id) is None:
        time.sleep(0.1)
    assert svc.incidents.get(event_id) is not None, "el incidente de prueba no se creó a tiempo"
    return event_id


@pytest.mark.parametrize("boton,accion_o_patch,estado_esperado", [
    ("Verdadero positivo", {"kind": "triage", "action": "CONFIRM"}, "confirmed"),
    ("Falso positivo", {"kind": "triage", "action": "REJECT"}, "false_positive"),
    ("Dudoso", {"kind": "triage", "action": "UNCERTAIN"}, "uncertain"),
    ("Benigno", {"kind": "patch", "state": "resolved", "resolution": "benign"}, "resolved"),
])
def test_los_cuatro_botones_de_veredicto_funcionan_de_extremo_a_extremo(
    panel_client, boton, accion_o_patch, estado_esperado,
):
    """
    Reproduce, contra la API real (no un mock), exactamente lo que el botón
    correspondiente de panel.js dispara ahora que está arreglado.
    """
    c, svc, cab = panel_client
    event_id = f"panel-gap-{boton.replace(' ', '-').lower()}"
    _crear_incidente(c, svc, event_id)

    if accion_o_patch["kind"] == "triage":
        r = c.post(f"/api/v1/incidents/{event_id}/triage",
                  json={"action": accion_o_patch["action"], "reason": f"prueba: {boton}"},
                  headers=cab)
    else:
        r = c.patch(f"/api/v1/incidents/{event_id}",
                   json={"state": accion_o_patch["state"],
                        "resolution": accion_o_patch["resolution"],
                        "note": f"prueba: {boton}"},
                   headers=cab)

    assert r.status_code in (200, 201), f"{boton} -> {r.status_code}: {r.text}"
    detalle = c.get(f"/api/v1/incidents/{event_id}", headers=cab).json()
    assert detalle["state"] == estado_esperado, f"{boton} no dejó el incidente en '{estado_esperado}'"
