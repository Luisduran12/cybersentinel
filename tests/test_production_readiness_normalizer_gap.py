"""
Fix de un hallazgo CRÍTICO de la auditoría de producción real (Fase 1/2):
`linux`, `suricata` y `wazuh` no tenían parser en `ingestion/normalizer.py`
— el módulo que usa la API HTTP real (`IngestService.ingest`) y la CLI
(`cybersentinel analyze`). Un evento `{"source": "suricata", ...}` enviado a
`POST /api/v1/events` caía en silencio al parser de Sysmon (con la etiqueta
`fuente_desconocida`) aunque `collectors/suricata.py` ya existiera, funcionara
y tuviera sus propios tests — simplemente nunca se llamaba desde ahí.

Estas pruebas verifican el fix por el camino real: `Normalizer` (no el
collector aislado) y, para `suricata`, la API HTTP completa con
`TestClient`, exactamente como llegaría un evento real.
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cybersentinel.api.models import KNOWN_SOURCES  # noqa: E402
from cybersentinel.ingestion.normalizer import Normalizer, PARSERS  # noqa: E402


def test_parsers_incluye_las_tres_fuentes_antes_huerfanas():
    assert {"linux", "suricata", "wazuh"} <= set(PARSERS)


def test_known_sources_incluye_las_tres_fuentes():
    assert {"linux", "suricata", "wazuh"} <= KNOWN_SOURCES


def test_normalizer_suricata_ya_no_cae_a_sysmon():
    evento = Normalizer().normalize_record({
        "source": "suricata", "timestamp": "2025-03-10T10:00:00Z",
        "event_type": "alert", "src_ip": "1.1.1.1", "dest_ip": "2.2.2.2",
        "alert": {"signature": "ET TROJAN test", "severity": 2},
    })
    assert evento.source == "suricata"
    assert "fuente_desconocida" not in evento.tags
    assert evento.category == "ids"
    assert evento.properties["signature"] == "ET TROJAN test"


def test_normalizer_wazuh_ya_no_cae_a_sysmon():
    evento = Normalizer().normalize_record({
        "source": "wazuh", "timestamp": "2025-03-10T10:00:00Z",
        "rule": {"id": "5710", "level": 10, "description": "sshd: brute force attempt"},
        "agent": {"id": "001", "name": "SRV-APP"},
        "data": {"srcip": "203.0.113.5", "srcuser": "root"},
    })
    assert evento.source == "wazuh"
    assert "fuente_desconocida" not in evento.tags
    assert evento.host == "SRV-APP"
    assert evento.properties["wazuh_rule_id"] == "5710"


def test_normalizer_linux_journald_ya_no_cae_a_sysmon():
    evento = Normalizer().normalize_record({
        "source": "linux", "timestamp": "2025-03-10T10:00:00Z",
        "MESSAGE": "Accepted password for ana from 10.0.0.5",
        "_COMM": "sshd", "_UID": "0",
    })
    assert evento.source == "linux"
    assert "fuente_desconocida" not in evento.tags
    assert evento.process_name == "sshd"


def test_normalizer_suricata_payload_excesivo_se_rechaza_no_se_inventa():
    """
    Cuando el collector delegado falla de verdad (payload > 5 MiB), el
    fallo debe propagarse como ValueError -- no silenciarse ni mostrarse
    como un evento sysmon válido.
    """
    enorme = {"source": "suricata", "event_type": "alert", "padding": "a" * (6 * 1024 * 1024)}
    with pytest.raises(ValueError):
        Normalizer().normalize_record(enorme)


# --------------------- a través de la API HTTP real --------------------------
from fastapi.testclient import TestClient  # noqa: E402

from cybersentinel.api.app import IngestService, create_app  # noqa: E402
from cybersentinel.api.security import (  # noqa: E402
    IdentityStore, LimitPolicy, RateLimiter, Role, SecurityConfig, SecurityGate,
)

RULES = ROOT / "config" / "rules"
BASE = datetime(2025, 3, 10, 10, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def cliente_api(tmp_path_factory):
    directorio = tmp_path_factory.mktemp("normalizer_gap")
    svc = IngestService(
        rules_dir=RULES, db_path=directorio / "events.db", wal_dir=directorio / "wal",
        audit_path=directorio / "audit.jsonl", queue_maxsize=5000, batch_size=200,
        enable_rag=False, enable_llm=False,
    )
    almacen = IdentityStore(directorio / "identities.db")
    sensor = almacen.create_api_key("suite-normalizer-gap", Role.COLLECTOR)
    abierto = LimitPolicy(10_000, 20_000, 10_000_000, 20_000_000)
    gate = SecurityGate(SecurityConfig(
        identity_db=directorio / "identities.db",
        jwt_secret="a" * 48,
        rate_limiter=RateLimiter({r.value: abierto for r in Role} | {"anonymous": abierto}),
    ))
    with TestClient(create_app(svc, gate=gate), base_url="https://testserver") as c:
        c.headers.update({"X-API-Key": sensor.token})
        yield c, svc


def test_api_real_acepta_y_detecta_un_evento_suricata(cliente_api):
    """
    Antes del fix: este evento se habría procesado como si fuera Sysmon
    (silenciosamente mal interpretado). Ahora debe llegar como IDS real.
    """
    c, svc = cliente_api
    r = c.post("/api/v1/events", json={"events": [{
        "source": "suricata", "timestamp": BASE.isoformat(),
        "event_type": "alert", "src_ip": "185.220.101.5", "dest_ip": "10.0.0.5",
        "alert": {"signature": "ET TROJAN Generic C2", "severity": 1},
    }]})
    assert r.status_code == 202, r.text
    assert r.json()["accepted"] == 1

    import time
    limite = time.time() + 10
    while time.time() < limite and svc.store.count() == 0:
        time.sleep(0.1)
    assert svc.store.count() >= 1


def test_api_real_evento_linux_ya_no_se_pierde_como_sysmon(cliente_api):
    c, svc = cliente_api
    antes = svc.store.count()
    r = c.post("/api/v1/events", json={"events": [{
        "source": "linux", "timestamp": (BASE + timedelta(seconds=1)).isoformat(),
        "MESSAGE": "Failed password for root from 203.0.113.9", "_COMM": "sshd",
    }]})
    assert r.status_code == 202, r.text
    assert r.json()["accepted"] == 1
    assert "fuente_desconocida" not in r.json().get("annotations", {})
