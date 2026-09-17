"""
Pruebas del adaptador OCSF: `SecurityEvent` <-> OCSF.

No dependen de infraestructura (ni NATS, ni Docker): son conversión pura, y
deben poder correr en cualquier máquina de desarrollo o CI sin nada levantado.
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cybersentinel.ingestion.ocsf import (  # noqa: E402
    CLASS_AUTHENTICATION, CLASS_BASE_EVENT, CLASS_DETECTION_FINDING,
    CLASS_NETWORK_ACTIVITY, CLASS_PROCESS_ACTIVITY, from_ocsf, to_ocsf,
)
from cybersentinel.schema import SecurityEvent  # noqa: E402

BASE = datetime(2026, 1, 15, 9, 30, tzinfo=timezone.utc)


def _evento(**kwargs) -> SecurityEvent:
    datos = dict(
        event_id="evt-1", timestamp=BASE, source="sysmon", category="process",
        action="process_create", host="WKS-01", user="ana",
        process_name="powershell.exe", command_line="powershell -enc AAA",
        outcome="success",
    )
    datos.update(kwargs)
    return SecurityEvent(**datos)


def test_proceso_se_clasifica_como_process_activity():
    doc = to_ocsf(_evento())
    assert doc["class_uid"] == CLASS_PROCESS_ACTIVITY
    assert doc["category_uid"] == 1
    assert doc["activity_id"] == 1          # process_create -> Launch
    assert doc["type_uid"] == CLASS_PROCESS_ACTIVITY * 100 + 1
    assert doc["process"]["cmd_line"] == "powershell -enc AAA"
    assert doc["metadata"]["version"] == "1.1.0"
    assert doc["time"] == int(BASE.timestamp() * 1000)


def test_autenticacion_se_clasifica_como_authentication():
    evento = _evento(source="auth", category="authentication", action="user_login",
                      process_name=None, command_line=None, outcome="failure",
                      src_ip="203.0.113.5")
    doc = to_ocsf(evento)
    assert doc["class_uid"] == CLASS_AUTHENTICATION
    assert doc["category_uid"] == 3
    assert doc["status_id"] == 2            # failure
    assert "process" not in doc             # no se inventan bloques vacíos


def test_firewall_se_clasifica_como_network_activity():
    evento = _evento(source="firewall", category="network", action="network_connection",
                      process_name=None, command_line=None,
                      src_ip="10.0.0.5", dst_ip="203.0.113.9", dst_port=443,
                      protocol="tcp", bytes_out=1500, bytes_in=200)
    doc = to_ocsf(evento)
    assert doc["class_uid"] == CLASS_NETWORK_ACTIVITY
    assert doc["category_uid"] == 4
    assert doc["dst_endpoint"] == {"ip": "203.0.113.9", "port": 443}
    assert doc["traffic"] == {"bytes_in": 200, "bytes_out": 1500}


def test_alerta_suricata_se_clasifica_como_detection_finding():
    evento = _evento(source="suricata", category="alert", action="ids_alert",
                      process_name=None, command_line=None,
                      properties={"signature": "ET TROJAN Generic"})
    doc = to_ocsf(evento)
    assert doc["class_uid"] == CLASS_DETECTION_FINDING
    assert doc["category_uid"] == 2
    assert doc["finding_info"]["title"] == "ET TROJAN Generic"


def test_categoria_desconocida_cae_en_base_event_no_en_error():
    evento = _evento(source="algo-nuevo", category="algo-raro", action="quien-sabe",
                      process_name=None, command_line=None)
    doc = to_ocsf(evento)
    assert doc["class_uid"] == CLASS_BASE_EVENT
    assert doc["category_uid"] == 0


def test_ningun_campo_ausente_viaja_como_null():
    doc = to_ocsf(_evento(host=None, user=None))
    assert None not in doc.values()


def test_ida_y_vuelta_sin_perdidas_en_lo_esencial():
    original = _evento(properties={"hashes": {"sha256": "abc"}}, tags=["collector:sysmon"])
    doc = to_ocsf(original)
    reconstruido = from_ocsf(doc)

    assert reconstruido.source == original.source
    assert reconstruido.category == original.category
    assert reconstruido.action == original.action
    assert reconstruido.host == original.host
    assert reconstruido.user == original.user
    assert reconstruido.process_name == original.process_name
    assert reconstruido.command_line == original.command_line
    assert reconstruido.outcome == original.outcome
    assert reconstruido.tags == original.tags
    assert reconstruido.properties.get("hashes") == {"sha256": "abc"}
    assert reconstruido.timestamp == original.timestamp


def test_evento_ocsf_ajeno_sin_metadata_propia_no_falla():
    """
    Un evento OCSF que no vino de nosotros no trae `cybersentinel_action`: se
    deriva una categoría/acción genérica del `class_uid` en vez de fallar.
    """
    ajeno = {
        "class_uid": CLASS_NETWORK_ACTIVITY, "activity_id": 1,
        "time": int(BASE.timestamp() * 1000),
        "src_endpoint": {"ip": "10.0.0.1"}, "dst_endpoint": {"ip": "10.0.0.2", "port": 22},
    }
    evento = from_ocsf(ajeno)
    assert evento.source == "ocsf"
    assert evento.category == "network"
    assert evento.src_ip == "10.0.0.1"
    assert evento.dst_port == 22
