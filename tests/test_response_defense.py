"""
Pruebas de Fase 4-E: respuesta defensiva real.

Auditoría relevante: existían DOS sistemas de respuesta que no se hablaban
entre sí. `response/actions.py` (ResponsePlanner+GovernancePolicy) sí estaba
conectado al `Pipeline`, pero solo producía un string de texto simulado —
nunca ejecutaba nada. `response/executor.py` (ResponseAction/ActionStatus,
con el ciclo de vida HITL completo) tenía el diseño correcto pero estaba
100% desconectado y sin ningún test. Esta fase conecta ambos y reemplaza la
simulación por integraciones reales.

Cuatro bloques de prueba, como pide el prompt:
- DRY_RUN: no ejecuta nada real.
- HITL: no aprueba sin humano (ni el LLM puede).
- Auditoría: todo queda registrado.
- Wazuh: ingesta y respuesta activa reales (con `httpx.MockTransport`).
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cybersentinel.collectors import WazuhCollector, get_collector  # noqa: E402
from cybersentinel.config import DEFAULT_RULES_DIR  # noqa: E402
from cybersentinel.governance.audit import AuditLog  # noqa: E402
from cybersentinel.pipeline import ALERT_THRESHOLD, Pipeline  # noqa: E402
from cybersentinel.response.executor import (  # noqa: E402
    ResponseExecutor, UnauthorizedApproverError,
)
from cybersentinel.response.integrations import (  # noqa: E402
    EmailNotifier, IOCBlocklist, TicketWriter, WebhookNotifier,
)
from cybersentinel.response.models import ActionStatus, ActionType, ResponseAction  # noqa: E402
from cybersentinel.response.store import ResponseStore  # noqa: E402
from cybersentinel.response.wazuh_client import WazuhResponseClient  # noqa: E402
from cybersentinel.schema import SecurityEvent  # noqa: E402

BASE = datetime(2025, 3, 10, 10, tzinfo=timezone.utc)


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


# ------------------------------ integrations.py ------------------------------
def test_webhook_dry_run_no_hace_ninguna_peticion():
    def handler(request: httpx.Request) -> httpx.Response:
        pytest.fail("dry_run no debe hacer ninguna petición HTTP")

    notifier = WebhookNotifier(webhook_url="https://hooks.example/x", client=_client(handler))
    resultado = notifier.send("alerta de prueba", dry_run=True)
    assert resultado["status"] == "DRY_RUN"


def test_webhook_real_hace_post_real():
    llamadas = []

    def handler(request: httpx.Request) -> httpx.Response:
        llamadas.append(json.loads(request.content))
        return httpx.Response(200, json={"ok": True})

    notifier = WebhookNotifier(webhook_url="https://hooks.example/x", client=_client(handler))
    resultado = notifier.send("alerta real", dry_run=False)
    assert resultado["status"] == "OK"
    assert llamadas == [{"text": "alerta real"}]


def test_webhook_sin_url_es_not_configured():
    notifier = WebhookNotifier(webhook_url=None)
    assert notifier.send("x", dry_run=False)["status"] == "NOT_CONFIGURED"


def test_webhook_error_http_no_lanza_excepcion():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="internal error")

    notifier = WebhookNotifier(webhook_url="https://hooks.example/x", client=_client(handler))
    resultado = notifier.send("x", dry_run=False)
    assert resultado["status"] == "ERROR"


class _FakeSMTP:
    def __init__(self):
        self.enviados = []

    def send_message(self, msg):
        self.enviados.append(msg)


def test_email_real_envia_via_smtp_inyectado():
    smtp_falso = _FakeSMTP()
    notifier = EmailNotifier(host="smtp.example.com", sender="cs@example.com",
                             recipient="soc@example.com", smtp_client=smtp_falso)
    resultado = notifier.send("asunto", "cuerpo", dry_run=False)
    assert resultado["status"] == "OK"
    assert len(smtp_falso.enviados) == 1
    assert smtp_falso.enviados[0]["Subject"] == "asunto"


def test_email_dry_run_no_envia_nada():
    smtp_falso = _FakeSMTP()
    notifier = EmailNotifier(host="smtp.example.com", sender="a@a.com", recipient="b@b.com",
                             smtp_client=smtp_falso)
    notifier.send("x", "y", dry_run=True)
    assert smtp_falso.enviados == []


def test_email_sin_configurar_es_not_configured():
    notifier = EmailNotifier(host=None, sender=None, recipient=None)
    assert notifier.send("x", "y", dry_run=False)["status"] == "NOT_CONFIGURED"


def test_ticket_writer_escribe_json_real(tmp_path):
    writer = TicketWriter(output_dir=tmp_path)
    resultado = writer.create({"action_id": "abc-123", "summary": "x"}, dry_run=False)
    assert resultado["status"] == "OK"
    ruta = Path(resultado["path"])
    assert ruta.exists()
    assert json.loads(ruta.read_text())["summary"] == "x"


def test_ticket_writer_dry_run_no_escribe_nada(tmp_path):
    writer = TicketWriter(output_dir=tmp_path)
    writer.create({"action_id": "x"}, dry_run=True)
    assert list(tmp_path.glob("*.json")) == []


def test_ioc_blocklist_agrega_y_es_idempotente(tmp_path):
    ruta = tmp_path / "blocklist.json"
    blocklist = IOCBlocklist(path=ruta)
    r1 = blocklist.add("ip", "203.0.113.5", "C2 confirmado", dry_run=False)
    assert r1["status"] == "OK"
    assert blocklist.contains("ip", "203.0.113.5")

    r2 = blocklist.add("ip", "203.0.113.5", "otra razón", dry_run=False)
    assert r2["status"] == "OK"
    assert "idempotente" in r2["detail"]
    assert len(json.loads(ruta.read_text())) == 1


def test_ioc_blocklist_dry_run_no_escribe(tmp_path):
    ruta = tmp_path / "blocklist.json"
    blocklist = IOCBlocklist(path=ruta)
    blocklist.add("ip", "1.2.3.4", "x", dry_run=True)
    assert not ruta.exists()


# -------------------------------- executor.py --------------------------------
@pytest.fixture
def executor(tmp_path):
    store = ResponseStore(tmp_path / "responses.db")
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    return ResponseExecutor(
        store, audit,
        webhook=WebhookNotifier(webhook_url=None),   # sin config: NOT_CONFIGURED si no es dry_run
        tickets_dir=str(tmp_path / "tickets"),
        blocklist_path=str(tmp_path / "blocklist.json"),
    )


def test_nivel_1_se_autoaprueba_y_ejecuta_ya(executor):
    accion = ResponseAction(incident_id="INC-1", action_type=ActionType.SEND_WEBHOOK_ALERT,
                            target={"ip": "1.2.3.4"}, justification="x", requested_by="pipeline")
    resultado = executor.request_action(accion)
    assert resultado.status == ActionStatus.COMPLETED
    assert resultado.approved_by is None  # nadie tuvo que aprobar nada


def test_nivel_2_se_queda_esperando_aprobacion(executor):
    accion = ResponseAction(incident_id="INC-1", action_type=ActionType.BLOCK_IP,
                            target={"ip": "203.0.113.5"}, justification="C2", requested_by="pipeline")
    resultado = executor.request_action(accion)
    assert resultado.status == ActionStatus.REQUESTED
    assert resultado.command is not None and "203.0.113.5" in resultado.command
    # Nada se ejecutó todavía.
    assert executor.store.get(resultado.action_id).status == ActionStatus.REQUESTED


def test_nivel_2_genera_comando_para_cada_tipo(executor):
    casos = [
        (ActionType.BLOCK_IP, {"ip": "1.2.3.4"}, "1.2.3.4"),
        (ActionType.ISOLATE_HOST, {"host": "SRV-DB"}, "SRV-DB"),
        (ActionType.DISABLE_ACCOUNT, {"user": "ana"}, "ana"),
        (ActionType.RESET_PASSWORD, {"user": "ana"}, "ana"),
    ]
    for tipo, target, esperado in casos:
        accion = ResponseAction(incident_id="INC-1", action_type=tipo, target=target,
                                justification="x", requested_by="pipeline")
        resultado = executor.request_action(accion)
        assert esperado in resultado.command, f"{tipo}: comando no contiene {esperado}"


# --------------------------------- DRY_RUN -----------------------------------
def test_dry_run_no_ejecuta_nada_real(tmp_path, monkeypatch):
    """Con DRY_RUN=true (el default), ninguna integración real se ejecuta."""
    monkeypatch.setenv("CYBERSENTINEL_DRY_RUN", "true")
    store = ResponseStore(tmp_path / "r.db")
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    ex = ResponseExecutor(store, audit, tickets_dir=str(tmp_path / "tickets"),
                          blocklist_path=str(tmp_path / "blocklist.json"))
    assert ex.global_dry_run is True

    for tipo, target in [
        (ActionType.SEND_WEBHOOK_ALERT, {}), (ActionType.CREATE_TICKET, {}),
        (ActionType.BLOCK_IOC_LOCAL, {"ip": "1.2.3.4"}),
    ]:
        accion = ex.request_action(ResponseAction(
            incident_id="INC-1", action_type=tipo, target=target,
            justification="x", requested_by="pipeline"))
        assert accion.result["status"] == "DRY_RUN"

    assert not (tmp_path / "tickets").exists()
    assert not (tmp_path / "blocklist.json").exists()


def test_dry_run_false_permite_ejecucion_real(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSENTINEL_DRY_RUN", "false")
    store = ResponseStore(tmp_path / "r.db")
    ex = ResponseExecutor(store, None, blocklist_path=str(tmp_path / "blocklist.json"))
    assert ex.global_dry_run is False

    accion = ex.request_action(ResponseAction(
        incident_id="INC-1", action_type=ActionType.BLOCK_IOC_LOCAL, target={"ip": "9.9.9.9"},
        justification="x", requested_by="pipeline"))
    assert accion.result["status"] == "OK"
    assert (tmp_path / "blocklist.json").exists()


# ----------------------------------- HITL ------------------------------------
def test_llm_no_puede_aprobar_una_accion(executor):
    accion = executor.request_action(ResponseAction(
        incident_id="INC-1", action_type=ActionType.ISOLATE_HOST, target={"host": "SRV-DB"},
        justification="x", requested_by="pipeline"))
    for identidad in ("llm", "LLM", "agent", "system", "ia", ""):
        with pytest.raises(UnauthorizedApproverError):
            executor.approve_action(accion.action_id, approved_by=identidad)
    # Sigue esperando: ningún intento la aprobó de verdad.
    assert executor.store.get(accion.action_id).status == ActionStatus.REQUESTED


def test_un_humano_si_puede_aprobar_y_dispara_la_ejecucion(executor):
    accion = executor.request_action(ResponseAction(
        incident_id="INC-1", action_type=ActionType.ISOLATE_HOST, target={"host": "SRV-DB"},
        justification="x", requested_by="pipeline"))
    aprobada = executor.approve_action(accion.action_id, approved_by="analista.ana")
    assert aprobada.status == ActionStatus.COMPLETED
    assert aprobada.approved_by == "analista.ana"
    assert aprobada.result["executed_against_real_system"] is False


def test_rechazo_nunca_ejecuta(executor):
    accion = executor.request_action(ResponseAction(
        incident_id="INC-1", action_type=ActionType.BLOCK_IP, target={"ip": "1.2.3.4"},
        justification="x", requested_by="pipeline"))
    rechazada = executor.reject_action(accion.action_id, rejected_by="analista.ana")
    assert rechazada.status == ActionStatus.REJECTED
    assert rechazada.result is None


def test_no_se_puede_aprobar_dos_veces(executor):
    accion = executor.request_action(ResponseAction(
        incident_id="INC-1", action_type=ActionType.BLOCK_IP, target={"ip": "1.2.3.4"},
        justification="x", requested_by="pipeline"))
    assert executor.approve_action(accion.action_id, approved_by="ana") is not None
    # Ya no está en REQUESTED: una segunda aprobación no hace nada.
    assert executor.approve_action(accion.action_id, approved_by="ana") is None


# --------------------------------- Auditoría ----------------------------------
def test_toda_transicion_queda_en_el_audit_log(tmp_path):
    store = ResponseStore(tmp_path / "r.db")
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    ex = ResponseExecutor(store, audit, blocklist_path=str(tmp_path / "b.json"))

    accion = ex.request_action(ResponseAction(
        incident_id="INC-1", action_type=ActionType.BLOCK_IP, target={"ip": "1.2.3.4"},
        justification="x", requested_by="pipeline"))
    ex.approve_action(accion.action_id, approved_by="ana")

    ok, fallo = audit.verify()
    assert ok, f"cadena de auditoría comprometida en {fallo}"
    entradas = [json.loads(l) for l in Path(tmp_path / "audit.jsonl").read_text().splitlines()]
    acciones_registradas = {e["action"] for e in entradas}
    assert {"action_requested", "action_approved", "action_executing",
            "action_completed"} <= acciones_registradas


def test_accion_completada_tiene_hash_de_auditoria(tmp_path):
    store = ResponseStore(tmp_path / "r.db")
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    ex = ResponseExecutor(store, audit)
    accion = ex.request_action(ResponseAction(
        incident_id="INC-1", action_type=ActionType.SEND_WEBHOOK_ALERT, target={},
        justification="x", requested_by="pipeline"))
    assert accion.audit_record is not None


# --------------------- integración con el pipeline real ---------------------
def test_pipeline_dispara_respuesta_solo_para_hallazgos_reales():
    pipeline = Pipeline(rules_dir=DEFAULT_RULES_DIR, enable_rag=False, enable_llm=False,
                       enable_cti=False, enable_temporal=False, enable_behavior=False)
    benigno = SecurityEvent(
        event_id="ok-1", timestamp=BASE, source="sysmon", category="process",
        action="process_create", host="WKS-01", user="ana",
        command_line="chrome.exe --tab 1", process_name="chrome.exe", outcome="success",
    )
    pipeline.run_events([benigno])
    # Sin hallazgo, ResponsePlanner igual propone (siempre lo hace), pero no
    # debe haberse creado ninguna ResponseAction real.
    assert pipeline.response_executor.store.list_by_incident("ok-1") == []


def test_pipeline_dispara_respuesta_real_para_un_hallazgo():
    pipeline = Pipeline(rules_dir=DEFAULT_RULES_DIR, enable_rag=False, enable_llm=False,
                       enable_cti=False, enable_temporal=False, enable_behavior=False)
    sospechoso = SecurityEvent(
        event_id="sospechoso-1", timestamp=BASE, source="sysmon", category="process",
        action="process_create", host="SRV-APP", user="admin",
        command_line="powershell.exe -nop -w hidden -enc SQBFAFgA",
        process_name="powershell.exe", outcome="success",
    )
    reporte = pipeline.run_events([sospechoso])
    assert reporte.results[0].evidence.hybrid_score >= ALERT_THRESHOLD

    acciones = pipeline.response_executor.store.list_by_incident("sospechoso-1")
    assert acciones, "un hallazgo real no generó ninguna ResponseAction"
    tipos = {a.action_type for a in acciones}
    # notify_analyst siempre se propone -> SEND_WEBHOOK_ALERT (Nivel 1, ya ejecutado).
    assert ActionType.SEND_WEBHOOK_ALERT in tipos
    webhook = next(a for a in acciones if a.action_type == ActionType.SEND_WEBHOOK_ALERT)
    assert webhook.status == ActionStatus.COMPLETED


def test_pipeline_block_ip_genera_nivel1_y_nivel2():
    """block_ip debe producir DOS acciones: IOC local (ya ejecutado) + regla de firewall (esperando)."""
    pipeline = Pipeline(rules_dir=DEFAULT_RULES_DIR, enable_rag=False, enable_llm=False,
                       enable_cti=False, enable_temporal=False, enable_behavior=False)
    # dst_port=4444 y 3+ conexiones en <=10 min: umbral real de RULE-0006
    # (config/rules/c2_beacon.yaml).
    beacon = [
        SecurityEvent(event_id=f"c2-{i}", timestamp=BASE + timedelta(minutes=i * 3),
                     source="firewall", category="network", action="connection",
                     host="WKS-01", src_ip="10.0.0.5", dst_ip="203.0.113.66", dst_port=4444,
                     outcome="success")
        for i in range(4)
    ]
    reporte = pipeline.run_events(beacon)
    incidente_con_hallazgo = next(
        (r for r in reporte.results if r.evidence.hybrid_score >= ALERT_THRESHOLD), None)
    assert incidente_con_hallazgo is not None, "el beacon no disparó ninguna regla C2"

    acciones = pipeline.response_executor.store.list_by_incident(incidente_con_hallazgo.evidence.event_id)
    tipos = {a.action_type for a in acciones}
    assert ActionType.BLOCK_IOC_LOCAL in tipos
    assert ActionType.BLOCK_IP in tipos
    ioc = next(a for a in acciones if a.action_type == ActionType.BLOCK_IOC_LOCAL)
    firewall = next(a for a in acciones if a.action_type == ActionType.BLOCK_IP)
    assert ioc.status == ActionStatus.COMPLETED       # Nivel 1: ya se ejecutó
    assert firewall.status == ActionStatus.REQUESTED  # Nivel 2: espera aprobación


# ----------------------------------- Wazuh ------------------------------------
def test_wazuh_collector_normaliza_alerta_real():
    alerta = {
        "timestamp": "2025-03-10T10:00:00.000+0000",
        "rule": {"id": "5710", "level": 10, "description": "sshd: brute force attempt",
                "groups": ["authentication_failed"]},
        "agent": {"id": "001", "name": "web-server-01"},
        "data": {"srcip": "203.0.113.5", "srcuser": "root"},
        "full_log": "Failed password for root from 203.0.113.5",
    }
    resultado = get_collector("wazuh").collect(alerta)
    assert resultado.ok, resultado.errors
    evento = resultado.event
    assert evento.category == "authentication"
    assert evento.host == "web-server-01"
    assert evento.src_ip == "203.0.113.5"
    assert evento.outcome == "failure"
    assert evento.properties["wazuh_rule_level"] == 10
    assert evento.properties["wazuh_rule_severity"] == "high"


def test_wazuh_collector_evento_corrupto_no_tumba_nada(caplog):
    resultado = WazuhCollector().collect("{json roto")
    assert not resultado.ok
    assert resultado.errors


def test_wazuh_collector_campo_faltante_normaliza_a_none():
    resultado = WazuhCollector().collect({"rule": {"description": "algo"}})
    assert resultado.ok
    assert resultado.event.host is None
    assert resultado.event.src_ip is None


def test_wazuh_collector_llega_a_deteccion_real():
    """E2E: alerta Wazuh -> SecurityEvent -> Pipeline real -> DetectionEvidence."""
    pipeline = Pipeline(rules_dir=DEFAULT_RULES_DIR, enable_rag=False, enable_llm=False,
                       enable_cti=False, enable_temporal=False, enable_behavior=False)
    eventos = []
    for i in range(6):
        alerta = {
            "timestamp": (BASE + timedelta(seconds=i * 10)).isoformat(),
            "rule": {"id": "5710", "level": 5, "description": "sshd: authentication failed"},
            "agent": {"id": "001", "name": "SRV-APP"},
            "data": {"srcuser": "admin", "srcip": "203.0.113.66"},
        }
        resultado = get_collector("wazuh").collect(alerta)
        assert resultado.ok
        eventos.append(resultado.event)

    reporte = pipeline.run_events(eventos)
    assert reporte.total_events == 6
    assert any(r.evidence.rule_matches or r.evidence.anomaly_score > 0 for r in reporte.results)


# --- Wazuh: respuesta activa (CyberSentinel -> Wazuh) ------------------------
def test_wazuh_response_client_sin_configurar_es_not_configured():
    cliente = WazuhResponseClient(base_url=None, token=None)
    resultado = cliente.send_active_response("001", "firewall-drop", dry_run=False)
    assert resultado["status"] == "NOT_CONFIGURED"


def test_wazuh_response_client_dry_run_no_envia_nada():
    def handler(request: httpx.Request) -> httpx.Response:
        pytest.fail("dry_run no debe llamar a la API de Wazuh")

    cliente = WazuhResponseClient(base_url="https://wazuh.example:55000", token="tok",
                                  client=_client(handler))
    resultado = cliente.send_active_response("001", "firewall-drop", dry_run=True)
    assert resultado["status"] == "DRY_RUN"


def test_wazuh_response_client_real_llama_a_la_api():
    llamadas = []

    def handler(request: httpx.Request) -> httpx.Response:
        llamadas.append(request)
        assert request.headers["Authorization"] == "Bearer tok"
        assert "agents_list=001" in str(request.url)
        return httpx.Response(200, json={"data": {"affected_items": ["001"]}})

    cliente = WazuhResponseClient(base_url="https://wazuh.example:55000", token="tok",
                                  client=_client(handler))
    resultado = cliente.send_active_response("001", "firewall-drop", ["203.0.113.5"], dry_run=False)
    assert resultado["status"] == "OK"
    assert len(llamadas) == 1


def test_wazuh_response_client_error_no_lanza_excepcion():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route to host", request=request)

    cliente = WazuhResponseClient(base_url="https://wazuh.example:55000", token="tok",
                                  client=_client(handler))
    resultado = cliente.send_active_response("001", "firewall-drop", dry_run=False)
    assert resultado["status"] == "ERROR"
