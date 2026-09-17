"""
Pruebas E2E del ciclo de vida de incidentes y HITL (Fase 10).
"""
import pytest
from starlette.testclient import TestClient
from pathlib import Path

from cybersentinel.api.app import app
from cybersentinel.api.security import Permission, Role

@pytest.fixture
def api_client():
    return TestClient(app)

from cybersentinel.api.security.tokens import TokenSigner

@pytest.fixture
def app_configured(monkeypatch, tmp_path):
    # Setup test env
    monkeypatch.setenv("CS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CS_JWT_SECRET", "f" * 48)
    monkeypatch.setenv("CYBERSENTINEL_ALLOW_PLAINTEXT", "1")
    
    from cybersentinel.api.app import IngestService, SecurityGate, TransportPolicy, app
    from cybersentinel.api.security import SecurityConfig
    from cybersentinel.governance import AuditLog
    
    audit = AuditLog(str(tmp_path / "audit.db"))
    
    config = SecurityConfig(
        identity_db=str(tmp_path / "auth.db"),
        audit_log=audit,
        jwt_secret="f" * 48
    )
    gate = SecurityGate(config)
    gate.store.create_user("analyst-1", "Aaaaa11112222", Role.ANALYST.value)
    gate.store.create_user("collector-1", "Ccccc11112222", Role.COLLECTOR.value)
    
    svc = IngestService(
        db_path=str(tmp_path / "events.db"),
        wal_dir=str(tmp_path / "wal"),
        audit_path=str(tmp_path / "audit.jsonl"),
        enable_llm=True
    )
    app.state.gate = gate
    app.state.service = svc
    app.state.transport = TransportPolicy.from_env()
    
    # Mock pipeline directly on the configured service
    def mock_run_events(eventos):
        from cybersentinel.pipeline import PipelineReport, IncidentResult
        from cybersentinel.detection.hybrid import DetectionEvidence
        from cybersentinel.observability import TraceContext
        
        class MockEvidence(DetectionEvidence):
            @property
            def hybrid_score(self) -> float:
                return 99.0
            @property
            def detection_status(self) -> str:
                return "ANOMALY_ONLY"
                
        res = []
        for e in eventos:
            evidence = MockEvidence(
                run_id="run-1", event_ref=e.fingerprint(), event_id=e.fingerprint(),
                entity="host1", llm_status="none", fallback_used=False
            )
            res.append(IncidentResult(evidence=evidence, narrative="", trace=TraceContext(event_id=e.fingerprint()), recommendations=[]))
        return PipelineReport(total_events=1, total_findings=1, run_id="run-1", results=res)
    
    monkeypatch.setattr(svc.pipeline, "run_events", mock_run_events)
    return app

@pytest.fixture
def api_client(app_configured):
    return TestClient(app_configured, base_url="http://127.0.0.1")

@pytest.fixture
def auth_headers(app_configured):
    token, _ = TokenSigner("f" * 48).issue("analyst-1", Role.ANALYST.value)
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
def collector_headers(app_configured):
    token, _ = TokenSigner("f" * 48).issue("collector-1", Role.COLLECTOR.value)
    return {"Authorization": f"Bearer {token}"}

def test_flujo_completo_incidente_hitl(api_client, auth_headers, collector_headers, app_configured):
    svc = app_configured.state.service
    
    # 2. Ingestar evento
    payload = {
        "events": [
            {"source": "sysmon", "event_id": "e2e-evt-1", "EventID": 1, "Image": "malware.exe"}
        ]
    }
    resp = api_client.post("/api/v1/events", json=payload, headers=collector_headers)
    assert resp.status_code == 202, resp.text
    
    # Procesar la cola explícitamente para el test
    lote = svc.queue.drain(1)
    svc.worker._procesar(lote)
    
    # 3. Listar incidentes
    resp = api_client.get("/api/v1/incidents", headers=auth_headers)
    assert resp.status_code == 200
    incidents = resp.json()["incidents"]
    assert len(incidents) == 1
    inc = incidents[0]
    incident_id = inc["incident_id"]
    assert inc["state"] == "new"
    
    # 4. Leer detalle (verificando labels [OBSERVADO])
    resp = api_client.get(f"/api/v1/incidents/{incident_id}", headers=auth_headers)
    assert resp.status_code == 200
    detalle = resp.json()
    assert "[OBSERVADO]" in detalle["narrative"], "La explicación determinista no incluye las etiquetas"

    # 5. Aplicar decisión HITL: CONFIRM
    triage_payload = {
        "action": "CONFIRM",
        "reason": "Confirmado, es un ataque real."
    }
    resp = api_client.post(f"/api/v1/incidents/{incident_id}/triage", json=triage_payload, headers=auth_headers)
    assert resp.status_code == 201
    
    # Verificamos estado actualizado
    resp = api_client.get(f"/api/v1/incidents/{incident_id}", headers=auth_headers)
    assert resp.json()["state"] == "confirmed"
    
    # 6. Consultar Timeline
    resp = api_client.get(f"/api/v1/incidents/{incident_id}/timeline", headers=auth_headers)
    assert resp.status_code == 200
    timeline = resp.json()
    assert len(timeline) >= 2  # Creación y Triage
    
    triage_event = [t for t in timeline if t["kind"] == "state"][-1]
    assert "new → confirmed" in triage_event["text"]
    
    # 7. Validar AuditLog
    gate = app_configured.state.gate
    actions = [e.action for e in gate.audit.entries]
    assert "analyst_triage" in actions
