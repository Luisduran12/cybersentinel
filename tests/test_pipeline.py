"""
Pruebas unitarias de CyberSentinel.

Ejecutar desde la raíz del proyecto:
    PYTHONPATH=src python -m pytest -q
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cybersentinel.schema import SecurityEvent, Severity  # noqa: E402
from cybersentinel.ingestion import Normalizer  # noqa: E402
from cybersentinel.detection import RulesEngine, AnomalyDetector  # noqa: E402
from cybersentinel.correlation import Correlator  # noqa: E402
from cybersentinel.correlation import mitre  # noqa: E402
from cybersentinel.governance import GovernancePolicy, AuditLog, ProposedAction, Decision  # noqa: E402
from cybersentinel.pipeline import Pipeline  # noqa: E402

RULES_DIR = ROOT / "config" / "rules"


# --------------------------- schema / ingesta -------------------------------
def test_normalizer_auth_event():
    norm = Normalizer()
    rec = {"source": "auth", "timestamp": "2025-03-10T10:00:00",
           "user": "admin", "src_ip": "1.2.3.4", "outcome": "failure"}
    ev = norm.normalize_record(rec)
    assert ev.category == "authentication"
    assert ev.user == "admin"
    assert ev.outcome == "failure"


def test_event_fingerprint_stable():
    ev = SecurityEvent(event_id="x", timestamp=datetime(2025, 3, 10, tzinfo=timezone.utc),
                       source="sysmon", category="process", action="process_create",
                       command_line="powershell -enc AAAA")
    assert ev.fingerprint() == ev.fingerprint()
    assert len(ev.fingerprint()) == 16


# ------------------------------ detección -----------------------------------
def test_rules_engine_detects_encoded_powershell():
    engine = RulesEngine.from_directory(RULES_DIR)
    ev = SecurityEvent(event_id="1", timestamp=datetime(2025, 3, 10, tzinfo=timezone.utc),
                       source="sysmon", category="process", action="process_create",
                       command_line="powershell.exe -nop -w hidden -enc SQBFAFgA")
    hits = engine.evaluate_event(ev)
    assert any(h.rule.mitre_technique == "T1059" for h in hits)


def test_rules_engine_detects_exfiltration():
    engine = RulesEngine.from_directory(RULES_DIR)
    ev = SecurityEvent(event_id="2", timestamp=datetime(2025, 3, 10, tzinfo=timezone.utc),
                       source="firewall", category="network", action="connection",
                       bytes_out=524_288_000)
    hits = engine.evaluate_event(ev)
    assert any(h.rule.mitre_tactic == "exfiltration" for h in hits)


def test_anomaly_detector_flags_outlier():
    base = datetime(2025, 3, 10, 12, tzinfo=timezone.utc)
    normal = [
        SecurityEvent(event_id=str(i), timestamp=base + timedelta(minutes=i),
                      source="sysmon", category="process", action="process_create",
                      command_line="chrome.exe --tab", dst_port=443, bytes_out=1000)
        for i in range(30)
    ]
    outlier = SecurityEvent(event_id="out", timestamp=base.replace(hour=3),
                            source="firewall", category="network", action="connection",
                            command_line="x" * 500, dst_port=4444, bytes_out=999_999_999)
    events = normal + [outlier]
    det = AnomalyDetector(contamination=0.05).fit(events)
    results = det.score(events)
    scored = {r.event.event_id: r for r in results}
    assert scored["out"].anomaly_score >= scored["0"].anomaly_score


# ------------------------- correlación / MITRE ------------------------------
def test_mitre_next_tactics():
    nxt = mitre.next_tactics("credential-access", k=2)
    assert "discovery" in nxt


def test_correlator_builds_incident_and_prediction():
    engine = RulesEngine.from_directory(RULES_DIR)
    norm = Normalizer()
    recs = [
        {"source": "auth", "timestamp": "2025-03-10T10:00:00", "user": "admin",
         "host": "SRV", "src_ip": "9.9.9.9", "outcome": "failure"},
        {"source": "sysmon", "timestamp": "2025-03-10T10:05:00", "host": "SRV",
         "user": "admin", "command_line": "powershell.exe -enc AAAA"},
        {"source": "sysmon", "timestamp": "2025-03-10T10:08:00", "host": "SRV",
         "user": "admin", "command_line": "schtasks /create /tn x /tr y"},
    ]
    events = norm.normalize(recs)
    hits = engine.evaluate(events)
    correlator = Correlator()
    findings = correlator.build_findings(hits, [], 0.6)
    incidents = correlator.correlate(findings)
    assert len(incidents) >= 1
    inc = incidents[0]
    assert inc.prediction is not None
    assert inc.risk_score > 0


# ------------------------------ gobernanza ----------------------------------
def test_policy_prohibits_destructive_action():
    pol = GovernancePolicy()
    v = pol.evaluate(ProposedAction("hack_back", "attacker", "revancha", "INC-1"))
    assert v.decision == Decision.PROHIBITED


def test_policy_requires_approval_for_isolation():
    pol = GovernancePolicy()
    v = pol.evaluate(ProposedAction("isolate_host", "SRV", "contencion", "INC-1"))
    assert v.decision == Decision.REQUIRES_APPROVAL


def test_policy_unknown_defaults_to_approval():
    pol = GovernancePolicy()
    v = pol.evaluate(ProposedAction("some_new_action", "SRV", "x", "INC-1"))
    assert v.decision == Decision.REQUIRES_APPROVAL


def test_audit_chain_integrity(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.record("agent", "test", {"a": 1})
    log.record("agent", "test", {"b": 2})
    ok, bad = log.verify()
    assert ok and bad is None


def test_audit_detects_tampering(tmp_path):
    p = tmp_path / "audit.jsonl"
    log = AuditLog(p)
    log.record("agent", "test", {"a": 1})
    log.record("agent", "test", {"b": 2})
    # Manipular la primera entrada en memoria
    log.entries[0].detail = {"a": 999}
    ok, bad = log.verify()
    assert not ok and bad == 0


# ------------------------------ pipeline ------------------------------------
def test_full_pipeline_end_to_end(tmp_path):
    # Generar datos sintéticos
    sys.path.insert(0, str(ROOT / "data"))
    import generate_sample  # noqa
    sample = tmp_path / "logs.jsonl"
    generate_sample.generate(sample, num_benign=60)

    pipeline = Pipeline(
        rules_dir=RULES_DIR,
        policy=GovernancePolicy(),
        audit_path=tmp_path / "audit.jsonl",
    )
    report = pipeline.run_file(sample)
    assert report.total_events > 0
    assert len(report.results) >= 1
    assert report.audit_integrity is True
    # Debe existir al menos un incidente con predicción de kill-chain
    assert any(r.incident.prediction is not None for r in report.results)
    # Ninguna acción prohibida debe quedar como 'allowed'
    for r in report.results:
        for rec in r.recommendations:
            if rec.verdict.action.action_type in ("hack_back", "deploy_exploit"):
                assert rec.verdict.decision == Decision.PROHIBITED
