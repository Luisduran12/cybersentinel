import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cybersentinel.schema import SecurityEvent, Severity
from cybersentinel.detection.rules_engine import DetectionRule, RuleHit
from cybersentinel.detection.temporal import SequenceRule, TemporalCorrelator

_UTC = timezone.utc

def _ts(m: int) -> datetime:
    return datetime(2026, 9, 15, 10, m, tzinfo=_UTC)

def test_temporal_correlation_sequence():
    rule1 = DetectionRule(id="1", title="Exec", description="", severity=Severity.MEDIUM, mitre_technique="T1059", mitre_tactic="execution")
    rule2 = DetectionRule(id="2", title="C2", description="", severity=Severity.HIGH, mitre_technique="T1071", mitre_tactic="command-and-control")

    ev1 = SecurityEvent(event_id="A", timestamp=_ts(1), source="sysmon", category="process", action="create", host="HOST1")
    ev2 = SecurityEvent(event_id="B", timestamp=_ts(2), source="net", category="network", action="conn", host="HOST1")
    ev3 = SecurityEvent(event_id="C", timestamp=_ts(10), source="net", category="network", action="conn", host="HOST1")

    hit1 = RuleHit(rule=rule1, event=ev1, confidence=0.5)
    hit2 = RuleHit(rule=rule2, event=ev2, confidence=0.8)
    hit3 = RuleHit(rule=rule2, event=ev3, confidence=0.8)

    seq_rule = SequenceRule(name="Exec -> C2", techniques_sequence=["T1059", "T1071"], window_minutes=5, group_by=["host"])
    correlator = TemporalCorrelator(rules=[seq_rule])

    correlator.observe_batch([hit1, hit2, hit3])
    incidents = correlator.correlate()

    assert len(incidents) == 1
    assert incidents[0].name == "Exec -> C2"
    assert len(incidents[0].hits) == 2
    assert incidents[0].hits[0].event.event_id == "A"
    assert incidents[0].hits[1].event.event_id == "B"

def test_temporal_correlation_window_timeout():
    rule1 = DetectionRule(id="1", title="Exec", description="", severity=Severity.MEDIUM, mitre_technique="T1059", mitre_tactic="execution")
    rule2 = DetectionRule(id="2", title="C2", description="", severity=Severity.HIGH, mitre_technique="T1071", mitre_tactic="command-and-control")

    ev1 = SecurityEvent(event_id="A", timestamp=_ts(1), source="sysmon", category="process", action="create", host="HOST1")
    ev2 = SecurityEvent(event_id="B", timestamp=_ts(10), source="net", category="network", action="conn", host="HOST1") # 9 mins later

    hit1 = RuleHit(rule=rule1, event=ev1, confidence=0.5)
    hit2 = RuleHit(rule=rule2, event=ev2, confidence=0.8)

    seq_rule = SequenceRule(name="Exec -> C2", techniques_sequence=["T1059", "T1071"], window_minutes=5, group_by=["host"])
    correlator = TemporalCorrelator(rules=[seq_rule])

    correlator.observe_batch([hit1, hit2])
    incidents = correlator.correlate()

    assert len(incidents) == 0, "No debe haber correlación porque pasó la ventana de tiempo"
