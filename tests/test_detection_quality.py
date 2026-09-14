"""
Pruebas de CALIDAD de detección (Fase 0).

No comprueban que el pipeline corra —eso ya lo cubre test_pipeline.py— sino que
detecte lo que dice detectar y, sobre todo, que **no** detecte lo que no es.
Cada prueba corresponde a un falso positivo real observado en la revisión.
"""
from __future__ import annotations

import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cybersentinel.detection import RulesEngine, AnomalyDetector  # noqa: E402
from cybersentinel.detection.anomaly import severity_from_anomaly  # noqa: E402
from cybersentinel.governance import GovernancePolicy  # noqa: E402
from cybersentinel.ingestion import Normalizer  # noqa: E402
from cybersentinel.pipeline import Pipeline  # noqa: E402
from cybersentinel.schema import SecurityEvent, Severity  # noqa: E402

RULES_DIR = ROOT / "config" / "rules"
BASE = datetime(2025, 3, 10, 12, tzinfo=timezone.utc)


def _event(seconds: int = 0, **kwargs) -> SecurityEvent:
    data = dict(
        event_id="e", timestamp=BASE + timedelta(seconds=seconds),
        source="sysmon", category="process", action="process_create",
    )
    data.update(kwargs)
    return SecurityEvent(**data)


def _engine() -> RulesEngine:
    return RulesEngine.from_directory(RULES_DIR)


# --------------------------- falsos positivos -------------------------------
def test_benign_process_with_nop_flag_does_not_trigger_powershell_rule():
    """`-nop` suelto no es PowerShell ofuscado: la alternativa debe ir agrupada."""
    engine = _engine()
    for cmd in ("chrome.exe --no-nopersist", r"C:\tools\build.exe -nopause"):
        assert engine.evaluate_event(_event(command_line=cmd)) == [], cmd


def test_web_url_mentioning_nmap_does_not_trigger_scan_rule():
    """El normalizador guarda la URL en command_line; las reglas de proceso no deben verla."""
    event = _event(source="web", category="web", command_line="/search?q=nmap+tutorial")
    assert _engine().evaluate_event(event) == []


def test_rdp_from_public_ip_is_not_lateral_movement():
    """Movimiento lateral exige que ambos extremos sean internos."""
    event = _event(source="firewall", category="network", dst_port=3389,
                   src_ip="203.0.113.9", dst_ip="10.0.0.5")
    assert _engine().evaluate_event(event) == []


def test_port_containing_c2_port_digits_is_not_a_match():
    """El operador `in` compara por igualdad: 14444 no es 4444."""
    event = _event(source="firewall", category="network", dst_port=14444,
                   src_ip="10.0.0.5", dst_ip="8.8.8.8")
    assert _engine().evaluate_event(event) == []


# --------------------------- verdaderos positivos ---------------------------
def test_known_attack_commands_still_detected():
    """Endurecer las reglas no debe perder las detecciones reales."""
    engine = _engine()
    cases = {
        "T1059": _event(command_line="powershell.exe -nop -w hidden -enc SQBFAFgA"),
        "T1046": _event(command_line="nmap -sS -p- 10.0.0.0/24"),
        "T1053": _event(command_line="schtasks /create /tn x /tr y"),
        "T1021": _event(source="firewall", category="network", dst_port=3389,
                        src_ip="10.0.0.50", dst_ip="10.0.0.60"),
        "T1048": _event(source="firewall", category="network", bytes_out=524_288_000),
    }
    for technique, event in cases.items():
        hits = engine.evaluate_event(event)
        assert any(h.rule.mitre_technique == technique for h in hits), technique


# ------------------------------ agregación ----------------------------------
def _failed_logins(n: int, step_seconds: int) -> list[SecurityEvent]:
    return [
        _event(i * step_seconds, source="auth", category="authentication",
               action="user_login", outcome="failure", user="ana", src_ip="10.0.0.9")
        for i in range(n)
    ]


def test_single_failed_login_is_not_brute_force():
    """La regla se titula 'fuerza bruta': un solo fallo no puede dispararla."""
    assert _engine().evaluate(_failed_logins(1, 10)) == []


def test_burst_of_failed_logins_raises_one_aggregated_finding():
    """Ocho fallos en 80 s son UN hallazgo de fuerza bruta, no ocho alertas."""
    hits = _engine().evaluate(_failed_logins(8, 10))
    assert len(hits) == 1
    assert hits[0].rule.mitre_technique == "T1110"
    assert hits[0].match_count >= 5
    assert len(hits[0].related_fingerprints) == hits[0].match_count - 1


def test_failed_logins_spread_over_hours_are_not_brute_force():
    """Fuera de la ventana temporal no hay fuerza bruta."""
    assert _engine().evaluate(_failed_logins(8, 20 * 60)) == []


def test_aggregated_rule_groups_by_entity():
    """Fallos repartidos entre cuentas distintas no se suman en un solo ataque."""
    events = []
    for user in ("ana", "carlos", "sofia", "jdoe"):
        events += [
            _event(i * 10, source="auth", category="authentication", action="user_login",
                   outcome="failure", user=user, src_ip="10.0.0.9")
            for i in range(4)
        ]
    assert _engine().evaluate(events) == []


# ------------------------ puntuación de anomalías ---------------------------
def _benign_events(n: int = 120, seed: int = 1) -> list[SecurityEvent]:
    rng = random.Random(seed)
    base = datetime(2025, 3, 10, 8, tzinfo=timezone.utc)
    records = [
        {
            "source": "sysmon",
            "timestamp": (base + timedelta(minutes=rng.randint(0, 600))).isoformat(),
            "action": "process_create",
            "host": rng.choice(["WKS-01", "WKS-02"]),
            "user": rng.choice(["ana", "carlos"]),
            "command_line": f"chrome.exe --tab {rng.randint(1, 99)}",
            "outcome": "success",
        }
        for _ in range(n)
    ]
    return Normalizer().normalize(records)


def test_anomaly_score_is_absolute_not_batch_relative():
    """
    Una normalización min-max por lote garantiza un 1.0 en cualquier lote.
    La escala absoluta debe dejar el máximo de un lote benigno lejos de 1.0.
    """
    events = _benign_events()
    results = AnomalyDetector().fit(events).score(events)
    scores = [r.anomaly_score for r in results]
    assert max(scores) < 0.95
    assert all(0.0 <= s <= 1.0 for s in scores)


def test_same_event_keeps_its_score_across_batches():
    """El score de un evento no puede depender de con quién se le puntúe."""
    events = _benign_events()
    detector = AnomalyDetector().fit(events)
    full = detector.score(events)[0].anomaly_score
    alone = detector.score(events[:1])[0].anomaly_score
    assert abs(full - alone) < 1e-9


def test_anomaly_alone_cannot_be_critical():
    """Una anomalía sin corroborar es una pista: su severidad tiene techo."""
    for score in (0.6, 0.75, 0.99, 1.0):
        assert severity_from_anomaly(score).score <= Severity.MEDIUM.score


def test_suggested_threshold_comes_from_the_baseline():
    """El umbral se deriva de los datos, no de una constante mágica."""
    detector = AnomalyDetector().fit(_benign_events())
    assert detector.suggested_threshold >= 0.5
    assert AnomalyDetector().suggested_threshold == 0.5   # sin entrenar


def test_benign_traffic_produces_no_critical_incident(tmp_path):
    """
    Prueba de regresión del hallazgo principal de la revisión: sobre tráfico
    100% benigno el sistema producía 6 incidentes, 2 de ellos CRITICAL.
    """
    pipeline = Pipeline(rules_dir=RULES_DIR, policy=GovernancePolicy(),
                        audit_path=tmp_path / "audit.jsonl")
    report = pipeline.run_events(_benign_events())

    assert all(
        r.incident.max_severity.score <= Severity.MEDIUM.score for r in report.results
    ), "el tráfico benigno no puede generar incidentes de severidad alta o crítica"
    assert all(r.incident.risk_score < 50 for r in report.results)


def test_attack_chain_is_still_detected(tmp_path):
    """Y el ataque completo debe seguir saliendo, con su cadena de tácticas."""
    sys.path.insert(0, str(ROOT / "data"))
    import generate_sample  # noqa: PLC0415

    sample = tmp_path / "logs.jsonl"
    generate_sample.generate(sample, num_benign=120)
    report = Pipeline(rules_dir=RULES_DIR, policy=GovernancePolicy(),
                      audit_path=tmp_path / "audit.jsonl").run_file(sample)

    top = max(report.results, key=lambda r: r.incident.risk_score)
    tactics = top.incident.tactics
    for expected in ("credential-access", "execution", "persistence",
                     "discovery", "lateral-movement", "command-and-control",
                     "exfiltration"):
        assert expected in tactics, f"falta la fase {expected}: {tactics}"
    assert top.incident.risk_score >= 70
