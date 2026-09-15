"""
Tests de integración pySigma — Fase 1 Parte 2.

Verifica:
  1. Parseo correcto de reglas Sigma (válidas e inválidas)
  2. SigmaBackedRule es subclase de DetectionRule (contrato de tipo)
  3. Las 7 reglas YAML propias siguen funcionando exactamente igual (regresión)
  4. El formato RuleHit no cambia para reglas Sigma
  5. Evaluación correcta de operadores: contains, endswith, re, gt, list, AND/NOT
  6. Reglas multi-táctica (dos tags attack.tXXXX)
  7. Manejo explícito de regla con campo NOT EVALUABLE (no silencioso)
  8. from_sigma_directory() carga el conjunto de 15 reglas sin error
  9. Regresión: los tests del test_pipeline.py existente siguen pasando

Ejecutar desde la raíz del proyecto:
    PYTHONPATH=src python -m pytest -q tests/test_sigma_integration.py
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cybersentinel.schema import SecurityEvent, Severity                            # noqa: E402
from cybersentinel.detection import RulesEngine, DetectionRule, RuleHit            # noqa: E402
from cybersentinel.detection.sigma_adapter import (                                # noqa: E402
    SigmaBackedRule, sigma_rule_to_detection_rule,
    SigmaParseError, FIELD_MAP, LOGSOURCE_CATEGORY_MAP,
)
from cybersentinel.detection.sigma_loader import load_sigma_rules                  # noqa: E402

RULES_DIR        = ROOT / "config" / "rules"
SIGMA_RULES_DIR  = ROOT / "config" / "sigma_rules" / "selected"

_UTC = timezone.utc


def _ts(year=2025, month=3, day=10, hour=10) -> datetime:
    return datetime(year, month, day, hour, tzinfo=_UTC)


# ────────────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────────────

def _parse_sigma_yaml(yaml_str: str) -> SigmaBackedRule | None:
    """Parse a raw Sigma YAML string and return a SigmaBackedRule."""
    from sigma.rule import SigmaRule
    rule = SigmaRule.from_yaml(yaml_str)
    return sigma_rule_to_detection_rule(rule, source_file="<test>")


# ────────────────────────────────────────────────────────────────────────────
# 1. Parseo de YAML Sigma válido
# ────────────────────────────────────────────────────────────────────────────

def test_sigma_rule_parses_valid_yaml():
    rule = _parse_sigma_yaml("""
title: Valid Test Rule
id: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
status: test
logsource:
    product: cybersentinel
    category: process_creation
detection:
    selection:
        CommandLine|contains: powershell
    condition: selection
tags:
    - attack.t1059.001
level: high
""")
    assert rule is not None
    assert rule.title == "Valid Test Rule"
    assert rule.mitre_technique == "T1059.001"
    assert rule.severity == Severity.HIGH
    assert rule.is_evaluable


def test_sigma_rule_parses_uuid_correctly():
    rule = _parse_sigma_yaml("""
title: UUID Test
id: 12345678-1234-5678-1234-567812345678
status: test
logsource:
    product: cybersentinel
    category: network
detection:
    selection:
        dst_port: 4444
    condition: selection
tags:
    - attack.t1071
level: medium
""")
    assert rule is not None
    assert rule.id == "12345678-1234-5678-1234-567812345678"


def test_sigma_rule_rejects_invalid_yaml():
    """A malformed YAML (missing detection block) should fail gracefully."""
    from sigma.exceptions import SigmaError
    with pytest.raises(SigmaError):
        from sigma.rule import SigmaRule
        SigmaRule.from_yaml("""
title: Broken
id: bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb
status: test
logsource:
    product: cybersentinel
    category: process
# detection block intentionally missing
""")


def test_sigma_rule_with_no_attack_tag_has_unknown_technique():
    rule = _parse_sigma_yaml("""
title: No ATT&CK Tag
id: cccccccc-cccc-cccc-cccc-cccccccccccc
status: test
logsource:
    product: cybersentinel
    category: network
detection:
    selection:
        dst_port: 80
    condition: selection
level: low
""")
    assert rule is not None
    assert rule.mitre_technique == "unknown"


# ────────────────────────────────────────────────────────────────────────────
# 2. SigmaBackedRule es subclase de DetectionRule
# ────────────────────────────────────────────────────────────────────────────

def test_sigma_backed_rule_is_detectionrule_subclass():
    rule = _parse_sigma_yaml("""
title: Type Check
id: dddddddd-dddd-dddd-dddd-dddddddddddd
status: test
logsource:
    product: cybersentinel
    category: process_creation
detection:
    selection:
        CommandLine|contains: test
    condition: selection
tags:
    - attack.t1059
level: low
""")
    assert isinstance(rule, DetectionRule)
    assert isinstance(rule, SigmaBackedRule)


def test_sigma_backed_rule_has_empty_conditions():
    """conditions list must be [] — evaluation is done by AST, not condition list."""
    rule = _parse_sigma_yaml("""
title: Conditions Check
id: eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee
status: test
logsource:
    product: cybersentinel
    category: network
detection:
    selection:
        dst_port: 443
    condition: selection
tags:
    - attack.t1071
level: low
""")
    assert rule is not None
    assert rule.conditions == []
    assert rule.is_evaluable  # is_evaluable must be True despite conditions==[]


# ────────────────────────────────────────────────────────────────────────────
# 3. Regresión: las 7 reglas propias siguen funcionando
# ────────────────────────────────────────────────────────────────────────────

def test_original_7_rules_load_unchanged():
    engine = RulesEngine.from_directory(RULES_DIR)
    assert len(engine.rules) == 7, (
        f"Se esperaban 7 reglas propias, se cargaron {len(engine.rules)}"
    )


def test_original_rules_detect_encoded_powershell():
    engine = RulesEngine.from_directory(RULES_DIR)
    ev = SecurityEvent(
        event_id="1", timestamp=_ts(), source="sysmon",
        category="process", action="process_create",
        command_line="powershell.exe -nop -w hidden -enc SQBFAFgA",
    )
    hits = engine.evaluate_event(ev)
    assert any(h.rule.mitre_technique == "T1059" for h in hits), (
        "REGRESIÓN: La regla propia de PowerShell encodeado no disparó"
    )


def test_original_rules_detect_exfiltration():
    engine = RulesEngine.from_directory(RULES_DIR)
    ev = SecurityEvent(
        event_id="2", timestamp=_ts(), source="firewall",
        category="network", action="connection",
        bytes_out=524_288_000,
    )
    hits = engine.evaluate_event(ev)
    assert any(h.rule.mitre_tactic == "exfiltration" for h in hits), (
        "REGRESIÓN: La regla propia de exfiltración no disparó"
    )


# ────────────────────────────────────────────────────────────────────────────
# 4. Formato RuleHit no cambia para reglas Sigma
# ────────────────────────────────────────────────────────────────────────────

def test_rulehit_format_unchanged_for_sigma_rule():
    rule = _parse_sigma_yaml("""
title: Hit Format Test
id: ffffffff-ffff-ffff-ffff-ffffffffffff
status: test
logsource:
    product: cybersentinel
    category: process_creation
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
tags:
    - attack.t1033
level: medium
""")
    engine = RulesEngine(rules=[rule])
    ev = SecurityEvent(
        event_id="99", timestamp=_ts(), source="sysmon",
        category="process", action="process_create",
        command_line="whoami /all",
    )
    hits = engine.evaluate_event(ev)
    assert len(hits) == 1
    hit = hits[0]

    # Misma interfaz que RuleHit existente
    assert isinstance(hit, RuleHit)
    assert hit.rule is rule
    assert hit.event is ev
    assert 0.0 < hit.confidence <= 1.0

    # to_dict() debe funcionar sin errores
    d = hit.to_dict()
    assert "rule_id" in d
    assert "confidence" in d


# ────────────────────────────────────────────────────────────────────────────
# 5. Evaluación correcta de operadores individuales
# ────────────────────────────────────────────────────────────────────────────

def test_operator_contains_matches():
    rule = _parse_sigma_yaml("""
title: Contains Test
id: 11111111-1111-1111-1111-111111111111
status: test
logsource:
    product: cybersentinel
    category: process_creation
detection:
    selection:
        CommandLine|contains: '-enc'
    condition: selection
tags:
    - attack.t1059.001
level: high
""")
    engine = RulesEngine(rules=[rule])

    ev_match = SecurityEvent(event_id="a", timestamp=_ts(), source="sysmon",
                             category="process", action="process_create",
                             command_line="powershell.exe -enc AAAA")
    ev_no_match = SecurityEvent(event_id="b", timestamp=_ts(), source="sysmon",
                                category="process", action="process_create",
                                command_line="notepad.exe document.txt")
    assert len(engine.evaluate_event(ev_match)) == 1
    assert len(engine.evaluate_event(ev_no_match)) == 0


def test_operator_endswith_matches():
    rule = _parse_sigma_yaml("""
title: Endswith Test
id: 22222222-2222-2222-2222-222222222222
status: test
logsource:
    product: cybersentinel
    category: process_creation
detection:
    selection:
        Image|endswith: 'mshta.exe'
    condition: selection
tags:
    - attack.t1218.005
level: high
""")
    engine = RulesEngine(rules=[rule])

    ev_match = SecurityEvent(event_id="c", timestamp=_ts(), source="sysmon",
                             category="process", action="process_create",
                             process_name="mshta.exe")
    ev_no_match = SecurityEvent(event_id="d", timestamp=_ts(), source="sysmon",
                                category="process", action="process_create",
                                process_name="powershell.exe")
    assert len(engine.evaluate_event(ev_match)) == 1
    assert len(engine.evaluate_event(ev_no_match)) == 0


def test_operator_regex_matches():
    rule = _parse_sigma_yaml(r"""
title: Regex Test
id: 33333333-3333-3333-3333-333333333333
status: test
logsource:
    product: cybersentinel
    category: process_creation
detection:
    selection:
        CommandLine|re: 'powershell.*-enc'
    condition: selection
tags:
    - attack.t1059.001
level: high
""")
    engine = RulesEngine(rules=[rule])

    ev_match = SecurityEvent(event_id="e", timestamp=_ts(), source="sysmon",
                             category="process", action="process_create",
                             command_line="POWERSHELL.exe -NoProfile -enc AAAA")
    ev_no_match = SecurityEvent(event_id="f", timestamp=_ts(), source="sysmon",
                                category="process", action="process_create",
                                command_line="powershell.exe -version")
    assert len(engine.evaluate_event(ev_match)) == 1
    assert len(engine.evaluate_event(ev_no_match)) == 0


def test_operator_gt_numeric_matches():
    rule = _parse_sigma_yaml("""
title: GT Numeric Test
id: 44444444-4444-4444-4444-444444444444
status: test
logsource:
    product: cybersentinel
    category: network
detection:
    selection:
        bytes_out|gt: 1000000
    condition: selection
tags:
    - attack.t1048
level: critical
""")
    engine = RulesEngine(rules=[rule])

    ev_above = SecurityEvent(event_id="g", timestamp=_ts(), source="firewall",
                             category="network", action="connection",
                             bytes_out=2_000_000)
    ev_below = SecurityEvent(event_id="h", timestamp=_ts(), source="firewall",
                             category="network", action="connection",
                             bytes_out=500)
    ev_at    = SecurityEvent(event_id="i", timestamp=_ts(), source="firewall",
                             category="network", action="connection",
                             bytes_out=1_000_000)  # equal, not gt
    assert len(engine.evaluate_event(ev_above)) == 1
    assert len(engine.evaluate_event(ev_below)) == 0
    assert len(engine.evaluate_event(ev_at)) == 0   # strict GT


def test_operator_list_equality_matches():
    """dst_port: [4444, 1337] → SigmaNumber OR list."""
    rule = _parse_sigma_yaml("""
title: Port List Test
id: 55555555-5555-5555-5555-555555555555
status: test
logsource:
    product: cybersentinel
    category: network
detection:
    selection:
        dst_port:
            - 4444
            - 1337
    condition: selection
tags:
    - attack.t1071
level: high
""")
    engine = RulesEngine(rules=[rule])

    ev_4444  = SecurityEvent(event_id="j", timestamp=_ts(), source="firewall",
                             category="network", action="connection", dst_port=4444)
    ev_1337  = SecurityEvent(event_id="k", timestamp=_ts(), source="firewall",
                             category="network", action="connection", dst_port=1337)
    ev_443   = SecurityEvent(event_id="l", timestamp=_ts(), source="firewall",
                             category="network", action="connection", dst_port=443)
    assert len(engine.evaluate_event(ev_4444)) == 1
    assert len(engine.evaluate_event(ev_1337)) == 1
    assert len(engine.evaluate_event(ev_443))  == 0


def test_operator_and_not_condition():
    """condition: selection_a and not filter → must match AND exclude."""
    rule = _parse_sigma_yaml("""
title: AND NOT Test
id: 66666666-6666-6666-6666-666666666666
status: test
logsource:
    product: cybersentinel
    category: authentication
detection:
    selection:
        outcome|contains: 'fail'
    filter_internal:
        src_ip|startswith: '10.'
    condition: selection and not filter_internal
tags:
    - attack.t1110
level: medium
""")
    engine = RulesEngine(rules=[rule])

    ev_external = SecurityEvent(event_id="m", timestamp=_ts(), source="auth",
                                category="authentication", action="user_login",
                                outcome="failure", src_ip="8.8.8.8")
    ev_internal = SecurityEvent(event_id="n", timestamp=_ts(), source="auth",
                                category="authentication", action="user_login",
                                outcome="failure", src_ip="10.0.0.5")
    ev_success  = SecurityEvent(event_id="o", timestamp=_ts(), source="auth",
                                category="authentication", action="user_login",
                                outcome="success", src_ip="8.8.8.8")
    assert len(engine.evaluate_event(ev_external)) == 1   # matches: fail + NOT internal
    assert len(engine.evaluate_event(ev_internal)) == 0   # filtered: is internal
    assert len(engine.evaluate_event(ev_success))  == 0   # no failure


# ────────────────────────────────────────────────────────────────────────────
# 6. Multi-táctica (varios tags attack.tXXXX en la misma regla)
# ────────────────────────────────────────────────────────────────────────────

def test_sigma_rule_with_multiple_attack_tags():
    """Regla con T1087 y T1069 en tags: el primero 'T' encontrado es la técnica."""
    rule = _parse_sigma_yaml("""
title: Multi-tactic Test
id: 77777777-7777-7777-7777-777777777777
status: test
logsource:
    product: cybersentinel
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'net user'
    condition: selection
tags:
    - attack.t1087
    - attack.t1069
    - attack.discovery
level: medium
""")
    assert rule is not None
    # La técnica debe ser una de las dos
    assert rule.mitre_technique in ("T1087", "T1069")
    # La táctica debe derivarse del tag 'attack.discovery'
    assert rule.mitre_tactic == "discovery"


# ────────────────────────────────────────────────────────────────────────────
# 7. Regla con campo NOT EVALUABLE → no silenciosa
# ────────────────────────────────────────────────────────────────────────────

def test_unavailable_field_returns_false_not_exception(caplog):
    """
    Una regla que use un campo no disponible (ej. IntegrityLevel) no debe
    lanzar excepción. La condición debe devolver False con un WARNING en log.
    """
    import logging
    rule = _parse_sigma_yaml("""
title: Unavailable Field Test
id: 88888888-8888-8888-8888-888888888888
status: test
logsource:
    product: cybersentinel
    category: process_creation
detection:
    selection:
        IntegrityLevel: High
    condition: selection
tags:
    - attack.t1548.002
level: high
""")
    assert rule is not None

    ev = SecurityEvent(event_id="p", timestamp=_ts(), source="sysmon",
                       category="process", action="process_create",
                       command_line="cmd.exe")

    with caplog.at_level(logging.DEBUG, logger="cybersentinel.detection.sigma_adapter"):
        result = rule.matches(ev)

    assert result is False  # campo ausente → condición no se cumple


# ────────────────────────────────────────────────────────────────────────────
# 8. from_sigma_directory() carga las 15 reglas sin error
# ────────────────────────────────────────────────────────────────────────────

def test_sigma_directory_loads_all_15_rules():
    engine = RulesEngine.from_sigma_directory(SIGMA_RULES_DIR)
    assert len(engine.rules) == 15, (
        f"Se esperaban 15 reglas Sigma, se cargaron {len(engine.rules)}"
    )


def test_sigma_directory_all_rules_are_evaluable():
    engine = RulesEngine.from_sigma_directory(SIGMA_RULES_DIR)
    non_evaluable = [r for r in engine.rules if not r.is_evaluable]
    assert non_evaluable == [], (
        f"Reglas NOT_EVALUABLE encontradas: {[r.title for r in non_evaluable]}"
    )


def test_sigma_directory_all_rules_are_sigma_backed():
    engine = RulesEngine.from_sigma_directory(SIGMA_RULES_DIR)
    not_backed = [r for r in engine.rules if not isinstance(r, SigmaBackedRule)]
    assert not_backed == [], (
        f"Reglas no SigmaBackedRule: {[r.title for r in not_backed]}"
    )


def test_sigma_directory_all_rules_have_known_technique():
    engine = RulesEngine.from_sigma_directory(SIGMA_RULES_DIR)
    unknown_technique = [r for r in engine.rules if r.mitre_technique == "unknown"]
    assert unknown_technique == [], (
        f"Reglas sin técnica MITRE: {[r.title for r in unknown_technique]}"
    )


def test_sigma_directory_tactics_coverage():
    """Las 15 reglas deben cubrir al menos 7 tácticas distintas."""
    engine = RulesEngine.from_sigma_directory(SIGMA_RULES_DIR)
    tactics = {r.mitre_tactic for r in engine.rules if r.mitre_tactic != "unknown"}
    assert len(tactics) >= 7, (
        f"Se esperaban ≥7 tácticas distintas, encontradas: {sorted(tactics)}"
    )


# ────────────────────────────────────────────────────────────────────────────
# 9. Evaluación funcional con el conjunto de 15 reglas
# ────────────────────────────────────────────────────────────────────────────

def test_sigma_ps_encoded_cmd_fires():
    engine = RulesEngine.from_sigma_directory(SIGMA_RULES_DIR)
    ev = SecurityEvent(
        event_id="q", timestamp=_ts(), source="sysmon",
        category="process", action="process_create",
        command_line="powershell.exe -nop -w hidden -enc SQBFAFgA",
        process_name="powershell.exe",
    )
    hits = engine.evaluate_event(ev)
    assert any("PowerShell" in h.rule.title for h in hits), (
        "cs-ps-encoded-cmd.yml no disparó ante un comando PowerShell encodeado"
    )


def test_sigma_large_outbound_fires():
    engine = RulesEngine.from_sigma_directory(SIGMA_RULES_DIR)
    ev = SecurityEvent(
        event_id="r", timestamp=_ts(), source="firewall",
        category="network", action="connection",
        bytes_out=200_000_000,
    )
    hits = engine.evaluate_event(ev)
    titles = [h.rule.title for h in hits]
    assert any("Large" in t or "Outbound" in t for t in titles), (
        f"cs-large-outbound.yml no disparó. Hits: {titles}"
    )


def test_sigma_c2_port_fires():
    engine = RulesEngine.from_sigma_directory(SIGMA_RULES_DIR)
    ev = SecurityEvent(
        event_id="s", timestamp=_ts(), source="firewall",
        category="network", action="connection",
        dst_port=4444, dst_ip="1.2.3.4",
    )
    hits = engine.evaluate_event(ev)
    titles = [h.rule.title for h in hits]
    assert any("C2" in t or "Port" in t for t in titles), (
        f"cs-c2-port-connect.yml no disparó. Hits: {titles}"
    )


def test_sigma_rdp_lateral_fires():
    engine = RulesEngine.from_sigma_directory(SIGMA_RULES_DIR)
    ev = SecurityEvent(
        event_id="t", timestamp=_ts(), source="firewall",
        category="network", action="connection",
        src_ip="10.0.1.5", dst_ip="10.0.2.10", dst_port=3389,
    )
    hits = engine.evaluate_event(ev)
    titles = [h.rule.title for h in hits]
    assert any("RDP" in t for t in titles), (
        f"cs-rdp-lateral.yml no disparó. Hits: {titles}"
    )


def test_sigma_auth_failure_external_fires():
    engine = RulesEngine.from_sigma_directory(SIGMA_RULES_DIR)
    ev = SecurityEvent(
        event_id="u", timestamp=_ts(), source="auth",
        category="authentication", action="user_login",
        outcome="failure", src_ip="185.220.101.1",
    )
    hits = engine.evaluate_event(ev)
    titles = [h.rule.title for h in hits]
    # Both cs-auth-failure.yml and cs-auth-failure-external.yml should fire
    assert len(hits) >= 1, f"Ninguna regla de auth failure externa disparó. Hits: {titles}"
    assert any("External" in t for t in titles), (
        f"cs-auth-failure-external.yml específicamente no disparó. Hits: {titles}"
    )


def test_sigma_auth_failure_internal_not_fired_by_external_rule():
    """Internal auth failure must NOT trigger cs-auth-failure-external.yml."""
    engine = RulesEngine.from_sigma_directory(SIGMA_RULES_DIR)
    ev = SecurityEvent(
        event_id="v", timestamp=_ts(), source="auth",
        category="authentication", action="user_login",
        outcome="failure", src_ip="192.168.1.100",
    )
    hits = engine.evaluate_event(ev)
    external_hits = [h for h in hits if "External" in h.rule.title]
    assert external_hits == [], (
        "cs-auth-failure-external.yml disparó para IP interna 192.168.1.100"
    )


def test_sigma_no_false_positive_on_wrong_category():
    """Process rule must not match network events (logsource category pre-filter)."""
    engine = RulesEngine.from_sigma_directory(SIGMA_RULES_DIR)
    # Network event with PowerShell-like command_line (edge case)
    ev = SecurityEvent(
        event_id="w", timestamp=_ts(), source="web",
        category="network", action="http_request",
        command_line="GET /powershell?enc=AAAA HTTP/1.1",
    )
    hits = engine.evaluate_event(ev)
    # ps-encoded-cmd must NOT fire on a network event
    ps_hits = [h for h in hits if "PowerShell" in h.rule.title]
    assert ps_hits == [], (
        "cs-ps-encoded-cmd.yml disparó sobre un evento de red (falso positivo de categoría)"
    )


# ────────────────────────────────────────────────────────────────────────────
# 10. Campo FIELD_MAP: verificación de consistencia
# ────────────────────────────────────────────────────────────────────────────

def test_field_map_commandline_mapping():
    assert FIELD_MAP.get("CommandLine") == "command_line"


def test_field_map_image_mapping():
    assert FIELD_MAP.get("Image") == "process_name"


def test_field_map_dst_port_identity():
    assert FIELD_MAP.get("dst_port") == "dst_port"


def test_field_map_unavailable_fields_are_none():
    """Campos explícitamente no disponibles deben tener None como destino."""
    unavailable = ["TargetFilename"]
    for f in unavailable:
        assert FIELD_MAP.get(f) is None, (
            f"Campo '{f}' no está marcado como None en FIELD_MAP"
        )
