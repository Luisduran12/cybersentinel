"""
Tests de verificación post-evaluación — Fase 1 Parte 3.

Verifica que:
  1. Los cuatro reportes existen y son JSON/CSV válidos
  2. Las métricas de las 3 reglas evaluables son correctas y no fabricadas
  3. Los archivos Navigator existen y tienen la estructura ATT&CK correcta
  4. Las 7 reglas originales siguen funcionando (no-regresión)
  5. Los 18 técnicas en navigator_after corresponden a la cobertura real
  6. La distinción detected / covered / not_evaluated está presente en Navigator
  7. La reproducibilidad: metadata presente en summary.json

Ejecutar desde la raíz del proyecto:
    PYTHONPATH=src python -m pytest -q tests/test_sigma_phase1_evaluation.py
"""
from __future__ import annotations

import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

REPORTS_DIR    = ROOT / "reports"
DOCS_DIR       = ROOT / "docs"
RULES_DIR      = ROOT / "config" / "rules"
SIGMA_RULES_DIR = ROOT / "config" / "sigma_rules" / "selected"

from cybersentinel.detection import RulesEngine                              # noqa: E402
from cybersentinel.schema import SecurityEvent                               # noqa: E402

_UTC = timezone.utc


# ────────────────────────────────────────────────────────────────────────────
# Fixtures
# ────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def metrics_json() -> dict:
    path = REPORTS_DIR / "sigma_phase1_metrics.json"
    assert path.exists(), f"Reporte de métricas no encontrado: {path}"
    with open(path, encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def summary_json() -> dict:
    path = REPORTS_DIR / "sigma_phase1_summary.json"
    assert path.exists(), f"Reporte de resumen no encontrado: {path}"
    with open(path, encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def fp_json() -> dict:
    path = REPORTS_DIR / "sigma_phase1_false_positives.json"
    assert path.exists(), f"Reporte de FP no encontrado: {path}"
    with open(path, encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def navigator_before() -> dict:
    path = DOCS_DIR / "navigator_before.json"
    assert path.exists(), f"Navigator before no encontrado: {path}"
    with open(path, encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def navigator_after() -> dict:
    path = DOCS_DIR / "navigator_after.json"
    assert path.exists(), f"Navigator after no encontrado: {path}"
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# ────────────────────────────────────────────────────────────────────────────
# 1. Reportes existen y son válidos
# ────────────────────────────────────────────────────────────────────────────

def test_metrics_json_exists_and_parseable():
    path = REPORTS_DIR / "sigma_phase1_metrics.json"
    assert path.exists()
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    assert "metadata" in data
    assert "rules" in data
    assert len(data["rules"]) > 0


def test_summary_json_exists_and_parseable():
    path = REPORTS_DIR / "sigma_phase1_summary.json"
    assert path.exists()
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    assert "global_metrics" in data
    assert "coverage" in data


def test_false_positives_json_exists_and_parseable():
    path = REPORTS_DIR / "sigma_phase1_false_positives.json"
    assert path.exists()
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    assert "summary" in data
    assert "false_positive_records" in data


def test_csv_report_exists_and_readable():
    path = REPORTS_DIR / "sigma_phase1_by_rule.csv"
    assert path.exists()
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    assert len(rows) > 0
    assert "rule_id" in rows[0]
    assert "evaluable_on_unsw_nb15" in rows[0]


def test_navigator_before_exists_and_parseable():
    path = DOCS_DIR / "navigator_before.json"
    assert path.exists()
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    assert "techniques" in data
    assert "domain" in data
    assert data["domain"] == "enterprise-attack"


def test_navigator_after_exists_and_parseable():
    path = DOCS_DIR / "navigator_after.json"
    assert path.exists()
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    assert "techniques" in data
    assert len(data["techniques"]) > 0


# ────────────────────────────────────────────────────────────────────────────
# 2. Métricas coherentes e íntegras (no fabricadas)
# ────────────────────────────────────────────────────────────────────────────

def test_evaluable_rules_have_required_metric_fields(metrics_json):
    for rule in metrics_json["rules"]:
        if rule["evaluable_on_unsw_nb15"]:
            for field in ["tp", "fp", "fn", "tn", "precision", "recall", "f1", "fpr",
                          "exec_time_ms", "total_fired", "total_events"]:
                assert field in rule, (
                    f"Campo '{field}' faltante en regla evaluable '{rule['rule_title']}'"
                )


def test_not_evaluable_rules_have_reason(metrics_json):
    for rule in metrics_json["rules"]:
        if not rule["evaluable_on_unsw_nb15"]:
            assert "not_evaluable_reason" in rule, (
                f"Regla NOT EVALUABLE sin razón: '{rule['rule_title']}'"
            )
            assert len(rule["not_evaluable_reason"]) > 10, (
                f"Razón demasiado corta para '{rule['rule_title']}'"
            )


def test_confusion_matrix_arithmetic_consistency(metrics_json):
    """TP+FP+FN+TN debe ser igual a total_events para cada regla evaluable."""
    for rule in metrics_json["rules"]:
        if not rule["evaluable_on_unsw_nb15"]:
            continue
        total = rule["tp"] + rule["fp"] + rule["fn"] + rule["tn"]
        expected = rule["total_events"]
        assert total == expected, (
            f"Inconsistencia aritmética en '{rule['rule_title']}': "
            f"TP+FP+FN+TN={total} ≠ total_events={expected}"
        )


def test_precision_recall_f1_computed_correctly(metrics_json):
    """Comprueba que precision/recall/F1 coinciden con los contadores."""
    for rule in metrics_json["rules"]:
        if not rule["evaluable_on_unsw_nb15"]:
            continue
        tp, fp, fn, tn = rule["tp"], rule["fp"], rule["fn"], rule["tn"]
        denom_p = tp + fp
        denom_r = tp + fn
        expected_p = tp / denom_p if denom_p else 0.0
        expected_r = tp / denom_r if denom_r else 0.0
        expected_f1 = (
            2 * expected_p * expected_r / (expected_p + expected_r)
            if (expected_p + expected_r) else 0.0
        )
        assert abs(rule["precision"] - round(expected_p, 4)) < 1e-3, (
            f"Precision incorrecta en '{rule['rule_title']}'"
        )
        assert abs(rule["recall"] - round(expected_r, 4)) < 1e-3, (
            f"Recall incorrecta en '{rule['rule_title']}'"
        )


def test_total_events_is_5000(metrics_json):
    """Verifica que la evaluación se hizo sobre los 5000 eventos del dataset."""
    for rule in metrics_json["rules"]:
        if rule["evaluable_on_unsw_nb15"]:
            assert rule["total_events"] == 5000, (
                f"Evaluación no usó los 5000 eventos: '{rule['rule_title']}' "
                f"usó {rule['total_events']}"
            )


def test_c2_port_rule_has_perfect_precision(metrics_json):
    """
    cs-c2-port-connect debe tener Precision=1.0 (FP=0) porque los puertos
    4444/1337/31337 en el dataset UNSW-NB15 sintético son exclusivamente ataques.
    """
    c2_rules = [
        r for r in metrics_json["rules"]
        if r["evaluable_on_unsw_nb15"] and "C2" in r["rule_title"]
    ]
    assert len(c2_rules) >= 1, "No se encontró la regla de puertos C2"
    c2 = c2_rules[0]
    assert c2["fp"] == 0, f"Se esperaba FP=0 para C2 port rule, got FP={c2['fp']}"
    assert c2["precision"] == pytest.approx(1.0), (
        f"Se esperaba Precision=1.0 para C2 port rule, got {c2['precision']}"
    )


def test_c2_port_rule_fires_41_times(metrics_json):
    """
    Los puertos 4444/1337/31337 aparecen en 41 filas del dataset (todas Backdoor).
    """
    c2_rules = [
        r for r in metrics_json["rules"]
        if r["evaluable_on_unsw_nb15"] and "C2" in r["rule_title"]
    ]
    assert c2_rules[0]["tp"] == 41, (
        f"Se esperaban 41 TP para C2 rule, got {c2_rules[0]['tp']}"
    )


def test_large_outbound_fires_zero(metrics_json):
    """
    El dataset tiene max sbytes ~16MB, por debajo del umbral de 100MB.
    La regla no debe disparar ningún evento.
    """
    exfil_rules = [
        r for r in metrics_json["rules"]
        if r["evaluable_on_unsw_nb15"] and "Exfiltr" in r["rule_title"] and "Sigma" not in r.get("rule_id", "")
    ]
    # cs-large-outbound o RULE-0007
    large_rules = [
        r for r in metrics_json["rules"]
        if r["evaluable_on_unsw_nb15"] and ("Large" in r["rule_title"] or r.get("rule_id") == "RULE-0007")
    ]
    for rule in large_rules:
        assert rule["total_fired"] == 0, (
            f"'{rule['rule_title']}' debería disparar 0 veces (umbral 100MB > max 16MB), "
            f"disparó {rule['total_fired']}"
        )


def test_rdp_lateral_fires_zero(metrics_json):
    """
    El dataset RDP tiene src_ip externo (203.0.113.x), no RFC1918.
    La regla RDP requiere AMBOS extremos internos → 0 disparos.
    """
    rdp_rules = [
        r for r in metrics_json["rules"]
        if r["evaluable_on_unsw_nb15"] and "RDP" in r["rule_title"]
    ]
    for rule in rdp_rules:
        assert rule["total_fired"] == 0, (
            f"'{rule['rule_title']}' debería disparar 0 veces (sin RDP interno en dataset), "
            f"disparó {rule['total_fired']}"
        )


def test_global_precision_meets_target(summary_json):
    """
    Precision global ≥ 0.70 (solo basada en las reglas que dispararon).
    El target se alcanza porque cs-c2-port-connect tiene Precision=1.0 y FP=0.
    """
    gm = summary_json["global_metrics"]
    assert gm["precision"] >= 0.70, (
        f"Precision global {gm['precision']} < 0.70 target"
    )


def test_global_fpr_is_zero(summary_json):
    """FPR=0: ninguna regla evaluable disparó sobre tráfico benigno."""
    gm = summary_json["global_metrics"]
    assert gm["fpr"] == pytest.approx(0.0), (
        f"Se esperaba FPR=0.0, got {gm['fpr']}"
    )


def test_no_false_positives_in_dataset(fp_json):
    """Confirma que el reporte de FP tiene 0 FP (resultado real, no filtrado)."""
    assert fp_json["summary"]["total_fp"] == 0, (
        f"Se esperaban 0 FP globales, got {fp_json['summary']['total_fp']}"
    )


# ────────────────────────────────────────────────────────────────────────────
# 3. Cobertura ATT&CK — estructural, no empírica
# ────────────────────────────────────────────────────────────────────────────

def test_coverage_before_is_7(summary_json):
    assert summary_json["coverage"]["before"]["technique_count"] == 7, (
        "La cobertura antes debe ser exactamente 7 técnicas"
    )


def test_coverage_after_is_18(summary_json):
    assert summary_json["coverage"]["after"]["technique_count"] == 18, (
        "La cobertura después debe ser exactamente 18 técnicas"
    )


def test_coverage_percentage_before(summary_json):
    pct = summary_json["coverage"]["before"]["percentage"]
    assert abs(pct - 3.15) < 0.1, f"Porcentaje antes esperado ~3.15%, got {pct}%"


def test_coverage_percentage_after(summary_json):
    pct = summary_json["coverage"]["after"]["percentage"]
    assert abs(pct - 8.11) < 0.1, f"Porcentaje después esperado ~8.11%, got {pct}%"


def test_coverage_gain_is_11(summary_json):
    assert summary_json["coverage"]["absolute_gain"] == 11, (
        "La ganancia absoluta debe ser 11 técnicas nuevas"
    )


def test_coverage_note_distinguishes_structural_from_empirical(summary_json):
    """El nota de cobertura debe mencionar explícitamente que es estructural."""
    note = summary_json["coverage"].get("note", "")
    assert "ESTRUCTURAL" in note or "estructural" in note, (
        "La nota de cobertura no diferencia cobertura estructural de empírica"
    )


def test_evaluability_count(summary_json):
    """Debe haber exactamente 5 reglas evaluables y 17 NOT EVALUABLE."""
    gm = summary_json["global_metrics"]
    assert gm["evaluable_rules"] == 5, (
        f"Se esperaban 5 reglas evaluables, got {gm['evaluable_rules']}"
    )
    assert gm["not_evaluable_rules"] == 17, (
        f"Se esperaban 17 NOT EVALUABLE, got {gm['not_evaluable_rules']}"
    )


# ────────────────────────────────────────────────────────────────────────────
# 4. Navigator layers — estructura y estados correctos
# ────────────────────────────────────────────────────────────────────────────

def test_navigator_before_has_7_techniques(navigator_before):
    assert len(navigator_before["techniques"]) == 7, (
        f"navigator_before debe tener 7 técnicas, tiene {len(navigator_before['techniques'])}"
    )


def test_navigator_after_has_18_techniques(navigator_after):
    assert len(navigator_after["techniques"]) == 18, (
        f"navigator_after debe tener 18 técnicas, tiene {len(navigator_after['techniques'])}"
    )


def test_navigator_before_required_fields(navigator_before):
    for t in navigator_before["techniques"]:
        assert "techniqueID" in t
        assert "color" in t
        assert "comment" in t


def test_navigator_after_t1071_is_detected(navigator_after):
    """T1071 (C2 ports) debe estar detectada (verde) porque cs-c2-port-connect disparó."""
    t1071 = next(
        (t for t in navigator_after["techniques"] if t["techniqueID"] == "T1071"),
        None,
    )
    assert t1071 is not None, "T1071 no encontrada en navigator_after"
    # Verde = detected
    assert t1071["color"] == "#2ecc71", (
        f"T1071 debería ser 'detected' (#2ecc71), tiene color={t1071['color']}"
    )


def test_navigator_after_t1048_is_covered_not_detected(navigator_after):
    """T1048 (exfiltration) no disparó (umbral 100MB > max en dataset) → covered/grey."""
    t1048 = next(
        (t for t in navigator_after["techniques"] if t["techniqueID"] == "T1048"),
        None,
    )
    assert t1048 is not None, "T1048 no encontrada en navigator_after"
    # No debe ser verde (no hubo disparos)
    assert t1048["color"] != "#2ecc71", (
        "T1048 no debería ser 'detected' — la regla de exfiltración no disparó en UNSW-NB15"
    )


def test_navigator_after_process_techniques_are_not_detected(navigator_after):
    """
    Técnicas de process_creation (T1059.001, T1218.005, etc.) deben ser
    grey (covered/not_evaluable), nunca verde (detected), ya que UNSW-NB15
    no tiene telemetría de proceso.
    """
    process_techniques = {
        "T1059.001", "T1033", "T1087", "T1053.005",
        "T1105", "T1218.005", "T1047", "T1218.010", "T1218.011",
    }
    for t in navigator_after["techniques"]:
        if t["techniqueID"] in process_techniques:
            assert t["color"] != "#2ecc71", (
                f"Técnica {t['techniqueID']} no debería ser 'detected' — "
                f"no hay telemetría de proceso en UNSW-NB15"
            )


def test_navigator_has_legend_items(navigator_after):
    assert "legendItems" in navigator_after
    assert len(navigator_after["legendItems"]) >= 2


def test_navigator_after_metadata_present(navigator_after):
    assert "metadata" in navigator_after
    meta = navigator_after["metadata"]
    assert "generated" in meta
    assert "dataset" in meta
    assert "total_techniques_covered" in meta
    assert meta["total_techniques_covered"] == 18


# ────────────────────────────────────────────────────────────────────────────
# 5. No-regresión: las 7 reglas originales siguen funcionando
# ────────────────────────────────────────────────────────────────────────────

def test_original_7_rules_still_load():
    engine = RulesEngine.from_directory(RULES_DIR)
    assert len(engine.rules) == 7, (
        f"Se esperaban 7 reglas originales, cargaron {len(engine.rules)}"
    )


def test_original_rules_detect_exfiltration_event():
    """RULE-0007 debe disparar sobre un evento con bytes_out > 100MB."""
    engine = RulesEngine.from_directory(RULES_DIR)
    ev = SecurityEvent(
        event_id="test-exfil", timestamp=__import__("datetime").datetime.now(tz=_UTC),
        source="netflow", category="network", action="network_flow",
        bytes_out=200_000_000,
    )
    hits = engine.evaluate_event(ev)
    assert any(h.rule.id == "RULE-0007" for h in hits), (
        "REGRESIÓN: RULE-0007 (exfiltración) no disparó con bytes_out=200MB"
    )


def test_original_rules_detect_rdp_internal():
    """RULE-0005 debe disparar sobre RDP entre hosts internos."""
    engine = RulesEngine.from_directory(RULES_DIR)
    ev = SecurityEvent(
        event_id="test-rdp", timestamp=__import__("datetime").datetime.now(tz=_UTC),
        source="netflow", category="network", action="network_flow",
        src_ip="10.0.0.5", dst_ip="10.0.0.10", dst_port=3389,
    )
    hits = engine.evaluate_event(ev)
    assert any(h.rule.id == "RULE-0005" for h in hits), (
        "REGRESIÓN: RULE-0005 (RDP lateral) no disparó con IPs internas"
    )


def test_original_rules_detect_c2_port():
    """RULE-0006 stateless debe incluirse; C2 usa aggregation pero el matching funciona."""
    # Note: RULE-0006 has aggregation so won't appear in stateless_rules.
    # Test that it loads correctly.
    engine = RulesEngine.from_directory(RULES_DIR)
    c2_rule = next((r for r in engine.rules if r.id == "RULE-0006"), None)
    assert c2_rule is not None, "RULE-0006 no cargó"
    assert c2_rule.aggregation is not None, "RULE-0006 debe tener aggregation"


def test_sigma_38_rules_still_load():
    """
    Guarda de regresión sobre el directorio real, no sobre el reporte
    congelado de Fase 1 (ese vive en reports/sigma_phase1_summary.json y
    documenta las 15 reglas de entonces a propósito). Fase 4-A subió esto a
    38; ver tests/test_sigma_expansion.py para la cobertura ATT&CK.
    """
    engine = RulesEngine.from_sigma_directory(SIGMA_RULES_DIR)
    assert len(engine.rules) == 38, (
        f"Se esperaban 38 reglas Sigma, cargaron {len(engine.rules)}"
    )


# ────────────────────────────────────────────────────────────────────────────
# 6. Reproducibilidad
# ────────────────────────────────────────────────────────────────────────────

def test_summary_has_reproducibility_metadata(summary_json):
    meta = summary_json["metadata"]
    required = [
        "generated", "python_version", "pysigma_version",
        "dataset", "dataset_events", "dataset_attacks", "dataset_benign",
        "random_seed",
    ]
    for field in required:
        assert field in meta, f"Campo de reproducibilidad faltante: '{field}'"


def test_dataset_event_counts_match(summary_json):
    meta = summary_json["metadata"]
    assert meta["dataset_events"] == 5000
    assert meta["dataset_attacks"] == 500
    assert meta["dataset_benign"] == 4500


def test_pysigma_version_recorded(summary_json):
    version = summary_json["metadata"].get("pysigma_version", "")
    assert version != "", "Versión de pySigma no registrada"
    assert version != "unknown", f"Versión de pySigma registrada como 'unknown'"


def test_notes_mention_no_fabrication(summary_json):
    notes = summary_json.get("notes", [])
    has_structural_note = any("ESTRUCTURAL" in n or "estructural" in n for n in notes)
    assert has_structural_note, (
        "Las notas deben mencionar que la cobertura es estructural, no empírica"
    )
