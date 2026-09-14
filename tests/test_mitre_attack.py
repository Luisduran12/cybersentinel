"""
Pruebas de la integración con MITRE ATT&CK oficial (Fase 2).

Cubren tres cosas: que la fachada siga cumpliendo el contrato anterior, que el
sistema funcione **sin** la matriz oficial (un clon recién descargado no la
tiene), y que los cambios reales de ATT&CK —tácticas renombradas, técnicas en
varias tácticas a la vez— estén contemplados.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cybersentinel.correlation import mitre, navigator  # noqa: E402
from cybersentinel.correlation.attack_data import (  # noqa: E402
    DEFAULT_CACHE_PATH, AttackData, Technique, build_from_stix,
)
from cybersentinel.correlation.correlator import Correlator, Finding  # noqa: E402
from cybersentinel.detection import RulesEngine  # noqa: E402
from cybersentinel.schema import SecurityEvent, Severity  # noqa: E402

RULES_DIR = ROOT / "config" / "rules"
BASE = datetime(2025, 3, 10, 10, tzinfo=timezone.utc)


@pytest.fixture
def matriz_restaurada():
    """Devuelve la matriz activa a su estado real tras manipularla en una prueba."""
    original = mitre.attack_data()
    yield
    mitre.use(original)


def _finding(tactic: str, technique: str, minutes: int = 0) -> Finding:
    event = SecurityEvent("e", BASE + timedelta(minutes=minutes), "sysmon",
                          "process", "process_create", host="SRV")
    return Finding("rule", event, Severity.HIGH, 0.8, technique, tactic, "titulo")


# ------------------------- contrato de la fachada ---------------------------
def test_public_interface_is_unchanged():
    """La interfaz que usaba el resto del sistema sigue existiendo."""
    assert mitre.technique_name("T1110") == "Brute Force"
    assert mitre.tactic_of("T1110") == "credential-access"
    assert mitre.tactic_index("execution") >= 0
    assert mitre.next_tactics("credential-access", k=2)
    assert isinstance(mitre.TACTIC_ORDER, list) and mitre.TACTIC_ORDER


def test_unknown_technique_degrades_gracefully():
    assert mitre.technique_name("T9999") == "T9999"
    assert mitre.tactic_of("T9999") == "unknown"
    assert mitre.tactic_index("una-tactica-inventada") == -1
    assert mitre.next_tactics("una-tactica-inventada") == []


def test_tactic_order_ends_in_impact():
    """El orden es el de la cadena de ataque, no alfabético."""
    assert mitre.TACTIC_ORDER[-1] == "impact"
    assert mitre.TACTIC_ORDER[0] == "reconnaissance"
    assert mitre.tactic_index("exfiltration") > mitre.tactic_index("initial-access")


# ------------------- cambios reales de la matriz oficial --------------------
def test_retired_tactic_name_still_resolves():
    """
    MITRE dividió `defense-evasion` en `stealth` y `defense-impairment`. Las
    reglas y los corpus escritos antes tienen que seguir funcionando.
    """
    assert mitre.normalize_tactic("defense-evasion") == "stealth"
    assert mitre.tactic_index("defense-evasion") == mitre.tactic_index("stealth")
    assert mitre.tactic_index("defense-evasion") >= 0


def test_a_technique_can_belong_to_several_tactics():
    """T1053 está en ejecución, persistencia y escalada de privilegios."""
    tacticas = mitre.tactics_of("T1053")
    if not mitre.using_official_matrix():
        pytest.skip("requiere la matriz oficial (ejecuta 'attack-sync')")
    assert len(tacticas) > 1
    assert "persistence" in tacticas


def test_primary_tactic_is_the_earliest_in_the_chain():
    """
    Con varias tácticas posibles se elige la más temprana: un solo hallazgo no
    debe hacer parecer que el ataque está más avanzado de lo que demuestra.
    """
    data = AttackData(
        techniques={"T9001": Technique("T9001", "Prueba",
                                       ["impact", "execution", "persistence"])},
        tactic_order=["execution", "persistence", "impact"],
    )
    assert data.primary_tactic("T9001") == "execution"


def test_subtechniques_resolve_through_their_parent():
    """La telemetría real cita T1059.001; las reglas propias citan T1059."""
    assert mitre.technique_name("T1059.001") != "T1059.001"
    assert mitre.tactic_of("T1059.001") == "execution"


# --------------------------- respaldo embebido ------------------------------
def test_system_works_without_the_official_matrix(matriz_restaurada):
    """Un clon recién descargado no tiene la caché: no puede fallar por eso."""
    mitre.use(mitre._embedded())

    assert not mitre.using_official_matrix()
    assert mitre.technique_name("T1110") == "Brute Force"
    assert mitre.tactic_of("T1059") == "execution"
    assert len(mitre.TACTIC_ORDER) == len(mitre.EMBEDDED_TACTIC_ORDER)
    assert "embebido" in mitre.describe_source()


def test_rules_load_with_the_embedded_fallback(matriz_restaurada):
    mitre.use(mitre._embedded())
    engine = RulesEngine.from_directory(RULES_DIR)
    assert len(engine.rules) == 7
    assert all(r.mitre_tactic != "unknown" for r in engine.rules)


def test_prediction_works_with_the_embedded_fallback(matriz_restaurada):
    mitre.use(mitre._embedded())
    incidente = Correlator().correlate([
        _finding("credential-access", "T1110", 0), _finding("execution", "T1059", 5),
    ])[0]
    assert incidente.prediction is not None
    assert incidente.prediction.predicted_next


def test_missing_cache_falls_back_instead_of_failing(tmp_path, matriz_restaurada):
    assert AttackData.load(tmp_path / "no-existe.json") is None
    mitre.reload(tmp_path / "no-existe.json")
    assert not mitre.using_official_matrix()


def test_corrupt_cache_falls_back_instead_of_failing(tmp_path, matriz_restaurada, caplog):
    corrupta = tmp_path / "cache.json"
    corrupta.write_text("{esto no es json}", encoding="utf-8")
    assert AttackData.load(corrupta) is None


# ------------------------------- caché --------------------------------------
def test_cache_round_trip(tmp_path):
    original = AttackData(
        techniques={
            "T1000": Technique("T1000", "Madre", ["execution"]),
            "T1000.001": Technique("T1000.001", "Hija", ["execution"],
                                   is_subtechnique=True, parent="T1000"),
        },
        tactic_order=["execution", "impact"],
        tactic_names={"execution": "Execution"},
        version="19.2",
    )
    ruta = original.save(tmp_path / "cache.json")
    restaurada = AttackData.load(ruta)

    assert restaurada.version == "19.2"
    assert restaurada.n_techniques == 1
    assert restaurada.n_subtechniques == 1
    assert restaurada.techniques["T1000.001"].parent == "T1000"
    assert restaurada.tactic_order == ["execution", "impact"]


def test_the_shipped_cache_is_usable():
    """La caché versionada con el proyecto tiene que cargar."""
    if not DEFAULT_CACHE_PATH.exists():
        pytest.skip("no hay cache generada")
    data = AttackData.load(DEFAULT_CACHE_PATH)
    assert data.n_techniques > 100
    assert len(data.tactic_order) >= 14
    assert data.version != "desconocida"


def test_build_from_stix_explains_how_to_get_the_bundle(tmp_path):
    with pytest.raises(FileNotFoundError, match="attack-stix-data"):
        build_from_stix(tmp_path / "no-existe.json")


def test_build_from_a_minimal_stix_bundle(tmp_path):
    """
    El constructor lee STIX plano, así que se puede probar sin los 51 MB
    oficiales ni la librería instalada.
    """
    bundle = {
        "type": "bundle",
        "objects": [
            {"type": "x-mitre-collection",
             "id": "x-mitre-collection--00000000-0000-4000-8000-000000000001",
             "x_mitre_version": "19.2"},
            {"type": "x-mitre-tactic",
             "id": "x-mitre-tactic--00000000-0000-4000-8000-000000000011",
             "name": "Execution", "x_mitre_shortname": "execution"},
            {"type": "x-mitre-tactic",
             "id": "x-mitre-tactic--00000000-0000-4000-8000-000000000012",
             "name": "Impact", "x_mitre_shortname": "impact"},
            {"type": "x-mitre-matrix",
             "id": "x-mitre-matrix--00000000-0000-4000-8000-000000000021",
             "name": "Prueba",
             "tactic_refs": ["x-mitre-tactic--00000000-0000-4000-8000-000000000011",
                             "x-mitre-tactic--00000000-0000-4000-8000-000000000012"]},
            {"type": "attack-pattern",
             "id": "attack-pattern--00000000-0000-4000-8000-000000000031",
             "name": "Interprete",
             "kill_chain_phases": [{"kill_chain_name": "mitre-attack",
                                    "phase_name": "execution"}],
             "external_references": [{"source_name": "mitre-attack",
                                      "external_id": "T1059"}]},
            {"type": "attack-pattern",
             "id": "attack-pattern--00000000-0000-4000-8000-000000000032",
             "name": "PowerShell", "x_mitre_is_subtechnique": True,
             "kill_chain_phases": [{"kill_chain_name": "mitre-attack",
                                    "phase_name": "execution"}],
             "external_references": [{"source_name": "mitre-attack",
                                      "external_id": "T1059.001"}]},
            {"type": "attack-pattern",
             "id": "attack-pattern--00000000-0000-4000-8000-000000000033",
             "name": "Revocada", "revoked": True,
             "external_references": [{"source_name": "mitre-attack",
                                      "external_id": "T1562"}]},
        ],
    }
    ruta = tmp_path / "stix.json"
    ruta.write_text(json.dumps(bundle), encoding="utf-8")

    data = build_from_stix(ruta)
    assert data.version == "19.2"
    assert data.tactic_order == ["execution", "impact"]
    assert data.technique("T1059").name == "Interprete"
    assert data.techniques["T1059.001"].parent == "T1059"
    assert "T1562" not in data.techniques        # las revocadas no entran


# ------------------------------ Navigator -----------------------------------
def test_incident_layer_has_the_structure_navigator_expects():
    incidentes = Correlator().correlate([
        _finding("credential-access", "T1110", 0),
        _finding("execution", "T1059", 5),
    ])
    capa = navigator.layer_from_incidents(incidentes)

    for clave in ("name", "versions", "domain", "techniques", "gradient", "layout"):
        assert clave in capa
    assert capa["versions"]["layer"] == "4.5"
    assert capa["domain"] == "enterprise-attack"
    assert {t["techniqueID"] for t in capa["techniques"]} == {"T1110", "T1059"}
    assert all(0 <= t["score"] <= 100 for t in capa["techniques"])


def test_a_technique_in_several_incidents_keeps_the_worst_risk():
    """La matriz debe destacar el peor caso observado, no la media."""
    leve = Correlator().correlate([_finding("execution", "T1059", 0)])[0]
    grave = Correlator().correlate([
        _finding("execution", "T1059", 0), _finding("exfiltration", "T1048", 5),
    ])[0]

    capa = navigator.layer_from_incidents([leve, grave])
    puntuacion = {t["techniqueID"]: t["score"] for t in capa["techniques"]}
    assert puntuacion["T1059"] == max(leve.risk_score, grave.risk_score)


def test_coverage_layer_lists_every_rule_technique():
    reglas = RulesEngine.from_directory(RULES_DIR).rules
    capa = navigator.layer_from_rules(reglas)
    esperadas = {r.mitre_technique for r in reglas}
    assert {t["techniqueID"] for t in capa["techniques"]} == esperadas
    assert all(t["comment"] for t in capa["techniques"])


def test_coverage_summary_is_honest_about_the_gap():
    """
    La cobertura baja es un resultado, no un fallo: mide el alcance real del
    prototipo y justifica la fase de reglas Sigma de la comunidad.
    """
    resumen = navigator.coverage_summary(RulesEngine.from_directory(RULES_DIR).rules)
    assert resumen["tecnicas_cubiertas"] == 7
    assert resumen["tecnicas_totales"] >= resumen["tecnicas_cubiertas"]
    assert 0.0 < resumen["cobertura"] < 1.0
    assert len(resumen["por_tactica"]) == len(mitre.TACTIC_ORDER)
    assert sum(f["cubiertas"] for f in resumen["por_tactica"]) >= 7


def test_empty_incident_list_produces_a_valid_layer():
    capa = navigator.layer_from_incidents([])
    assert capa["techniques"] == []
    assert capa["versions"]["layer"] == "4.5"


def test_layer_is_written_as_readable_json(tmp_path):
    capa = navigator.layer_from_rules(RulesEngine.from_directory(RULES_DIR).rules)
    ruta = navigator.save_layer(capa, tmp_path / "capa.json")
    recargada = json.loads(ruta.read_text(encoding="utf-8"))
    assert recargada["name"] == capa["name"]
    assert recargada["techniques"]
