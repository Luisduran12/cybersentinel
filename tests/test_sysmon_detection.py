import json
import pytest
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cybersentinel.ingestion.normalizer import parse_sysmon
from cybersentinel.detection.rules_engine import RulesEngine

DATASET_PATH = Path("data/synthetic_sysmon_eval.json")
RULES_PATH = Path("config/sigma_rules/selected")

@pytest.fixture(scope="module")
def engine():
    eng = RulesEngine()
    eng.rules += RulesEngine.from_sigma_directory(RULES_PATH).rules
    return eng

@pytest.fixture(scope="module")
def dataset():
    with open(DATASET_PATH, "r") as f:
        records = json.load(f)
    return [parse_sysmon(r) for r in records]

def test_sysmon_synthetic_detection(engine, dataset):
    """
    Evalúa que los eventos Sysmon sintéticos disparen las reglas Sigma esperadas.
    """
    assert len(dataset) == 11, "Debería haber 11 eventos en el dataset sintético"
    
    # Mapeo de evento índice -> regla esperada
    expected_matches = {
        0: "cs-ps-encoded-cmd",
        1: "cs-whoami-exec",
        2: "cs-net-recon",
        3: "cs-schtasks-create",
        4: "cs-certutil-download",
        5: "cs-mshta-exec",
        6: "cs-wmic-process",
        7: "cs-regsvr32-exec",
        8: "cs-rundll32-exec",
        9: "cs-portscan-tool",
        10: None # benign event (notepad)
    }
    
    for idx, expected_rule in expected_matches.items():
        event = dataset[idx]
        hits = engine.evaluate_event(event)
        
        if expected_rule is None:
            assert len(hits) == 0, f"El evento {idx} benigno no debe generar hits"
        else:
            assert len(hits) >= 1, f"El evento {idx} no generó el hit esperado para {expected_rule}"
            matched_rule_ids = [hit.rule.id for hit in hits]
            # Las reglas en config/sigma_rules/manifest.yaml tienen ids.
            # Verificamos por el título o por el nombre del archivo si es posible.
            # Como los ID son UUIDs, verificaremos que el título o archivo coincida.
            # Sin embargo, hit.rule.id es el UUID. Podemos chequear si alguna regla
            # originada desde expected_rule + ".yml" disparó.
            matched = any(expected_rule in hit.rule._sigma_source_file for hit in hits)
            assert matched, f"El evento {idx} esperaba {expected_rule}, obtuvo {matched_rule_ids}"
