"""
Validación Científica Integral (Fase 8.1)
Evalúa el Pipeline completo (Sigma, ML, Temporal, CTI, RAG, LLM) sobre
un dataset mixto (benigno y sysmon malicioso) con separación temporal
estricta (Train/Val/Test) para evitar leakage.
"""
import sys
import os
import json
import uuid
import hashlib
import argparse
import random
from pathlib import Path
from datetime import datetime, timedelta, timezone

import numpy as np
from sklearn.metrics import (
    precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, confusion_matrix
)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cybersentinel.schema import SecurityEvent
from cybersentinel.ingestion import Normalizer
from cybersentinel.ml.dataset import TimeBasedSplitter
from cybersentinel.ml.base import Dataset
from cybersentinel.pipeline import Pipeline
from cybersentinel.cti.stix_ingestor import StixIngestor
from cybersentinel.cti.enrichment import CTIEnricher
from cybersentinel.cti.models import Indicator


BASELINE_EPOCH = datetime(2026, 9, 15, 0, 0, 0, tzinfo=timezone.utc)
ROOT = Path(__file__).resolve().parents[1]

def generate_benign_sysmon(n_events: int, seed: int, start_time: datetime) -> list[SecurityEvent]:
    """Genera eventos sysmon benignos para entrenar y evaluar."""
    rng = random.Random(seed)
    events = []
    
    # Eventos distribuidos en 72 horas
    for i in range(n_events):
        ts = start_time + timedelta(seconds=rng.randint(0, 72 * 3600))
        host = rng.choice(["WKS-01", "WKS-02", "SRV-01"])
        user = rng.choice(["ana", "carlos", "system"])
        
        cmd = rng.choice([
            "chrome.exe --type=renderer",
            "svchost.exe -k netsvcs",
            "explorer.exe",
            "taskhostw.exe"
        ])
        
        properties = {}
        if rng.random() < 0.3:
            properties["hashes"] = {"SHA256": "1234567890ABCDEF"}
            
        events.append(SecurityEvent(
            event_id=f"benign_{i:05d}",
            timestamp=ts,
            source="sysmon",
            category="process",
            action="process_create",
            host=host,
            user=user,
            process_name=cmd.split()[0],
            command_line=cmd,
            outcome="success",
            properties=properties
        ))
    return events


def load_attacks(start_time: datetime) -> list[SecurityEvent]:
    """Carga eventos sysmon sintéticos de ataque y los posiciona al final (hacia hora 70)."""
    path = ROOT / "data" / "synthetic_sysmon_eval.json"
    with open(path, "r") as f:
        data = json.load(f)
    
    events = Normalizer().normalize(data)
    
    # Mover timestamps hacia el final (Test)
    for e in events:
        e.timestamp = start_time + timedelta(hours=70, minutes=e.timestamp.minute)
        # Ensure hashes is a dict, because CTIEnricher expects it
        if "hashes" in e.properties and isinstance(e.properties["hashes"], str):
            h_str = e.properties["hashes"]
            # example: "SHA1=1234,MD5=5678"
            h_dict = {}
            for part in h_str.split(","):
                if "=" in part:
                    k, v = part.split("=", 1)
                    h_dict[k.strip()] = v.strip()
            e.properties["hashes"] = h_dict
            
    return events


def compute_dataset_hash(events: list[SecurityEvent]) -> str:
    h = hashlib.sha256()
    for ev in events:
        # Sort keys to ensure deterministic hash even if properties are unordered
        prop_str = json.dumps(ev.properties, sort_keys=True) if ev.properties else ""
        record = "|".join([
            ev.event_id, ev.timestamp.isoformat(),
            ev.source, ev.category, ev.action,
            prop_str, str(ev.command_line)
        ])
        h.update(record.encode("utf-8"))
    return h.hexdigest()


def compute_metrics(y_true, y_pred, y_scores=None):
    metrics = {}
    if len(set(y_true)) > 1:
        metrics["precision"] = float(precision_score(y_true, y_pred, zero_division=0))
        metrics["recall"] = float(recall_score(y_true, y_pred, zero_division=0))
        metrics["f1"] = float(f1_score(y_true, y_pred, zero_division=0))
        
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
        metrics["tp"] = int(tp)
        metrics["fp"] = int(fp)
        metrics["fn"] = int(fn)
        metrics["tn"] = int(tn)
        metrics["fpr"] = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        metrics["fnr"] = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
        
        if y_scores is not None:
            metrics["roc_auc"] = float(roc_auc_score(y_true, y_scores))
            metrics["pr_auc"] = float(average_precision_score(y_true, y_scores))
    else:
        metrics = {"error": "INSUFFICIENT_LABELS"}
    return metrics


def p95(arr):
    if not arr: return 0.0
    idx = int(len(arr) * 0.95)
    return arr[min(idx, len(arr)-1)]


def setup_cti() -> StixIngestor:
    """Mockea CTI real referenciando atributos de sysmon malicioso."""
    ingestor = StixIngestor()
    now = datetime.now(timezone.utc)
    # Ejemplo: Mimikatz o cmd malicioso común
    ingestor.indicators["ind-mimikatz"] = Indicator(
        id="ind-mimikatz", 
        pattern="[process:command_line MATCHES 'mimikatz']", 
        valid_from=now, 
        labels=["malware", "credential-dumping"]
    )
    # Podríamos inyectar más si tuviéramos un analizador completo STIX
    return ingestor


def run_ablation(test_events: list[SecurityEvent], y_test: np.ndarray, configurations: dict, 
                 pre_fitted_detector, rules_dir: str):
    
    results = {}
    
    for name, flags in configurations.items():
        print(f"\n[*] Evaluando Ablation: {name}")
        
        pipeline = Pipeline(rules_dir=rules_dir, **flags)
        
        if flags.get("enable_ml"):
            # Transferimos el detector ya entrenado para no re-entrenar en TEST (Leakage!)
            pipeline.anomaly_detector = pre_fitted_detector
        
        if flags.get("enable_cti"):
            pipeline.cti_enricher = CTIEnricher(setup_cti())
            
        # Ejecutamos el pipeline (simulando procesamiento evento a evento para el RAG/Temporal)
        report = pipeline.run_events(test_events)
        
        # Decision: Alertamos si hybrid_score >= 50.0 (Umbral del Pipeline Fase 7/8)
        y_pred = [1 if res.evidence.hybrid_score >= 50.0 else 0 for res in report.results]
        y_scores = [res.evidence.hybrid_score / 100.0 for res in report.results]
        
        met = compute_metrics(y_test, y_pred, y_scores)
        
        # Latencias
        core_lat = sorted([res.trace.total_core_ms for res in report.results])
        total_lat = sorted([res.trace.total_ms for res in report.results])
        
        met["latency"] = {
            "p50_core_ms": float(core_lat[len(core_lat)//2]) if core_lat else 0.0,
            "p95_core_ms": float(p95(core_lat)),
            "p50_total_ms": float(total_lat[len(total_lat)//2]) if total_lat else 0.0,
            "p95_total_ms": float(p95(total_lat))
        }
        
        # Guardar RAG / LLM status (Para evaluar invariancia y overhead)
        met["rag_llm_status"] = "RAG: NO DEMONSTRATED (No corpus) | LLM: EXPLICADOR INVARIANTE" if flags.get("enable_llm") else "DISABLED"
        
        results[name] = met
        print(f"    -> Precision: {met.get('precision', 0):.4f} | Recall: {met.get('recall', 0):.4f} | F1: {met.get('f1', 0):.4f}")
        
    return results


def main():
    parser = argparse.ArgumentParser(description="Scientific Validation Phase 8.1")
    parser.add_argument("--seed", type=int, default=42, help="Seed for benign generation")
    parser.add_argument("--benign", type=int, default=2000, help="Number of benign events")
    args = parser.parse_args()

    run_id = str(uuid.uuid4())
    executed_at = datetime.now(timezone.utc).isoformat()
    
    print(f"==================================================")
    print(f" CYBERSENTINEL - SCIENTIFIC VALIDATION PHASE 8.1")
    print(f"==================================================")
    print(f"Run ID: {run_id} | Seed: {args.seed}")

    # 1. Dataset
    print(f"\n[1] Generando dataset (Seed {args.seed})...")
    benign = generate_benign_sysmon(args.benign, args.seed, BASELINE_EPOCH)
    attacks = load_attacks(BASELINE_EPOCH)
    
    all_events = benign + attacks
    
    # Ground truth mapping
    labels_map = {e.event_id: (0 if "benign" in e.event_id else 1) for e in all_events}
    
    # 2. Control de Leakage (Temporal Split)
    print(f"\n[2] División Temporal Estricta (TimeBasedSplitter)...")
    splitter = TimeBasedSplitter(train_ratio=0.6, val_ratio=0.2)
    train_ev, val_ev, test_ev = splitter.split(all_events)
    
    y_train = np.array([labels_map[e.event_id] for e in train_ev])
    y_val = np.array([labels_map[e.event_id] for e in val_ev])
    y_test = np.array([labels_map[e.event_id] for e in test_ev])
    
    print(f"    Total: {len(all_events)}")
    print(f"    Train: {len(train_ev)} (Ataques: {sum(y_train)})")
    print(f"    Val:   {len(val_ev)} (Ataques: {sum(y_val)})")
    print(f"    Test:  {len(test_ev)} (Ataques: {sum(y_test)})")
    
    dataset_hash = compute_dataset_hash(all_events)
    print(f"    Dataset Hash (SHA-256): {dataset_hash}")

    # 3. Entrenamiento ML
    print(f"\n[3] Ajustando ML AnomalyDetector en Train (No supervisado)...")
    from cybersentinel.detection.anomaly import AnomalyDetector
    detector = AnomalyDetector(contamination="auto", random_state=args.seed)
    # Fit strictly on train
    detector.fit(Dataset(X=np.array([]), events=train_ev))
    print(f"    Detector entrenado correctamente.")

    # 4. Evaluación ML en Validación (Distribución y separación pura)
    print(f"\n[4] Análisis de ML en Validation...")
    val_X = detector.extractor.extract_batch(val_ev)
    val_dataset = Dataset(X=val_X, y=y_val, events=val_ev)
    val_scores = detector.predict_proba(val_dataset)
    
    ml_val_metrics = compute_metrics(y_val, (val_scores > 0.5).astype(int), val_scores)
    print(f"    ROC-AUC puro ML (Val): {ml_val_metrics.get('roc_auc', 0):.4f}")

    # 5. Ablation Study Pipeline sobre Test
    print(f"\n[5] Ejecutando Matriz de Ablation en Test...")
    configs = {
        "A_Sigma":       {"enable_ml": False, "enable_temporal": False, "enable_cti": False, "enable_rag": False, "enable_llm": False},
        "B_Sigma_ML":    {"enable_ml": True,  "enable_temporal": False, "enable_cti": False, "enable_rag": False, "enable_llm": False},
        "C_Sigma_ML_T":  {"enable_ml": True,  "enable_temporal": True,  "enable_cti": False, "enable_rag": False, "enable_llm": False},
        "D_Sigma_ML_T_CTI": {"enable_ml": True, "enable_temporal": True,  "enable_cti": True,  "enable_rag": False, "enable_llm": False},
        "E_Full_System": {"enable_ml": True,  "enable_temporal": True,  "enable_cti": True,  "enable_rag": True,  "enable_llm": True},
    }
    
    rules_dir = str(ROOT / "config" / "rules")
    ablation_results = run_ablation(test_ev, y_test, configs, detector, rules_dir)
    
    # 6. Almacenamiento Estructurado
    results_dir = ROOT / "results" / f"run_{run_id}"
    results_dir.mkdir(parents=True, exist_ok=True)
    
    metadata = {
        "run_id": run_id,
        "seed": args.seed,
        "executed_at": executed_at,
        "dataset_hash_sha256": dataset_hash,
        "splits": {
            "total": len(all_events),
            "train": len(train_ev),
            "val": len(val_ev),
            "test": len(test_ev)
        },
        "ml_val_metrics": ml_val_metrics,
        "ablation": ablation_results
    }
    
    out_file = results_dir / "report.json"
    with open(out_file, "w") as f:
        json.dump(metadata, f, indent=2)
        
    print(f"\n[OK] Validación Científica completada. Resultados en {results_dir}")

if __name__ == "__main__":
    main()
