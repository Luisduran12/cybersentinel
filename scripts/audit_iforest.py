#!/usr/bin/env python3
"""
Auditoría científica del baseline de Isolation Forest (Fase 4.1).
Recopila datos para el análisis de distribución, Falsos Positivos, Verdaderos
Positivos y thresholds.
"""
import sys
import json
import csv
from pathlib import Path
from datetime import datetime, timezone
import numpy as np
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from cybersentinel.ml.dataset import TimeBasedSplitter
from cybersentinel.ml.base import Dataset
from cybersentinel.detection.anomaly import AnomalyDetector
from scripts.train_eval_iforest import generate_benign_background, load_synthetic_sysmon

def get_event_dict(event, score, is_anomaly, top_features, label):
    return {
        "event_id": event.event_id,
        "timestamp": event.timestamp.isoformat(),
        "command_line": event.command_line,
        "score": round(float(score), 4),
        "is_anomaly": is_anomaly,
        "true_label": label,
        "top_features": [(k, round(float(v), 4)) for k, v in top_features]
    }

def main():
    print("[*] Iniciando auditoría...")
    reports_dir = ROOT / "reports"
    reports_dir.mkdir(exist_ok=True)

    base_time = datetime(2026, 9, 15, 0, 0, tzinfo=timezone.utc)
    benign_events = generate_benign_background(n_events=2000, start_time=base_time)
    attack_events = load_synthetic_sysmon()
    
    all_events = benign_events + attack_events
    labels_map = {e.event_id: (1 if "benign" not in e.event_id else 0) for e in all_events}

    splitter = TimeBasedSplitter(train_ratio=0.6, val_ratio=0.2)
    train_ev, val_ev, test_ev = splitter.split(all_events)

    # 1. Class Distribution
    dist = {
        "total": len(all_events),
        "total_attacks": sum(labels_map[e.event_id] for e in all_events),
        "train": {"total": len(train_ev), "attacks": sum(labels_map[e.event_id] for e in train_ev)},
        "val": {"total": len(val_ev), "attacks": sum(labels_map[e.event_id] for e in val_ev)},
        "test": {"total": len(test_ev), "attacks": sum(labels_map[e.event_id] for e in test_ev)}
    }
    with open(reports_dir / "class_distribution.json", "w") as f:
        json.dump(dist, f, indent=2)

    # 2. Training Model
    detector = AnomalyDetector(contamination="auto", random_state=42)
    train_dataset = Dataset(X=np.array([]), events=train_ev)
    detector.fit(train_dataset)

    # 3. Extracting and scoring Test set
    test_X = detector.extractor.extract_batch(test_ev)
    test_y = np.array([labels_map[e.event_id] for e in test_ev])
    test_dataset = Dataset(X=test_X, y=test_y, events=test_ev)
    
    # Calculate baseline mean/std for explainability
    Xn = (test_X - detector._means) / detector._stds
    scores = detector.predict_proba(test_dataset)
    binary_preds = (detector.predict(test_dataset) == -1).astype(int)

    # Análisis de FP y TP
    fp_list = []
    tp_list = []
    tn_list = []
    fn_list = []

    for idx, (event, score, pred, label, xn_vec) in enumerate(zip(test_ev, scores, binary_preds, test_y, Xn)):
        # Calculate top features manually for explainability
        deviations = np.abs(xn_vec)
        top_idx = np.argsort(deviations)[::-1][:3]
        top_features = [(detector.extractor.FEATURE_NAMES[i], deviations[i]) for i in top_idx]

        ev_dict = get_event_dict(event, score, bool(pred), top_features, int(label))
        
        if pred == 1 and label == 0:
            fp_list.append(ev_dict)
        elif pred == 1 and label == 1:
            tp_list.append(ev_dict)
        elif pred == 0 and label == 0:
            tn_list.append(ev_dict)
        elif pred == 0 and label == 1:
            fn_list.append(ev_dict)

    with open(reports_dir / "iforest_false_positive_analysis.json", "w") as f:
        json.dump(fp_list, f, indent=2)

    # Guardar TP para análisis de Recall
    with open(reports_dir / "iforest_true_positive_analysis.json", "w") as f:
        json.dump(tp_list, f, indent=2)
        
    # Guardar TN y FN sample para análisis
    with open(reports_dir / "iforest_sample_tn_fn.json", "w") as f:
        json.dump({"TN_sample": tn_list[:10], "FN": fn_list}, f, indent=2)

    # 4. Threshold Sweep
    thresholds = [0.5, 0.55, 0.6, 0.65, 0.7, 0.75, 0.8, 0.85, 0.9, 0.95, 0.99]
    with open(reports_dir / "iforest_threshold_analysis.csv", "w", newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["threshold", "precision", "recall", "f1", "fpr", "tp", "fp", "fn", "tn"])
        
        for th in thresholds:
            th_preds = (scores >= th).astype(int)
            tn, fp, fn, tp = confusion_matrix(test_y, th_preds, labels=[0, 1]).ravel()
            precision = precision_score(test_y, th_preds, zero_division=0)
            recall = recall_score(test_y, th_preds, zero_division=0)
            f1 = f1_score(test_y, th_preds, zero_division=0)
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
            writer.writerow([th, precision, recall, f1, fpr, tp, fp, fn, tn])

    # Confusion Matrix
    cm_dict = {
        "threshold": 0.5,
        "TP": len(tp_list),
        "FP": len(fp_list),
        "TN": len(tn_list),
        "FN": len(fn_list)
    }
    with open(reports_dir / "iforest_confusion_matrix.json", "w") as f:
        json.dump(cm_dict, f, indent=2)

    # Experiment reproducibility 
    exp_config = {
        "version": "1.0",
        "seed": 42,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "model": "IsolationForest",
        "hyperparameters": {
            "contamination": "auto",
            "n_estimators": 200,
            "random_state": 42
        },
        "features": detector.extractor.FEATURE_NAMES,
    }
    with open(reports_dir / "experiment_reproducibility.json", "w") as f:
        json.dump(exp_config, f, indent=2)
        
    print("[*] Auditoría finalizada. Reportes generados en 'reports/'.")

if __name__ == "__main__":
    main()
