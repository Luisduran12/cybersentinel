#!/usr/bin/env python3
"""
Evaluación científica del modelo Isolation Forest para CyberSentinel (Fase 4).
Garantiza cero data leakage utilizando separación temporal.
"""
import sys
import json
from pathlib import Path
from datetime import datetime, timedelta, timezone
import numpy as np
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score, average_precision_score

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cybersentinel.schema import SecurityEvent
from cybersentinel.ingestion import Normalizer
from cybersentinel.ml.dataset import TimeBasedSplitter
from cybersentinel.ml.base import Dataset
from cybersentinel.detection.anomaly import AnomalyDetector

def load_synthetic_sysmon() -> list[SecurityEvent]:
    path = ROOT / "data" / "synthetic_sysmon_eval.json"
    with open(path, "r") as f:
        data = json.load(f)
    return Normalizer().normalize(data)

def generate_benign_background(n_events: int = 1000, start_time: datetime = None) -> list[SecurityEvent]:
    import random
    rng = random.Random(42)
    start = start_time or datetime(2026, 9, 15, 0, 0, tzinfo=timezone.utc)
    
    events = []
    for i in range(n_events):
        # Distribuidos uniformemente a lo largo de 72 horas para abarcar ciclos completos dia/noche
        ts = start + timedelta(seconds=rng.randint(0, 72 * 3600))
        host = rng.choice(["WKS-01", "WKS-02", "SRV-01"])
        user = rng.choice(["ana", "carlos", "system"])
        
        # Simulamos procesos benignos repetitivos
        cmd = rng.choice([
            "chrome.exe --type=renderer",
            "svchost.exe -k netsvcs",
            "explorer.exe",
            "taskhostw.exe",
            "conhost.exe 0xffffffff"
        ])
        
        # Inyectar atributos Sysmon en un 30% del tráfico benigno
        properties = {}
        if rng.random() < 0.3:
            properties["hashes"] = "SHA256=1234567890ABCDEF"
        if rng.random() < 0.3:
            properties["parent_command_line"] = "services.exe"
            
        events.append(SecurityEvent(
            event_id=f"benign_{i}",
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

def main():
    print("=== CyberSentinel ML Evaluation ===")
    
    # 1. Preparar dataset
    print("[*] Generando dataset híbrido...")
    base_time = datetime(2026, 9, 15, 0, 0, tzinfo=timezone.utc)
    benign_events = generate_benign_background(n_events=2000, start_time=base_time)
    
    # Los ataques suceden alrededor de la hora 70, por lo que caerán al final (Test)
    attack_events = load_synthetic_sysmon()
    for e in attack_events:
        e.timestamp = base_time + type(base_time - base_time)(hours=70) + type(base_time - base_time)(minutes=e.timestamp.minute)
    
    all_events = benign_events + attack_events
    # Etiquetas reales (Ground truth): 1 para ataque, 0 para benigno
    # NOTA: Esto solo se usa para evaluación, el modelo NO lo ve.
    labels_map = {e.event_id: (1 if "benign" not in e.event_id else 0) for e in all_events}
    
    # 2. Separación Temporal Estricta
    print("[*] Ejecutando TimeBasedSplitter (0.6, 0.2, 0.2)...")
    splitter = TimeBasedSplitter(train_ratio=0.6, val_ratio=0.2)
    train_ev, val_ev, test_ev = splitter.split(all_events)
    
    print(f"    Train: {len(train_ev)} eventos (Ataques: {sum(labels_map[e.event_id] for e in train_ev)})")
    print(f"    Val:   {len(val_ev)} eventos (Ataques: {sum(labels_map[e.event_id] for e in val_ev)})")
    print(f"    Test:  {len(test_ev)} eventos (Ataques: {sum(labels_map[e.event_id] for e in test_ev)})")
    
    # 3. Entrenamiento Completo (Baseline)
    print("\n[*] Entrenando Modelo Baseline...")
    detector = AnomalyDetector(contamination="auto", random_state=42)
    train_dataset = Dataset(X=np.array([]), events=train_ev)
    detector.fit(train_dataset)
    
    # 4. Evaluación Científica (Sobre Test)
    test_X = detector.extractor.extract_batch(test_ev)
    test_y = np.array([labels_map[e.event_id] for e in test_ev])
    test_dataset = Dataset(X=test_X, y=test_y, events=test_ev)
    
    preds = detector.predict(test_dataset)
    scores = detector.predict_proba(test_dataset)
    binary_preds = (preds == -1).astype(int)
    
    # Generar reportes
    import csv
    reports_dir = ROOT / "reports"
    reports_dir.mkdir(exist_ok=True)
    
    fp_list = []
    tp_list = []
    
    # Normalizar Xn para obtener top features
    Xn = (test_X - detector._means) / detector._stds
    for idx, (event, score, pred, label, xn_vec) in enumerate(zip(test_ev, scores, binary_preds, test_y, Xn)):
        deviations = np.abs(xn_vec)
        top_idx = np.argsort(deviations)[::-1][:3]
        top_features = [(detector.extractor.FEATURE_NAMES[i], round(float(deviations[i]), 4)) for i in top_idx]
        
        ev_dict = {
            "event_id": event.event_id,
            "timestamp": event.timestamp.isoformat(),
            "command_line": event.command_line,
            "score": round(float(score), 4),
            "is_anomaly": bool(pred),
            "true_label": int(label),
            "top_features": top_features
        }
        if pred == 1 and label == 0:
            fp_list.append(ev_dict)
        elif pred == 1 and label == 1:
            tp_list.append(ev_dict)

    with open(reports_dir / "iforest_false_positive_analysis.json", "w") as f:
        json.dump(fp_list, f, indent=2)

    with open(reports_dir / "iforest_true_positive_analysis.json", "w") as f:
        json.dump(tp_list, f, indent=2)
        
    # Análisis de Thresholds
    thresholds = [0.5, 0.55, 0.6, 0.65, 0.7, 0.75, 0.8, 0.85, 0.9]
    with open(reports_dir / "iforest_threshold_analysis.csv", "w", newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["threshold", "precision", "recall", "f1", "fpr", "tp", "fp", "fn", "tn"])
        
        for th in thresholds:
            th_preds = (scores >= th).astype(int)
            from sklearn.metrics import confusion_matrix
            tn, fp, fn, tp = confusion_matrix(test_y, th_preds, labels=[0, 1]).ravel()
            precision = precision_score(test_y, th_preds, zero_division=0)
            recall = recall_score(test_y, th_preds, zero_division=0)
            f1 = f1_score(test_y, th_preds, zero_division=0)
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
            writer.writerow([th, precision, recall, f1, fpr, tp, fp, fn, tn])
    
    # 5. Métricas Baseline
    print("\n=== Resultados Baseline ===")
    if len(set(test_y)) > 1:
        roc_auc = roc_auc_score(test_y, scores)
        pr_auc = average_precision_score(test_y, scores)
        precision = precision_score(test_y, binary_preds, zero_division=0)
        recall = recall_score(test_y, binary_preds, zero_division=0)
        f1 = f1_score(test_y, binary_preds, zero_division=0)
        
        print(f"ROC-AUC:   {roc_auc:.4f}")
        print(f"PR-AUC:    {pr_auc:.4f}")
        print(f"Precision: {precision:.4f}")
        print(f"Recall:    {recall:.4f}")
        print(f"F1-Score:  {f1:.4f}")
    else:
        print("NOT AVAILABLE — INSUFFICIENT LABELS")
        
    # 6. Ablation Study
    print("\n=== Ablation Study ===")
    
    # A. Solo features de red y proceso (sin temporales/cíclicas)
    # Indices temporales en extractor: hour_sin, hour_cos, is_night, events_in_window, time_since_prev_log
    # Corresponden a los últimos 5
    from sklearn.ensemble import IsolationForest
    
    def run_ablation(name, X_train, X_test):
        if X_train.shape[1] == 0:
            return
        means = X_train.mean(axis=0)
        stds = X_train.std(axis=0)
        stds[stds < 1e-5] = 1.0
        Xn_tr = (X_train - means) / stds
        
        mdl = IsolationForest(contamination="auto", random_state=42).fit(Xn_tr)
        Xn_te = (X_test - means) / stds
        p = (mdl.predict(Xn_te) == -1).astype(int)
        
        prec = precision_score(test_y, p, zero_division=0)
        rec = recall_score(test_y, p, zero_division=0)
        f1 = f1_score(test_y, p, zero_division=0)
        print(f"[{name}] Precision: {prec:.4f} | Recall: {rec:.4f} | F1: {f1:.4f}")

    run_ablation("A. Red + Proceso (Sin Temporal)", train_X := detector.extractor.extract_batch(train_ev)[:, :-5], test_X[:, :-5])
    run_ablation("B. Completo (Red + Proceso + Temporal)", train_X := detector.extractor.extract_batch(train_ev), test_X)

    # 7. Comparación Sigma vs ML
    print("\n=== Comparación Evidencia (Sigma vs ML) ===")
    from cybersentinel.detection import RulesEngine
    from cybersentinel.detection.hybrid import DetectionEvidence
    
    engine = RulesEngine.from_directory(ROOT / "config" / "rules")
    
    sigma_hits = 0
    ml_hits = 0
    hybrid_hits = 0
    
    for ev, score, p, y in zip(test_ev, scores, binary_preds, test_y):
        rule_hits = engine.evaluate_event(ev)
        
        evidence = DetectionEvidence(
            event_id=ev.event_id,
            rule_matches=rule_hits,
            anomaly_score=score
        )
        
        has_sigma = len(rule_hits) > 0
        has_ml = bool(p == 1)
        # Consideramos hybrid alert si score > 50 (Sigma aporta 50, ML boost aporta hasta 20)
        has_hybrid = evidence.hybrid_score >= 50.0
        
        if has_sigma: sigma_hits += 1
        if has_ml: ml_hits += 1
        if has_hybrid: hybrid_hits += 1
        
    print(f"Alertas Sigma: {sigma_hits} (Solo ataques con firma determinista)")
    print(f"Alertas ML:    {ml_hits} (Incluye anomalías sin firma - falsos positivos)")
    print(f"Alertas Híbrido: {hybrid_hits} (Filtro por alta confianza combinada)")
    
    with open(reports_dir / "experiment_reproducibility.json", "w") as f:
        json.dump({
            "version": "1.1",
            "seed": 42,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "model": "IsolationForest",
            "hyperparameters": {"contamination": "auto", "n_estimators": 200}
        }, f, indent=2)

if __name__ == "__main__":
    main()
