#!/usr/bin/env python3
"""
Auditoría de Distribution Shift (Fase 4.1).
Compara métricas (Mean, Std, Min, Max) de las características extraídas
entre Train, Validation y Test, buscando divergencias críticas.
"""
import sys
from pathlib import Path
from datetime import datetime, timezone
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from cybersentinel.ml.dataset import TimeBasedSplitter
from cybersentinel.detection.anomaly import AnomalyDetector
from cybersentinel.ml.base import Dataset
from scripts.train_eval_iforest import generate_benign_background, load_synthetic_sysmon

def print_stats(name, X, feature_names):
    print(f"\n--- {name} (N={X.shape[0]}) ---")
    if X.shape[0] == 0:
        return
    means = X.mean(axis=0)
    stds = X.std(axis=0)
    mins = X.min(axis=0)
    maxs = X.max(axis=0)
    
    for i, fname in enumerate(feature_names):
        flag = ""
        if stds[i] < 1e-5:
            flag = " [ZERO VARIANCE]"
        print(f"{fname[:20]:<20} | Mean: {means[i]:7.3f} | Std: {stds[i]:7.3f} | Min: {mins[i]:7.3f} | Max: {maxs[i]:7.3f}{flag}")

def main():
    print("[*] Generando dataset extendido (72 horas)...")
    base_time = datetime(2026, 9, 15, 0, 0, tzinfo=timezone.utc)
    benign_events = generate_benign_background(n_events=3000, start_time=base_time)
    attack_events = load_synthetic_sysmon()
    
    # Aseguramos que los ataques sucedan en el periodo de test (por ejemplo sumando horas)
    # Los ataques ya estan fijados en "2026-09-15T12:XX:XX" que cae en las primeras 12 horas.
    # Dado que ahora abarcamos 72 horas, los ataques caerían en TRAIN si los dejamos ahí.
    # Modificaremos los eventos de ataque en memoria para que caigan en la hora 70 (Test puro).
    for e in attack_events:
        e.timestamp = base_time + type(base_time - base_time)(hours=70) + type(base_time - base_time)(minutes=e.timestamp.minute)

    all_events = benign_events + attack_events
    
    print("[*] Ejecutando TimeBasedSplitter...")
    splitter = TimeBasedSplitter(train_ratio=0.6, val_ratio=0.2)
    train_ev, val_ev, test_ev = splitter.split(all_events)
    
    detector = AnomalyDetector()
    detector.extractor.fit(train_ev)
    
    train_X = detector.extractor.extract_batch(train_ev)
    val_X = detector.extractor.extract_batch(val_ev)
    test_X = detector.extractor.extract_batch(test_ev)
    
    fnames = detector.extractor.FEATURE_NAMES
    print_stats("TRAIN", train_X, fnames)
    print_stats("VALIDATION", val_X, fnames)
    print_stats("TEST", test_X, fnames)

    print("\n[*] Auditoría de Features Finalizada.")

if __name__ == "__main__":
    main()
