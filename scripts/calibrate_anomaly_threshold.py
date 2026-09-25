"""
Calibración del umbral de decisión del detector de anomalías (Isolation
Forest) sobre el mismo tráfico sintético del test de carga real de la
auditoría de producción (1.020 eventos, semilla 42, 5% sospechosos).

No inventa datos nuevos: reproduce DETERMINISTAMENTE la misma secuencia de
eventos que generó `scripts/telemetry_generator.py --rate 17 --seconds 60`
(mismo `random.Random(42)`, mismas 1.020 llamadas a `genera_evento`), porque
ese generador nunca guarda ni el evento crudo ni su etiqueta real — solo el
resumen agregado que ya está en `docs/evidence_production_audit/`.

La etiqueta real de cada evento ("sospechoso" = generado por la rama de
ataque de `genera_evento`, "benigno" = generado por la rama normal) se
reconstruye inspeccionando el propio contenido del evento contra las firmas
que solo esa rama puede producir (ver `_es_realmente_sospechoso`), no
interceptando el generador de números aleatorios: es la forma más honesta de
obtener la verdad de terreno sin modificar `telemetry_generator.py`.

Metodología (train / validation / test, sin fuga de datos):
  1. TRAIN (50%, aleatorio estratificado): entrena el `AnomalyDetector` real
     tal cual lo hace producción — sobre lo que le toque, incluida la
     contaminación natural del 5% de eventos sospechosos que un cold-start
     real también tendría que tragarse.
  2. VALIDATION (25%): se usa exclusivamente para barrer umbrales candidatos
     y elegir el que mejor cumple los objetivos (FPR<15%, Recall>60%).
  3. TEST (25%, nunca visto durante la selección): se usa solo para reportar
     el FPR/Recall final, para que el número publicado no esté inflado por
     haberse elegido a la medida del propio conjunto que lo mide.

LIMITACIÓN HONESTA: ~51 eventos sospechosos en total (5% de 1.020), por lo
que cada partición tiene ~12-13 positivos. Es una muestra pequeña — los
intervalos de confianza son anchos y un único evento mal clasificado mueve
el recall varios puntos. Ver la nota en el informe de calibración.
"""
from __future__ import annotations

import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from telemetry_generator import genera_evento, SOSPECHOSOS  # noqa: E402

from cybersentinel.detection.anomaly import AnomalyDetector  # noqa: E402
from cybersentinel.ingestion.normalizer import Normalizer  # noqa: E402
from cybersentinel.ml.base import Dataset  # noqa: E402

# Mismos parámetros que el test de carga real de la auditoría de producción.
SEED = 42
RATE = 17
SECONDS = 60
SUSPICIOUS_RATIO = 0.05
N_EVENTS = RATE * SECONDS  # 1020

# Semilla de la partición train/validation/test — independiente de la
# semilla de generación de eventos, y fija para que este informe sea
# reproducible.
SPLIT_SEED = 123

_COMANDOS_SOSPECHOSOS = {cmd for _, cmd in SOSPECHOSOS}


def _es_realmente_sospechoso(evento: dict[str, Any]) -> bool:
    """
    Verdad de terreno reconstruida del propio contenido del evento.

    Por construcción de `genera_evento`, cada uno de estos tres rasgos es
    exclusivo de la rama de ataque: la rama benigna nunca emite `source`
    "auth", nunca usa el puerto 4444, y sus comandos nunca coinciden con los
    de `SOSPECHOSOS` (llevan siempre un número aleatorio de sufijo).
    """
    if evento.get("source") == "auth":
        return True
    if evento.get("source") == "firewall" and evento.get("dst_port") == 4444:
        return True
    if evento.get("source") == "sysmon" and evento.get("command_line") in _COMANDOS_SOSPECHOSOS:
        return True
    return False


def _generar_eventos_etiquetados() -> list[tuple[dict[str, Any], bool]]:
    rng = random.Random(SEED)
    base = datetime.now(tz=timezone.utc)
    salida = []
    for i in range(N_EVENTS):
        momento = base + timedelta(milliseconds=i * 10)
        crudo = genera_evento(rng, momento, SUSPICIOUS_RATIO)
        salida.append((crudo, _es_realmente_sospechoso(crudo)))
    return salida


def _fpr_recall(scores: np.ndarray, etiquetas: np.ndarray, umbral: float) -> tuple[float, float]:
    pred_anomalo = scores >= umbral
    benignos = ~etiquetas
    sospechosos = etiquetas

    fp = int(np.sum(pred_anomalo & benignos))
    tn = int(np.sum(~pred_anomalo & benignos))
    tp = int(np.sum(pred_anomalo & sospechosos))
    fn = int(np.sum(~pred_anomalo & sospechosos))

    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    return fpr, recall


def main() -> None:
    etiquetados = _generar_eventos_etiquetados()
    n_sospechosos = sum(1 for _, es in etiquetados if es)
    print(f"Eventos generados: {len(etiquetados)} ({n_sospechosos} sospechosos reales, "
          f"{n_sospechosos / len(etiquetados):.1%})")

    normalizador = Normalizer()
    eventos_normalizados = [normalizador.normalize_record(dict(crudo)) for crudo, _ in etiquetados]
    etiquetas = np.array([es for _, es in etiquetados])

    # --- Partición estratificada train/validation/test, sin fuga -----------
    idx_benignos = np.where(~etiquetas)[0]
    idx_sospechosos = np.where(etiquetas)[0]
    rng_split = np.random.RandomState(SPLIT_SEED)
    rng_split.shuffle(idx_benignos)
    rng_split.shuffle(idx_sospechosos)

    def _partir(indices: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        n = len(indices)
        n_train = int(n * 0.5)
        n_val = int(n * 0.25)
        return indices[:n_train], indices[n_train:n_train + n_val], indices[n_train + n_val:]

    train_b, val_b, test_b = _partir(idx_benignos)
    train_s, val_s, test_s = _partir(idx_sospechosos)

    idx_train = np.sort(np.concatenate([train_b, train_s]))
    idx_val = np.sort(np.concatenate([val_b, val_s]))
    idx_test = np.sort(np.concatenate([test_b, test_s]))

    print(f"TRAIN:      {len(idx_train)} eventos ({len(train_s)} sospechosos)")
    print(f"VALIDATION: {len(idx_val)} eventos ({len(val_s)} sospechosos)")
    print(f"TEST:       {len(idx_test)} eventos ({len(test_s)} sospechosos)")

    eventos_train = [eventos_normalizados[i] for i in idx_train]

    # --- Entrena el detector REAL, tal cual lo hace producción --------------
    detector = AnomalyDetector()
    detector.fit(Dataset(X=np.array([]), events=eventos_train))
    if not detector.is_fitted:
        raise RuntimeError("El detector no llegó al mínimo de eventos para entrenar.")

    def _scores_de(indices: np.ndarray) -> np.ndarray:
        eventos = [eventos_normalizados[i] for i in indices]
        resultados = detector.score(eventos)
        return np.array([r.anomaly_score for r in resultados])

    scores_val = _scores_de(idx_val)
    etiquetas_val = etiquetas[idx_val]
    scores_test = _scores_de(idx_test)
    etiquetas_test = etiquetas[idx_test]

    # --- Barrido de umbrales sobre VALIDATION únicamente --------------------
    candidatos = sorted(set(np.round(scores_val, 3)) | set(np.round(np.linspace(0, 1, 101), 3)))
    filas = []
    for u in candidatos:
        fpr, recall = _fpr_recall(scores_val, etiquetas_val, u)
        filas.append({"umbral": round(float(u), 3), "fpr_validation": round(fpr, 4),
                      "recall_validation": round(recall, 4)})

    objetivo_fpr = 0.15
    objetivo_recall = 0.60
    factibles = [f for f in filas if f["fpr_validation"] < objetivo_fpr
                and f["recall_validation"] > objetivo_recall]

    umbral_anterior = 0.5
    fpr_anterior, recall_anterior = _fpr_recall(scores_val, etiquetas_val, umbral_anterior)

    if factibles:
        # Estadístico de Youden (recall - fpr) entre los que cumplen ambos
        # objetivos: maximiza la separación real entre detectar ataques y
        # generar ruido, en vez de quedarse con el primero que "pasa".
        elegido = max(factibles, key=lambda f: f["recall_validation"] - f["fpr_validation"])
        honesto = True
    else:
        # Ningún umbral cumple ambos objetivos a la vez: se reporta el mejor
        # compromiso real (máximo Youden J sobre todos los candidatos), sin
        # fingir que se alcanzó la meta.
        elegido = max(filas, key=lambda f: f["recall_validation"] - f["fpr_validation"])
        honesto = False

    fpr_test, recall_test = _fpr_recall(scores_test, etiquetas_test, elegido["umbral"])

    resultado = {
        "metodologia": {
            "dataset": "1020 eventos sintéticos, semilla 42 (idéntico al test de carga real)",
            "n_eventos": len(etiquetados),
            "n_sospechosos_reales": int(n_sospechosos),
            "train": {"n": len(idx_train), "sospechosos": len(train_s)},
            "validation": {"n": len(idx_val), "sospechosos": len(val_s)},
            "test": {"n": len(idx_test), "sospechosos": len(test_s)},
            "objetivo_fpr": objetivo_fpr,
            "objetivo_recall": objetivo_recall,
        },
        "umbral_anterior_0_5": {
            "umbral": umbral_anterior,
            "fpr_validation": round(fpr_anterior, 4),
            "recall_validation": round(recall_anterior, 4),
        },
        "umbral_calibrado": {
            "umbral": elegido["umbral"],
            "cumple_ambos_objetivos_en_validation": honesto,
            "fpr_validation": elegido["fpr_validation"],
            "recall_validation": elegido["recall_validation"],
            "fpr_test_holdout": round(fpr_test, 4),
            "recall_test_holdout": round(recall_test, 4),
        },
        "barrido_completo_validation": filas,
    }

    salida_path = ROOT / "reports" / "anomaly_threshold_calibration.json"
    salida_path.parent.mkdir(parents=True, exist_ok=True)
    salida_path.write_text(json.dumps(resultado, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"\nUmbral anterior (0.5): FPR_val={fpr_anterior:.1%} Recall_val={recall_anterior:.1%}")
    print(f"Umbral calibrado ({elegido['umbral']}): "
          f"FPR_val={elegido['fpr_validation']:.1%} Recall_val={elegido['recall_validation']:.1%}")
    print(f"  -> en TEST (holdout, nunca visto): FPR={fpr_test:.1%} Recall={recall_test:.1%}")
    print(f"  -> ¿cumple FPR<{objetivo_fpr:.0%} y Recall>{objetivo_recall:.0%} en validation? {honesto}")
    print(f"\nInforme completo: {salida_path}")


if __name__ == "__main__":
    main()
