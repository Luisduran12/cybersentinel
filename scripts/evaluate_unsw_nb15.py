"""
Evaluación real de CyberSentinel sobre el dataset oficial UNSW-NB15.

    python scripts/evaluate_unsw_nb15.py --limit 300000

PROTOCOLO
---------
El detector de anomalías es NO SUPERVISADO, lo que impone dos condiciones:

1. Se entrena **solo con tráfico benigno** (`label == 0`). Entrenar con los
   ataques dentro hace que el modelo los aprenda como normalidad.
2. El umbral se elige en VALIDATION y **jamás** en TEST. Ajustarlo sobre el
   conjunto con el que después se reporta convierte la métrica en una
   estimación optimista sin valor.

Partición: los CSV crudos traen marca de tiempo, así que el corte es
**temporal** (60 / 20 / 20 por orden cronológico). Un corte aleatorio permitiría
que un flujo del futuro entrenara al modelo que evalúa el pasado, que es la forma
más común de fuga en datos de red.

QUÉ SE PUEDE Y QUÉ NO SE PUEDE EVALUAR
--------------------------------------
UNSW-NB15 es un dataset de **flujos de red**. CyberSentinel tiene componentes
pensados para telemetría de host. No todo es evaluable, y presentarlo como si lo
fuera produciría una evaluación incorrecta. El script calcula esa elegibilidad a
partir de los datos y la escribe en el reporte.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cybersentinel.data.unsw_nb15_adapter import (  # noqa: E402
    FIELD_MAPPING, UNSWNB15Adapter, UNSWRecord, file_sha256,
)
from cybersentinel.detection.anomaly import AnomalyDetector  # noqa: E402
from cybersentinel.ml.base import Dataset  # noqa: E402
from cybersentinel.ml.features import FeatureExtractor  # noqa: E402
from cybersentinel.observability import new_run_id  # noqa: E402

DATA_DIR = ROOT / "data" / "unsw_nb15"
RESULTS_DIR = ROOT / "results"

#: Características cuya señal depende de campos que UNSW-NB15 no trae.
#: Se calcula empíricamente en `feature_eligibility`, no se asume.
HOST_ONLY_FEATURES = {
    "cmd_len", "cmd_special_chars", "cmd_entropy", "has_hash",
    "has_parent_cmd", "is_process", "user_rarity",
}


# ----------------------------------------------------------------- carga
def count_rows(path: Path) -> int:
    """Cuenta líneas sin cargar el archivo en memoria."""
    with open(path, "rb") as fh:
        return sum(1 for _ in fh)


def load_records(paths: list[Path], limit: int | None) -> list[UNSWRecord]:
    """
    Carga registros repartidos por TODO el periodo de captura.

    Tomar los primeros N registros seria un error grave con este dataset: en
    UNSW-NB15_2.csv el primer ataque aparece en la linea 387 248 de 700 001, de
    modo que una muestra de cabecera contiene **solo trafico benigno** y produce
    un conjunto de una sola clase con el que ninguna metrica tiene sentido.

    Se usa un muestreo sistematico (uno de cada k) que conserva la distribucion
    temporal y la proporcion de ataques del archivo completo.
    """
    adapter = UNSWNB15Adapter()
    if limit is None:
        registros: list[UNSWRecord] = []
        for path in paths:
            registros.extend(adapter.read_csv(path))
        return registros

    total = sum(count_rows(p) for p in paths)
    paso = max(1, total // limit)
    registros = []
    for path in paths:
        for indice, registro in enumerate(adapter.read_csv(path)):
            if indice % paso == 0:
                registros.append(registro)
                if len(registros) >= limit:
                    return registros
    return registros


def temporal_split(
    registros: list[UNSWRecord], ratios: tuple[float, float] = (0.6, 0.2)
) -> tuple[list[UNSWRecord], list[UNSWRecord], list[UNSWRecord]]:
    """
    Corte cronológico TRAIN / VALIDATION / TEST.

    Devuelve tres bloques disjuntos y ordenados en el tiempo: nada de TEST
    precede a nada de TRAIN, de modo que no hay forma de que el modelo vea el
    futuro.
    """
    ordenados = sorted(registros, key=lambda r: r.event.timestamp)
    n = len(ordenados)
    corte_train = int(n * ratios[0])
    corte_val = int(n * (ratios[0] + ratios[1]))
    return ordenados[:corte_train], ordenados[corte_train:corte_val], ordenados[corte_val:]


# ------------------------------------------------------------- elegibilidad
def feature_eligibility(extractor: FeatureExtractor, registros: list[UNSWRecord]) -> dict:
    """
    Mide qué características tienen señal real en estos datos.

    Una característica constante en todo el dataset no aporta nada al modelo;
    reportarla como si contribuyera seria engañoso.
    """
    muestra = [r.event for r in registros[:5000]]
    X = extractor.extract_batch(muestra)
    varianzas = X.std(axis=0)
    detalle = {}
    for nombre, std in zip(extractor.FEATURE_NAMES, varianzas):
        detalle[nombre] = {
            "std": round(float(std), 6),
            "informativa": bool(std > 1e-9),
            "motivo": (
                "constante: el dataset no aporta este campo"
                if std <= 1e-9 else "varía en los datos"
            ),
        }
    informativas = [n for n, d in detalle.items() if d["informativa"]]
    return {
        "n_features_total": len(extractor.FEATURE_NAMES),
        "n_features_informativas": len(informativas),
        "informativas": informativas,
        "detalle": detalle,
    }


def component_eligibility(registros: list[UNSWRecord]) -> dict:
    """
    Qué componentes del pipeline puede evaluar este dataset.

    Se decide por los datos presentes, no por suposiciones.
    """
    tiene_tiempo = not any("timestamp" in r.unavailable for r in registros[:100])
    tiene_ips = not any("ip_addresses" in r.unavailable for r in registros[:100])
    tiene_cmd = any(r.event.command_line for r in registros[:1000])

    return {
        "isolation_forest": {
            "estado": "evaluable",
            "motivo": "el dataset aporta volumen, puertos y estado de conexion",
        },
        "sigma": {
            "estado": "no evaluable",
            "motivo": (
                "las reglas del proyecto son de telemetria de host (linea de "
                "comandos, proceso padre). UNSW-NB15 son flujos de red sin "
                f"linea de comandos (command_line presente: {tiene_cmd}). Una "
                "regla que no puede activarse no mide nada: NO significa que "
                "Sigma no funcione."
            ),
        },
        "correlacion_temporal": {
            "estado": "parcialmente evaluable" if tiene_tiempo else "no evaluable",
            "motivo": (
                "hay marca de tiempo, pero las secuencias definidas encadenan "
                "tecnicas ATT&CK que solo las reglas de host pueden producir"
                if tiene_tiempo else
                "la particion oficial train/test no incluye marca de tiempo"
            ),
        },
        "mitre_attack": {
            "estado": "no evaluable",
            "motivo": (
                "la tecnica ATT&CK se deriva de la regla Sigma que se activa. "
                "Sin activaciones de regla no hay tecnica observada. Las "
                "categorias de UNSW-NB15 (Exploits, Fuzzers...) no son tecnicas "
                "ATT&CK y mapearlas seria inventar una correspondencia."
            ),
        },
        "cti": {
            "estado": "no evaluable",
            "motivo": (
                "las IPs del dataset son de un laboratorio de 2015 "
                f"(direcciones presentes: {tiene_ips}); no existen indicadores "
                "de inteligencia reales para ellas. Fabricarlos invalidaria la "
                "medida."
            ),
        },
        "rag_llm": {
            "estado": "no evaluable",
            "motivo": (
                "producen texto explicativo, no una decision de deteccion: no "
                "hay verdad-terreno contra la que medirlos en este dataset."
            ),
        },
    }


# ----------------------------------------------------------------- métricas
def compute_metrics(y_true: np.ndarray, scores: np.ndarray, threshold: float) -> dict:
    """Métricas completas en un punto de operación."""
    from sklearn.metrics import (
        average_precision_score, precision_recall_curve, roc_auc_score, roc_curve,
    )

    y_pred = (scores >= threshold).astype(int)
    tp = int(np.sum((y_pred == 1) & (y_true == 1)))
    fp = int(np.sum((y_pred == 1) & (y_true == 0)))
    tn = int(np.sum((y_pred == 0) & (y_true == 0)))
    fn = int(np.sum((y_pred == 0) & (y_true == 1)))

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    specificity = tn / (tn + fp) if (tn + fp) else 0.0
    accuracy = (tp + tn) / len(y_true) if len(y_true) else 0.0

    metricas = {
        "threshold": round(float(threshold), 6),
        "TP": tp, "TN": tn, "FP": fp, "FN": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "fpr": round(fpr, 4),
        "specificity": round(specificity, 4),
        "accuracy": round(accuracy, 4),
        "n": int(len(y_true)),
        "positives": int(y_true.sum()),
        "positive_rate": round(float(y_true.mean()), 4),
    }

    # Las curvas necesitan ambas clases presentes.
    if y_true.min() != y_true.max():
        metricas["roc_auc"] = round(float(roc_auc_score(y_true, scores)), 4)
        metricas["pr_auc"] = round(float(average_precision_score(y_true, scores)), 4)
        fpr_c, tpr_c, _ = roc_curve(y_true, scores)
        prec_c, rec_c, _ = precision_recall_curve(y_true, scores)
        metricas["_roc_curve"] = (fpr_c, tpr_c)
        metricas["_pr_curve"] = (rec_c, prec_c)
    else:
        metricas["roc_auc"] = "NOT EVALUABLE (una sola clase)"
        metricas["pr_auc"] = "NOT EVALUABLE (una sola clase)"
    return metricas


def pick_threshold(y_val: np.ndarray, scores_val: np.ndarray) -> tuple[float, list[dict]]:
    """
    Elige el umbral que maximiza F1 **en validación**.

    Devuelve además el barrido completo, para que la decisión sea auditable y no
    un número que aparece sin explicación.
    """
    barrido = []
    mejor = (0.0, 0.5)
    for percentil in np.arange(50, 100, 2.5):
        umbral = float(np.percentile(scores_val, percentil))
        m = compute_metrics(y_val, scores_val, umbral)
        barrido.append({
            "percentile": round(float(percentil), 1), "threshold": m["threshold"],
            "precision": m["precision"], "recall": m["recall"], "f1": m["f1"],
            "fpr": m["fpr"],
        })
        if m["f1"] > mejor[0]:
            mejor = (m["f1"], umbral)
    return mejor[1], barrido


# ------------------------------------------------------------------- main
def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=300_000,
                        help="Maximo de registros a cargar de los CSV crudos.")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--contamination", default="auto")
    parser.add_argument("--n-estimators", type=int, default=200)
    args = parser.parse_args()

    inicio = time.perf_counter()
    run_id = new_run_id()
    RESULTS_DIR.mkdir(exist_ok=True)

    crudos = sorted(DATA_DIR.glob("UNSW-NB15_[0-9].csv"))
    if not crudos:
        print(f"No hay CSV crudos en {DATA_DIR}")
        return 1

    print("=" * 74)
    print("EVALUACION DE CYBERSENTINEL SOBRE UNSW-NB15 (fuente oficial UNSW)")
    print("=" * 74)
    print(f"run_id: {run_id}   seed: {args.seed}")
    print(f"archivos: {', '.join(p.name for p in crudos)}")

    print(f"\nCargando hasta {args.limit:,} registros (muestreo sistematico)...")
    registros = load_records(crudos, args.limit)
    print(f"  cargados: {len(registros):,}")

    y_todos = np.array([r.label for r in registros])
    print(f"  benignos: {int((y_todos == 0).sum()):,}   ataques: {int(y_todos.sum()):,} "
          f"({y_todos.mean():.2%})")
    categorias = Counter(r.attack_cat for r in registros if r.is_attack)
    print(f"  categorias: {dict(categorias.most_common(5))}")

    # --- Particion temporal -------------------------------------------
    train, val, test = temporal_split(registros)
    print(f"\nParticion temporal (sin fuga):")
    for nombre, bloque in (("TRAIN", train), ("VALIDATION", val), ("TEST", test)):
        etiquetas = np.array([r.label for r in bloque])
        print(f"  {nombre:11s} {len(bloque):>8,} registros  "
              f"ataques {etiquetas.mean():.2%}  "
              f"[{bloque[0].event.timestamp:%Y-%m-%d %H:%M} .. "
              f"{bloque[-1].event.timestamp:%Y-%m-%d %H:%M}]")

    benignos_train = [r for r in train if r.label == 0]
    print(f"  Entrenamiento del modelo: SOLO los {len(benignos_train):,} benignos de TRAIN")
    if len(benignos_train) < 100:
        print("  ERROR: muy pocos benignos para aprender una linea base.")
        return 2

    # --- Elegibilidad --------------------------------------------------
    extractor = FeatureExtractor()
    extractor.fit([r.event for r in benignos_train])
    elegibilidad_features = feature_eligibility(extractor, train)
    elegibilidad_componentes = component_eligibility(registros)

    print(f"\nCaracteristicas con senal real: "
          f"{elegibilidad_features['n_features_informativas']}/"
          f"{elegibilidad_features['n_features_total']}")
    inutiles = [n for n, d in elegibilidad_features["detalle"].items()
                if not d["informativa"]]
    print(f"  constantes (el dataset no las alimenta): {inutiles}")

    print("\nElegibilidad por componente:")
    for comp, info in elegibilidad_componentes.items():
        print(f"  {comp:22s} {info['estado']}")

    # --- Entrenamiento --------------------------------------------------
    print("\nEntrenando Isolation Forest...")
    t0 = time.perf_counter()
    detector = AnomalyDetector(
        contamination=args.contamination, random_state=args.seed,
        n_estimators=args.n_estimators,
    )
    detector.extractor = extractor
    detector.fit(Dataset(X=np.array([]), events=[r.event for r in benignos_train]))
    t_fit = time.perf_counter() - t0
    if not detector.is_fitted:
        print("  ERROR: el modelo no quedo entrenado.")
        return 2
    print(f"  entrenado en {t_fit:.1f}s sobre {len(benignos_train):,} flujos benignos")

    def puntuar(bloque: list[UNSWRecord]) -> np.ndarray:
        X = extractor.extract_batch([r.event for r in bloque])
        return detector.predict_proba(Dataset(X=X))

    scores_val = puntuar(val)
    y_val = np.array([r.label for r in val])
    umbral, barrido = pick_threshold(y_val, scores_val)
    print(f"\nUmbral elegido en VALIDATION (maximo F1): {umbral:.6f}")
    print("  TEST no ha intervenido en esta eleccion.")

    t0 = time.perf_counter()
    scores_test = puntuar(test)
    t_score = time.perf_counter() - t0
    y_test = np.array([r.label for r in test])

    print(f"\nDistribucion del anomaly_score en TEST:")
    print(f"  min={scores_test.min():.6f}  max={scores_test.max():.6f}  "
          f"mean={scores_test.mean():.6f}")
    print(f"  median={np.median(scores_test):.6f}  std={scores_test.std():.6f}  "
          f"valores distintos={len(np.unique(np.round(scores_test, 6))):,}")
    if scores_test.std() < 1e-9:
        print("  ERROR: el score es constante, el modelo no esta puntuando.")
        return 2

    metricas = compute_metrics(y_test, scores_test, umbral)
    print(f"\nMETRICAS EN TEST (n={metricas['n']:,}, ataques={metricas['positive_rate']:.1%})")
    for clave in ("TP", "FP", "TN", "FN", "precision", "recall", "f1",
                  "fpr", "specificity", "accuracy", "roc_auc", "pr_auc"):
        print(f"  {clave:12s} {metricas[clave]}")

    # --- Recall por categoria de ataque ---------------------------------
    y_pred = (scores_test >= umbral).astype(int)
    por_categoria: dict[str, dict] = {}
    for registro, prediccion in zip(test, y_pred):
        if registro.label != 1:
            continue
        d = por_categoria.setdefault(registro.attack_cat, {"total": 0, "detectados": 0})
        d["total"] += 1
        d["detectados"] += int(prediccion)
    for datos in por_categoria.values():
        datos["recall"] = round(datos["detectados"] / datos["total"], 4)

    print("\nRECALL POR CATEGORIA DE ATAQUE")
    for cat, datos in sorted(por_categoria.items(), key=lambda kv: -kv[1]["total"]):
        print(f"  {cat:18s} {datos['detectados']:>6,}/{datos['total']:>6,}  "
              f"recall={datos['recall']:.3f}")

    # --- Ablation --------------------------------------------------------
    print("\nABLATION")
    ablation = run_ablation(train, val, test, benignos_train, args, umbral)
    for fila in ablation:
        if fila["evaluable"]:
            print(f"  {fila['configuracion']:34s} P={fila['precision']:.3f} "
                  f"R={fila['recall']:.3f} F1={fila['f1']:.3f} "
                  f"PR-AUC={fila['pr_auc']}")
        else:
            print(f"  {fila['configuracion']:34s} {fila['nota']}")

    # --- Persistencia ----------------------------------------------------
    duracion = time.perf_counter() - inicio
    hashes = {p.name: file_sha256(p) for p in crudos}
    metadatos = {
        "run_id": run_id,
        "timestamp": datetime.now(tz=timezone.utc).isoformat(timespec="seconds"),
        "dataset": {
            "name": "UNSW-NB15",
            "source": "https://research.unsw.edu.au/projects/unsw-nb15-dataset",
            "files": [p.name for p in crudos],
            "sha256": hashes,
            "records_loaded": len(registros),
            "limit_applied": args.limit,
        },
        "seed": args.seed,
        "model_parameters": {
            "algorithm": "IsolationForest",
            "contamination": args.contamination,
            "n_estimators": args.n_estimators,
            "random_state": args.seed,
            "trained_on": "solo flujos benignos de TRAIN",
            "n_training_records": len(benignos_train),
        },
        "feature_mapping": FIELD_MAPPING,
        "feature_eligibility": elegibilidad_features,
        "component_eligibility": elegibilidad_componentes,
        "split": {
            "method": "temporal 60/20/20 por orden cronologico",
            "train": len(train), "validation": len(val), "test": len(test),
            "threshold_selected_on": "VALIDATION",
        },
        "threshold": float(umbral),
        "threshold_sweep_validation": barrido,
        "score_distribution_test": {
            "min": float(scores_test.min()), "max": float(scores_test.max()),
            "mean": float(scores_test.mean()), "median": float(np.median(scores_test)),
            "std": float(scores_test.std()),
            "distinct_values": int(len(np.unique(np.round(scores_test, 6)))),
        },
        "execution_time_s": round(duracion, 2),
        "fit_time_s": round(t_fit, 2),
        "score_time_s": round(t_score, 2),
        "throughput_events_per_s": round(len(test) / t_score, 1) if t_score else None,
    }

    publicas = {k: v for k, v in metricas.items() if not k.startswith("_")}
    (RESULTS_DIR / "unsw_nb15_metrics.json").write_text(
        json.dumps({"run_id": run_id, "test_metrics": publicas,
                    "recall_by_category": por_categoria}, indent=2, ensure_ascii=False),
        encoding="utf-8")
    (RESULTS_DIR / "unsw_nb15_run_metadata.json").write_text(
        json.dumps(metadatos, indent=2, ensure_ascii=False), encoding="utf-8")

    with open(RESULTS_DIR / "unsw_nb15_confusion_matrix.csv", "w", newline="",
              encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["", "predicho_ataque", "predicho_benigno"])
        w.writerow(["real_ataque", metricas["TP"], metricas["FN"]])
        w.writerow(["real_benigno", metricas["FP"], metricas["TN"]])

    with open(RESULTS_DIR / "unsw_nb15_predictions.csv", "w", newline="",
              encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["unsw_row_id", "timestamp", "anomaly_score", "prediction",
                    "label", "attack_cat"])
        for registro, score, pred in zip(test, scores_test, y_pred):
            w.writerow([registro.unsw_row_id, registro.event.timestamp.isoformat(),
                        round(float(score), 6), int(pred), registro.label,
                        registro.attack_cat])

    with open(RESULTS_DIR / "unsw_nb15_ablation.csv", "w", newline="",
              encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["configuracion", "evaluable", "precision", "recall", "f1",
                    "pr_auc", "roc_auc", "nota"])
        for fila in ablation:
            w.writerow([fila["configuracion"], fila["evaluable"],
                        fila.get("precision", ""), fila.get("recall", ""),
                        fila.get("f1", ""), fila.get("pr_auc", ""),
                        fila.get("roc_auc", ""), fila.get("nota", "")])

    # Curvas para las figuras (datos, no imagenes).
    if "_roc_curve" in metricas:
        fpr_c, tpr_c = metricas["_roc_curve"]
        rec_c, prec_c = metricas["_pr_curve"]
        paso = max(1, len(fpr_c) // 2000)
        with open(RESULTS_DIR / "unsw_nb15_curves.csv", "w", newline="",
                  encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["curve", "x", "y"])
            for x, y in zip(fpr_c[::paso], tpr_c[::paso]):
                w.writerow(["roc", round(float(x), 6), round(float(y), 6)])
            paso_pr = max(1, len(rec_c) // 2000)
            for x, y in zip(rec_c[::paso_pr], prec_c[::paso_pr]):
                w.writerow(["pr", round(float(x), 6), round(float(y), 6)])

    print(f"\nResultados en {RESULTS_DIR}/")
    print(f"Tiempo total: {duracion:.1f}s")
    return 0


def run_ablation(train, val, test, benignos_train, args, umbral_ml) -> list[dict]:
    """
    Ablación honesta.

    Solo se reporta una métrica cuando el componente puede contribuir a la
    decisión sobre este dataset. Donde no puede, la fila dice por qué en lugar
    de mostrar un número que pareceria una comparación.
    """
    from cybersentinel.detection.temporal import TemporalCorrelator

    filas: list[dict] = []
    y_test = np.array([r.label for r in test])

    # --- A: solo Isolation Forest ---
    extractor = FeatureExtractor()
    extractor.fit([r.event for r in benignos_train])
    detector = AnomalyDetector(contamination=args.contamination,
                               random_state=args.seed, n_estimators=args.n_estimators)
    detector.extractor = extractor
    detector.fit(Dataset(X=np.array([]), events=[r.event for r in benignos_train]))
    scores = detector.predict_proba(
        Dataset(X=extractor.extract_batch([r.event for r in test]))
    )
    m = compute_metrics(y_test, scores, umbral_ml)
    filas.append({
        "configuracion": "A. Isolation Forest", "evaluable": True,
        "precision": m["precision"], "recall": m["recall"], "f1": m["f1"],
        "pr_auc": m["pr_auc"], "roc_auc": m["roc_auc"],
        "nota": "unico componente con verdad-terreno en este dataset",
    })

    # --- B: ML + correlacion temporal ---
    correlador = TemporalCorrelator.from_yaml(ROOT / "config" / "sequences.yaml")
    filas.append({
        "configuracion": "B. + Correlacion temporal", "evaluable": False,
        "nota": (
            f"NOT EVALUABLE: las {len(correlador.rules)} secuencias encadenan "
            "tecnicas ATT&CK que solo producen las reglas de host; sobre flujos "
            "de red no se activa ninguna, asi que no puede aportar ni restar."
        ),
    })

    # --- C: sistema completo ---
    filas.append({
        "configuracion": "C. Sistema completo", "evaluable": False,
        "nota": (
            "NOT EVALUABLE: Sigma, ATT&CK, CTI y RAG no son aplicables a este "
            "dataset (ver component_eligibility). Presentar una cifra aqui "
            "seria atribuir al sistema completo el merito del unico componente "
            "que si participa."
        ),
    })
    return filas


if __name__ == "__main__":
    sys.exit(main())
