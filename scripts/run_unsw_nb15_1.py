"""
EVALUACION EXPLORATORIA de CyberSentinel sobre UNSW-NB15_1.csv.

    python scripts/run_unsw_nb15_1.py --stage 100
    python scripts/run_unsw_nb15_1.py --stage 1000
    python scripts/run_unsw_nb15_1.py --stage full

Esto NO es la evaluación científica final. Su objetivo es comprobar la cadena
completa sobre un archivo del dataset que todavía no se había procesado:

    UNSW-NB15_1.csv -> adapter -> SecurityEvent -> pipeline -> evidencia

Las etapas pequeñas (100 y 1000 registros) verifican que el pipeline **real**
—sin mocks— procesa el archivo y produce evidencia con estado explícito. La
etapa completa mide el detector sobre el archivo entero.

Protocolo (el mismo de la evaluación principal, para que los números sean
comparables):
  - corte temporal 60/20/20, sin fuga;
  - el Isolation Forest se entrena SOLO con flujos benignos de TRAIN;
  - el umbral se elige en VALIDATION, jamás en TEST.
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
sys.path.insert(0, str(ROOT / "scripts"))

from cybersentinel.data.unsw_nb15_adapter import (  # noqa: E402
    FIELD_MAPPING, UNSWNB15Adapter, file_sha256,
)
from cybersentinel.detection.anomaly import AnomalyDetector  # noqa: E402
from cybersentinel.ml.base import Dataset  # noqa: E402
from cybersentinel.ml.features import FeatureExtractor  # noqa: E402
from cybersentinel.observability import new_run_id  # noqa: E402
from cybersentinel.pipeline import Pipeline  # noqa: E402

from evaluate_unsw_nb15 import (  # noqa: E402
    compute_metrics, count_rows, feature_eligibility, pick_threshold, temporal_split,
)

TARGET = ROOT / "data" / "unsw_nb15" / "UNSW-NB15_1.csv"
RESULTS = ROOT / "results"


def evaluable_window(registros: list) -> tuple[list, dict]:
    """
    Recorta la muestra al periodo en el que existen **ambas clases**.

    `UNSW-NB15_1.csv` tiene una propiedad que invalida un corte temporal ingenuo:
    todos sus ataques ocurren en las primeras dos horas de captura, y a partir de
    ahi hay cientos de miles de flujos sin un solo ataque. Cualquier particion
    cronologica 60/20/20 sobre el archivo entero deja el conjunto TEST con una
    sola clase, y con una sola clase no hay metrica posible.

    La solucion honesta no es cambiar a un corte aleatorio —eso destruiria la
    garantia de no fuga temporal— sino **restringir la evaluacion al periodo en
    el que el fenomeno a detectar existe**, y declararlo.
    """
    ordenados = sorted(registros, key=lambda r: r.event.timestamp)
    ataques = [r for r in ordenados if r.label == 1]
    if not ataques:
        return ordenados, {"restringida": False, "motivo": "no hay ataques en la muestra"}

    ultimo_ataque = ataques[-1].event.timestamp
    recortados = [r for r in ordenados if r.event.timestamp <= ultimo_ataque]
    descartados = len(ordenados) - len(recortados)

    info = {
        "restringida": descartados > 0,
        "inicio": ordenados[0].event.timestamp.isoformat(),
        "fin_evaluable": ultimo_ataque.isoformat(),
        "fin_archivo": ordenados[-1].event.timestamp.isoformat(),
        "registros_totales": len(ordenados),
        "registros_evaluables": len(recortados),
        "registros_descartados": descartados,
        "motivo": (
            "tras el ultimo ataque no queda ninguna clase positiva, asi que un "
            "corte temporal dejaria TEST con una sola clase"
        ),
    }
    return recortados, info


def stage_pipeline(registros: list, etiqueta: str) -> dict:
    """
    Pasa los eventos por el pipeline REAL de CyberSentinel.

    Comprueba que la evidencia llega completa y con el estado de cada etapa
    declarado. No se inyecta ningún doble: si el LLM no está disponible, el
    pipeline lo reporta como UNAVAILABLE con respaldo determinista.
    """
    print(f"\n--- PIPELINE COMPLETO sobre {len(registros)} eventos ({etiqueta}) ---")
    pipeline = Pipeline(rules_dir=ROOT / "config" / "rules")

    print("  componentes:")
    for nombre, estado in pipeline.component_status.items():
        print(f"     {nombre:9s} {estado}")

    t0 = time.perf_counter()
    reporte = pipeline.run_events([r.event for r in registros])
    duracion = time.perf_counter() - t0

    evidencias = [r.evidence for r in reporte.results]
    scores = np.array([e.anomaly_score for e in evidencias])
    estados = Counter(e.detection_status for e in evidencias)

    print(f"  procesados {reporte.total_events} en {duracion:.2f}s "
          f"({reporte.total_events / duracion:,.0f} ev/s)")
    print(f"  run_id: {reporte.run_id}")
    print(f"  hallazgos: {reporte.total_findings}   secuencias: "
          f"{len(reporte.correlated_incidents)}")
    print(f"  detection_status: {dict(estados)}")
    print(f"  anomaly_score: min={scores.min():.6f} max={scores.max():.6f} "
          f"distintos={len(np.unique(np.round(scores, 6)))}")

    # Comprobacion de que la evidencia es explicita en todos sus campos.
    muestra = evidencias[0]
    campos = {
        "run_id": bool(muestra.run_id),
        "event_id": bool(muestra.event_id),
        "event_ref": bool(muestra.event_ref),
        "sigma": muestra.stage_status.get("sigma"),
        "anomaly_score": muestra.stage_status.get("ml"),
        "temporal": muestra.stage_status.get("temporal"),
        "mitre": muestra.mitre_context or "NOT_AVAILABLE",
        "cti": muestra.stage_status.get("cti"),
        "rag": muestra.stage_status.get("rag"),
        "llm_status": muestra.llm_status,
        "latencies": bool(reporte.results[0].trace.to_dict()["latencies_ms"]),
    }
    print("  DetectionEvidence (primer evento):")
    for clave, valor in campos.items():
        print(f"     {clave:14s} {valor}")

    return {
        "stage": etiqueta,
        "n_events": reporte.total_events,
        "run_id": reporte.run_id,
        "seconds": round(duracion, 3),
        "events_per_second": round(reporte.total_events / duracion, 1),
        "findings": reporte.total_findings,
        "correlated_sequences": len(reporte.correlated_incidents),
        "detection_status": dict(estados),
        "component_status": reporte.component_status,
        "evidence_fields": {k: str(v) for k, v in campos.items()},
        "anomaly_score": {
            "min": float(scores.min()), "max": float(scores.max()),
            "mean": float(scores.mean()), "median": float(np.median(scores)),
            "std": float(scores.std()),
            "distinct": int(len(np.unique(np.round(scores, 6)))),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", default="100",
                        help="100 | 1000 | full | <numero de registros>")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--contamination", default="auto")
    parser.add_argument("--n-estimators", type=int, default=200)
    args = parser.parse_args()

    if not TARGET.exists():
        print(f"No existe {TARGET}")
        return 1

    inicio = time.perf_counter()
    run_id = new_run_id()
    RESULTS.mkdir(exist_ok=True)

    print("=" * 74)
    print("EXPLORATORY EVALUATION — UNSW-NB15_1.csv")
    print("=" * 74)
    print(f"run_id: {run_id}   seed: {args.seed}   etapa: {args.stage}")

    limite = None if args.stage == "full" else int(args.stage)
    adapter = UNSWNB15Adapter()

    print(f"\nLeyendo {TARGET.name}...")
    t0 = time.perf_counter()
    if limite is None:
        registros = list(adapter.read_csv(TARGET))
    else:
        # Muestreo sistematico: los ataques de UNSW-NB15 estan concentrados en
        # tramos concretos, asi que una muestra de cabecera puede ser de una
        # sola clase y no medir nada.
        total = count_rows(TARGET)
        paso = max(1, total // limite)
        registros = [
            r for i, r in enumerate(adapter.read_csv(TARGET)) if i % paso == 0
        ][:limite]
    t_lectura = time.perf_counter() - t0
    print(f"  {len(registros):,} registros en {t_lectura:.1f}s")

    etiquetas = np.array([r.label for r in registros])
    categorias = Counter(r.attack_cat for r in registros if r.is_attack)
    print(f"  benignos: {int((etiquetas == 0).sum()):,}   "
          f"ataques: {int(etiquetas.sum()):,} ({etiquetas.mean():.2%})")
    if categorias:
        print(f"  categorias: {dict(categorias.most_common(6))}")
    no_disponible = sorted({c for r in registros[:200] for c in r.unavailable})
    print(f"  NOT_AVAILABLE: {no_disponible or 'ninguno (el archivo trae todo)'}")

    # --- Etapas pequenas: verificar el pipeline completo ------------------
    resumen_pipeline = None
    if limite is not None and limite <= 2000:
        resumen_pipeline = stage_pipeline(registros, args.stage)

    # --- Evaluacion del detector -----------------------------------------
    if etiquetas.min() == etiquetas.max():
        print("\nNOT EVALUABLE: la muestra tiene una sola clase.")
        return 3

    evaluables, ventana = evaluable_window(registros)
    if ventana["restringida"]:
        print(f"\nVentana evaluable: se descartan {ventana['registros_descartados']:,} "
              f"registros posteriores al ultimo ataque.")
        print(f"  {ventana['inicio'][11:19]} .. {ventana['fin_evaluable'][11:19]} "
              f"(el archivo llega hasta {ventana['fin_archivo'][11:19]})")
        print(f"  motivo: {ventana['motivo']}")
        y_ev = np.array([r.label for r in evaluables])
        print(f"  quedan {len(evaluables):,} registros, {y_ev.mean():.2%} ataques")

    train, val, test = temporal_split(evaluables)
    print(f"\nParticion temporal (sin fuga):")
    for nombre, bloque in (("TRAIN", train), ("VALIDATION", val), ("TEST", test)):
        y = np.array([r.label for r in bloque])
        print(f"  {nombre:11s} {len(bloque):>9,}  ataques {y.mean():>6.2%}  "
              f"[{bloque[0].event.timestamp:%Y-%m-%d %H:%M} .. "
              f"{bloque[-1].event.timestamp:%Y-%m-%d %H:%M}]")

    benignos = [r for r in train if r.label == 0]
    print(f"  entrenamiento: SOLO los {len(benignos):,} benignos de TRAIN")
    if len(benignos) < 50:
        print("  NOT EVALUABLE: benignos insuficientes para una linea base.")
        return 3

    extractor = FeatureExtractor()
    extractor.fit([r.event for r in benignos])
    elegibilidad = feature_eligibility(extractor, train)
    print(f"\nCaracteristicas con senal: "
          f"{elegibilidad['n_features_informativas']}/{elegibilidad['n_features_total']}")

    print("\nEntrenando Isolation Forest...")
    t0 = time.perf_counter()
    detector = AnomalyDetector(contamination=args.contamination,
                               random_state=args.seed, n_estimators=args.n_estimators)
    detector.extractor = extractor
    detector.fit(Dataset(X=np.array([]), events=[r.event for r in benignos]))
    t_fit = time.perf_counter() - t0
    if not detector.is_fitted:
        print("  NOT EVALUABLE: el modelo no quedo entrenado.")
        return 3
    print(f"  entrenado en {t_fit:.1f}s")

    def puntuar(bloque):
        X = extractor.extract_batch([r.event for r in bloque])
        return detector.predict_proba(Dataset(X=X))

    scores_val = puntuar(val)
    y_val = np.array([r.label for r in val])
    umbral, barrido = pick_threshold(y_val, scores_val)

    t0 = time.perf_counter()
    scores_test = puntuar(test)
    t_score = time.perf_counter() - t0
    y_test = np.array([r.label for r in test])

    estadisticas = {
        "min": float(scores_test.min()), "max": float(scores_test.max()),
        "mean": float(scores_test.mean()), "median": float(np.median(scores_test)),
        "std": float(scores_test.std()),
        "distinct": int(len(np.unique(np.round(scores_test, 6)))),
    }
    print(f"\nanomaly_score en TEST:")
    for clave, valor in estadisticas.items():
        print(f"  {clave:9s} {valor:,.6f}" if isinstance(valor, float)
              else f"  {clave:9s} {valor:,}")

    if estadisticas["std"] < 1e-9:
        print("\n  DETENIDO: el score es constante. El modelo no esta puntuando.")
        return 2

    metricas = compute_metrics(y_test, scores_test, umbral)
    print(f"\nMETRICAS (EXPLORATORY) — TEST n={metricas['n']:,}, "
          f"ataques {metricas['positive_rate']:.1%}, umbral {umbral:.6f}")
    for clave in ("TP", "TN", "FP", "FN", "precision", "recall", "f1",
                  "fpr", "specificity", "accuracy", "roc_auc", "pr_auc"):
        print(f"  {clave:12s} {metricas[clave]}")

    y_pred = (scores_test >= umbral).astype(int)
    por_categoria: dict[str, dict] = {}
    for registro, prediccion in zip(test, y_pred):
        if registro.label != 1:
            continue
        d = por_categoria.setdefault(registro.attack_cat, {"total": 0, "detectados": 0})
        d["total"] += 1
        d["detectados"] += int(prediccion)
    for d in por_categoria.values():
        d["recall"] = round(d["detectados"] / d["total"], 4)
    if por_categoria:
        print("\nRecall por categoria:")
        for cat, d in sorted(por_categoria.items(), key=lambda kv: -kv[1]["total"]):
            print(f"  {cat:18s} {d['detectados']:>6,}/{d['total']:>6,} = {d['recall']}")

    # --- Persistencia ----------------------------------------------------
    publicas = {k: v for k, v in metricas.items() if not k.startswith("_")}
    (RESULTS / "unsw_nb15_1_metrics.json").write_text(json.dumps({
        "evaluation_type": "EXPLORATORY EVALUATION",
        "run_id": run_id, "file": TARGET.name, "stage": args.stage,
        "test_metrics": publicas, "recall_by_category": por_categoria,
        "anomaly_score_stats_test": estadisticas,
    }, indent=2, ensure_ascii=False), encoding="utf-8")

    with open(RESULTS / "unsw_nb15_1_predictions.csv", "w", newline="",
              encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["unsw_row_id", "timestamp", "anomaly_score", "prediction",
                    "label", "attack_cat"])
        for registro, score, pred in zip(test, scores_test, y_pred):
            w.writerow([registro.unsw_row_id, registro.event.timestamp.isoformat(),
                        round(float(score), 6), int(pred), registro.label,
                        registro.attack_cat])

    columnas = list(registros[0].event.raw.keys())
    metadatos = {
        "evaluation_type": "EXPLORATORY EVALUATION",
        "dataset": "UNSW-NB15",
        "source": "https://research.unsw.edu.au/projects/unsw-nb15-dataset",
        "file": TARGET.name,
        "sha256": file_sha256(TARGET),
        "file_size_bytes": TARGET.stat().st_size,
        "number_of_records": len(registros),
        "records_in_file": count_rows(TARGET),
        "columns": columnas,
        "n_columns": len(columnas),
        "seed": args.seed,
        "model_parameters": {
            "algorithm": "IsolationForest",
            "contamination": args.contamination,
            "n_estimators": args.n_estimators,
            "random_state": args.seed,
            "trained_on": "solo flujos benignos de TRAIN",
            "n_training_records": len(benignos),
        },
        "feature_mapping": FIELD_MAPPING,
        "feature_eligibility": elegibilidad,
        "split": {
            "method": "temporal 60/20/20", "train": len(train),
            "validation": len(val), "test": len(test),
            "threshold_selected_on": "VALIDATION",
        },
        "threshold": float(umbral),
        "threshold_sweep_validation": barrido,
        "run_id": run_id,
        "execution_timestamp": datetime.now(tz=timezone.utc).isoformat(timespec="seconds"),
        "timings_s": {
            "read": round(t_lectura, 2), "fit": round(t_fit, 2),
            "score": round(t_score, 2),
            "total": round(time.perf_counter() - inicio, 2),
        },
        "pipeline_stage_check": resumen_pipeline,
        "evaluable_window": ventana,
    }
    (RESULTS / "unsw_nb15_1_metadata.json").write_text(
        json.dumps(metadatos, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"\nResultados en {RESULTS}/unsw_nb15_1_*.json|csv")
    print(f"Tiempo total: {time.perf_counter() - inicio:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
