"""
Genera las figuras SVG de la evaluación a partir de los resultados en disco.

    python scripts/make_figures.py

Regla estricta: **ningún número se escribe a mano**. Todo sale de `results/`, que
a su vez lo produjo la ejecución real. Si un archivo de resultados falta, la
figura correspondiente no se genera y se dice por qué, en lugar de dibujar algo
que parezca un resultado.
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
FIGURES = ROOT / "docs" / "figures"

# Paleta sobria, legible en impresión a una tinta y en pantalla.
AZUL, NARANJA, GRIS, TEXTO = "#2f6fb2", "#e07b39", "#9aa5b1", "#1f2933"


def _setup():
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams.update({
        "font.family": "DejaVu Sans", "font.size": 10,
        "axes.edgecolor": GRIS, "axes.labelcolor": TEXTO, "text.color": TEXTO,
        "xtick.color": TEXTO, "ytick.color": TEXTO,
        "axes.spines.top": False, "axes.spines.right": False,
        "figure.facecolor": "white", "savefig.facecolor": "white",
    })
    return plt


def _load_json(name: str):
    path = RESULTS / name
    if not path.exists():
        print(f"  falta {name}: se omite la figura que depende de el")
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _load_curves() -> dict[str, tuple[list[float], list[float]]]:
    path = RESULTS / "unsw_nb15_curves.csv"
    if not path.exists():
        return {}
    curvas: dict[str, tuple[list[float], list[float]]] = {}
    with open(path, encoding="utf-8") as fh:
        for fila in csv.DictReader(fh):
            x, y = curvas.setdefault(fila["curve"], ([], []))
            x.append(float(fila["x"]))
            y.append(float(fila["y"]))
    return curvas


def figura_roc(plt, curvas, metricas) -> bool:
    if "roc" not in curvas or not metricas:
        return False
    auc = metricas["test_metrics"].get("roc_auc")
    fig, ax = plt.subplots(figsize=(5.2, 4.4))
    ax.plot(*curvas["roc"], color=AZUL, lw=2, label=f"CyberSentinel (AUC = {auc})")
    ax.plot([0, 1], [0, 1], ls="--", color=GRIS, lw=1, label="azar (AUC = 0.500)")
    ax.set_xlabel("Tasa de falsos positivos")
    ax.set_ylabel("Tasa de verdaderos positivos")
    ax.set_title("Curva ROC — Isolation Forest sobre UNSW-NB15", pad=12)
    ax.set_xlim(0, 1); ax.set_ylim(0, 1.02)
    ax.legend(loc="lower right", frameon=False)
    fig.tight_layout(); fig.savefig(FIGURES / "roc_curve.svg"); plt.close(fig)
    return True


def figura_pr(plt, curvas, metricas) -> bool:
    if "pr" not in curvas or not metricas:
        return False
    m = metricas["test_metrics"]
    auc, base = m.get("pr_auc"), m.get("positive_rate")
    fig, ax = plt.subplots(figsize=(5.2, 4.4))
    ax.plot(*curvas["pr"], color=NARANJA, lw=2, label=f"CyberSentinel (AUC-PR = {auc})")
    ax.axhline(base, ls="--", color=GRIS, lw=1,
               label=f"azar = proporcion de ataques ({base})")
    ax.set_xlabel("Exhaustividad (recall)")
    ax.set_ylabel("Precision")
    ax.set_title("Curva precision-exhaustividad — UNSW-NB15", pad=12)
    ax.set_xlim(0, 1); ax.set_ylim(0, 1.02)
    ax.legend(loc="lower left", frameon=False)
    fig.tight_layout(); fig.savefig(FIGURES / "pr_curve.svg"); plt.close(fig)
    return True


def figura_matriz(plt) -> bool:
    path = RESULTS / "unsw_nb15_confusion_matrix.csv"
    if not path.exists():
        return False
    with open(path, encoding="utf-8") as fh:
        filas = list(csv.reader(fh))
    valores = [[int(filas[1][1]), int(filas[1][2])],
               [int(filas[2][1]), int(filas[2][2])]]
    total = sum(sum(f) for f in valores)

    fig, ax = plt.subplots(figsize=(5.0, 4.2))
    ax.imshow(valores, cmap="Blues", vmin=0, vmax=max(max(f) for f in valores))
    ax.set_xticks([0, 1], ["Predicho: ataque", "Predicho: benigno"])
    ax.set_yticks([0, 1], ["Real: ataque", "Real: benigno"])
    etiquetas = [["TP", "FN"], ["FP", "TN"]]
    for i in range(2):
        for j in range(2):
            v = valores[i][j]
            ax.text(j, i, f"{etiquetas[i][j]}\n{v:,}\n{v / total:.1%}",
                    ha="center", va="center", fontsize=11,
                    color="white" if v > max(max(f) for f in valores) * 0.5 else TEXTO)
    ax.set_title(f"Matriz de confusion — TEST (n = {total:,})", pad=12)
    for lado in ("top", "right", "bottom", "left"):
        ax.spines[lado].set_visible(False)
    fig.tight_layout(); fig.savefig(FIGURES / "confusion_matrix.svg"); plt.close(fig)
    return True


def figura_ablation(plt) -> bool:
    path = RESULTS / "unsw_nb15_ablation.csv"
    if not path.exists():
        return False
    with open(path, encoding="utf-8") as fh:
        filas = list(csv.DictReader(fh))

    fig, ax = plt.subplots(figsize=(7.4, 4.2))
    nombres = [f["configuracion"] for f in filas]
    posiciones = range(len(filas))
    ancho = 0.26

    for desplazamiento, clave, color, etiqueta in (
        (-ancho, "precision", AZUL, "Precision"),
        (0.0, "recall", NARANJA, "Recall"),
        (ancho, "f1", "#4c9a5f", "F1"),
    ):
        alturas = [float(f[clave]) if f["evaluable"] == "True" else 0.0 for f in filas]
        ax.bar([p + desplazamiento for p in posiciones], alturas, ancho,
               color=color, label=etiqueta)

    # Las configuraciones no evaluables se marcan; no se dibuja un cero que
    # pareceria un mal resultado cuando en realidad no hay medida.
    for pos, fila in zip(posiciones, filas):
        if fila["evaluable"] != "True":
            ax.text(pos, 0.04, "NOT EVALUABLE\n(ver documentacion)", ha="center",
                    va="bottom", fontsize=8.5, color=TEXTO, style="italic")

    ax.set_xticks(list(posiciones), [n.replace(". ", ".\n") for n in nombres], fontsize=9)
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("Valor de la metrica")
    ax.set_title("Ablation sobre UNSW-NB15", pad=12)
    ax.legend(frameon=False, ncol=3, loc="upper right")
    fig.tight_layout(); fig.savefig(FIGURES / "ablation_metrics.svg"); plt.close(fig)
    return True


def figura_umbral(plt, metadatos) -> bool:
    if not metadatos or not metadatos.get("threshold_sweep_validation"):
        return False
    barrido = metadatos["threshold_sweep_validation"]
    elegido = metadatos["threshold"]

    fig, ax = plt.subplots(figsize=(6.6, 4.4))
    umbrales = [f["threshold"] for f in barrido]
    ax.plot(umbrales, [f["precision"] for f in barrido], color=AZUL, lw=2,
            marker="o", ms=3, label="Precision")
    ax.plot(umbrales, [f["recall"] for f in barrido], color=NARANJA, lw=2,
            marker="s", ms=3, label="Recall")
    ax.plot(umbrales, [f["f1"] for f in barrido], color="#4c9a5f", lw=2,
            marker="^", ms=3, label="F1")
    ax.plot(umbrales, [f["fpr"] for f in barrido], color=GRIS, lw=1.4, ls="--",
            label="Tasa de falsos positivos")
    ax.axvline(elegido, color=TEXTO, lw=1, ls=":",
               label=f"umbral elegido = {elegido:.4f}")

    ax.set_xlabel("Umbral de anomaly_score")
    ax.set_ylabel("Valor de la metrica")
    ax.set_title("Eleccion del umbral (medido en VALIDATION, no en TEST)", pad=12)
    ax.set_ylim(0, 1.05)
    ax.legend(frameon=False, fontsize=9)
    fig.tight_layout(); fig.savefig(FIGURES / "if_threshold_analysis.svg"); plt.close(fig)
    return True


def main() -> int:
    try:
        plt = _setup()
    except ImportError:
        print("matplotlib no esta instalado: pip install 'matplotlib>=3.7'")
        return 1

    FIGURES.mkdir(parents=True, exist_ok=True)
    metricas = _load_json("unsw_nb15_metrics.json")
    metadatos = _load_json("unsw_nb15_run_metadata.json")
    curvas = _load_curves()

    generadas = {
        "roc_curve.svg": figura_roc(plt, curvas, metricas),
        "pr_curve.svg": figura_pr(plt, curvas, metricas),
        "confusion_matrix.svg": figura_matriz(plt),
        "ablation_metrics.svg": figura_ablation(plt),
        "if_threshold_analysis.svg": figura_umbral(plt, metadatos),
    }

    print(f"Figuras en {FIGURES}/ (fuente: {RESULTS}/)")
    for nombre, ok in generadas.items():
        ruta = FIGURES / nombre
        estado = f"{ruta.stat().st_size / 1024:.0f} KB" if ok and ruta.exists() else "omitida"
        print(f"  {'OK ' if ok else '-- '} {nombre:28s} {estado}")
    if metadatos:
        print(f"\nrun_id de origen: {metadatos['run_id']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
