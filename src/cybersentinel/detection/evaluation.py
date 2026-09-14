"""
Evaluación cuantitativa del detector de anomalías sobre datasets etiquetados.

Responde con números a "¿qué tan bueno es detectando?": precisión, exhaustividad
(recall), F1, matriz de confusión, curva ROC y curva precisión-exhaustividad.

PROTOCOLO
---------
El detector es **no supervisado**: aprende qué es normal y marca lo que se
desvía. Eso impone dos condiciones que el pipeline de demostración no cumplía y
que aquí sí se cumplen:

1. **Se entrena solo con tráfico benigno.** Entrenar con los ataques dentro hace
   que el modelo los aprenda como parte de la normalidad y hunde la
   exhaustividad. La línea base tiene que ser lo que se considera normal.
2. **Se mide sobre datos que el modelo no vio.** El conjunto de evaluación
   contiene el resto del tráfico benigno más **todos** los ataques.

MÉTRICAS Y POR QUÉ ESTAS
------------------------
En detección de intrusiones las clases están muy desbalanceadas, así que la
exactitud (*accuracy*) engaña: un detector que no marque nada acierta el 99% si
solo el 1% son ataques. Por eso se reportan:

- **Precisión y exhaustividad por separado**, nunca solo su media.
- **AUC-PR** además de **AUC-ROC**: con clases desbalanceadas la ROC da una
  impresión optimista, porque la tasa de falsos positivos se diluye en el enorme
  número de negativos. La PR es la que refleja el trabajo real del analista.
- **Exhaustividad por categoría de ataque**: un F1 global alto puede esconder que
  una familia entera de ataques no se detecta nunca.
"""
from __future__ import annotations

import logging
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

import numpy as np

from ..ingestion.datasets import LabeledEvent
from .anomaly import AnomalyDetector

logger = logging.getLogger(__name__)


@dataclass
class ConfusionMatrix:
    """Matriz de confusión binaria, con los nombres que usa un analista."""
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int

    @property
    def precision(self) -> float:
        """De lo que marqué como ataque, ¿cuánto lo era?"""
        denominator = self.true_positives + self.false_positives
        return self.true_positives / denominator if denominator else 0.0

    @property
    def recall(self) -> float:
        """De todos los ataques que había, ¿cuántos vi?"""
        denominator = self.true_positives + self.false_negatives
        return self.true_positives / denominator if denominator else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def false_positive_rate(self) -> float:
        """La cifra que decide si un SOC puede convivir con el detector."""
        denominator = self.false_positives + self.true_negatives
        return self.false_positives / denominator if denominator else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "false_negatives": self.false_negatives,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
        }


@dataclass
class CategoryRecall:
    """Cuántos ataques de una familia concreta se detectaron."""
    category: str
    total: int
    detected: int

    @property
    def recall(self) -> float:
        return self.detected / self.total if self.total else 0.0


@dataclass
class DetectionEvaluation:
    """Resultado completo de evaluar el detector sobre un dataset etiquetado."""
    dataset: str
    n_train_benign: int
    n_test: int
    n_test_attacks: int
    threshold: float
    confusion: ConfusionMatrix
    roc_auc: float = 0.0
    pr_auc: float = 0.0
    roc_points: list[tuple[float, float]] = field(default_factory=list)
    pr_points: list[tuple[float, float]] = field(default_factory=list)
    per_category: list[CategoryRecall] = field(default_factory=list)
    threshold_sweep: list[dict[str, float]] = field(default_factory=list)

    @property
    def attack_ratio(self) -> float:
        return self.n_test_attacks / self.n_test if self.n_test else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "dataset": self.dataset,
            "protocol": {
                "training": "solo eventos benignos",
                "n_train_benign": self.n_train_benign,
                "n_test": self.n_test,
                "n_test_attacks": self.n_test_attacks,
                "attack_ratio": round(self.attack_ratio, 4),
                "threshold": round(self.threshold, 4),
            },
            "metrics": {
                **self.confusion.to_dict(),
                "roc_auc": round(self.roc_auc, 4),
                "pr_auc": round(self.pr_auc, 4),
            },
            "per_category_recall": [
                {"category": c.category, "total": c.total,
                 "detected": c.detected, "recall": round(c.recall, 4)}
                for c in sorted(self.per_category, key=lambda c: -c.total)
            ],
            "threshold_sweep": self.threshold_sweep,
            "roc_points": [[round(x, 4), round(y, 4)] for x, y in self.roc_points],
            "pr_points": [[round(x, 4), round(y, 4)] for x, y in self.pr_points],
        }


def _subsample(points: list[tuple[float, float]], maximum: int = 200) -> list[tuple[float, float]]:
    """Reduce una curva a un número manejable de puntos para el reporte."""
    if len(points) <= maximum:
        return points
    step = len(points) / maximum
    return [points[int(i * step)] for i in range(maximum)]


def split_benign_for_training(
    labeled: Sequence[LabeledEvent],
    train_ratio: float = 0.5,
    seed: int = 42,
) -> tuple[list[LabeledEvent], list[LabeledEvent]]:
    """
    Separa una línea base benigna para entrenar del resto para evaluar.

    Los ataques van **enteros** al conjunto de evaluación: no tendría sentido
    "entrenar" con ellos en un detector no supervisado.
    """
    benign = [item for item in labeled if item.label == 0]
    attacks = [item for item in labeled if item.label == 1]

    rng = random.Random(seed)
    shuffled = list(benign)
    rng.shuffle(shuffled)
    cut = int(len(shuffled) * train_ratio)

    train = shuffled[:cut]
    test = shuffled[cut:] + attacks
    test.sort(key=lambda item: item.event.timestamp)
    return train, test


def evaluate_anomaly_detector(
    labeled: Sequence[LabeledEvent],
    dataset: str = "dataset",
    train_ratio: float = 0.5,
    threshold: float | None = None,
    detector: AnomalyDetector | None = None,
    seed: int = 42,
) -> DetectionEvaluation:
    """
    Entrena el detector con la parte benigna y lo mide sobre el resto.

    `threshold` por defecto es el que sugiere la propia línea base (percentil 99),
    que es el que usa el pipeline en producción: medir con otro daría números que
    el sistema real no alcanza.
    """
    from sklearn.metrics import auc, average_precision_score, precision_recall_curve, roc_curve

    train, test = split_benign_for_training(labeled, train_ratio=train_ratio, seed=seed)
    if not train or not test:
        raise ValueError(
            "No hay suficientes eventos para evaluar: se necesitan benignos para "
            "entrenar y al menos un evento de evaluacion."
        )

    detector = detector or AnomalyDetector()
    detector.fit([item.event for item in train])
    applied = threshold if threshold is not None else detector.suggested_threshold

    results = detector.score([item.event for item in test])
    scores = np.array([r.anomaly_score for r in results])
    truth = np.array([item.label for item in test])
    predicted = (scores >= applied).astype(int)

    confusion = ConfusionMatrix(
        true_positives=int(np.sum((predicted == 1) & (truth == 1))),
        false_positives=int(np.sum((predicted == 1) & (truth == 0))),
        true_negatives=int(np.sum((predicted == 0) & (truth == 0))),
        false_negatives=int(np.sum((predicted == 0) & (truth == 1))),
    )

    evaluation = DetectionEvaluation(
        dataset=dataset,
        n_train_benign=len(train),
        n_test=len(test),
        n_test_attacks=int(truth.sum()),
        threshold=float(applied),
        confusion=confusion,
    )

    # Las curvas necesitan las dos clases presentes.
    if truth.min() != truth.max():
        fpr, tpr, _ = roc_curve(truth, scores)
        evaluation.roc_auc = float(auc(fpr, tpr))
        evaluation.roc_points = _subsample(list(zip(map(float, fpr), map(float, tpr))))

        precisions, recalls, _ = precision_recall_curve(truth, scores)
        evaluation.pr_auc = float(average_precision_score(truth, scores))
        evaluation.pr_points = _subsample(list(zip(map(float, recalls), map(float, precisions))))
    else:
        logger.warning("El conjunto de evaluacion tiene una sola clase; sin curvas.")

    evaluation.per_category = _category_recall(test, predicted)
    evaluation.threshold_sweep = _sweep(truth, scores)
    return evaluation


def _category_recall(test: Sequence[LabeledEvent], predicted: np.ndarray) -> list[CategoryRecall]:
    """Exhaustividad desglosada por familia de ataque."""
    totals: dict[str, int] = {}
    detected: dict[str, int] = {}
    for item, prediction in zip(test, predicted):
        if item.label != 1:
            continue
        totals[item.category] = totals.get(item.category, 0) + 1
        detected[item.category] = detected.get(item.category, 0) + int(prediction)
    return [
        CategoryRecall(category=name, total=total, detected=detected.get(name, 0))
        for name, total in totals.items()
    ]


def _sweep(truth: np.ndarray, scores: np.ndarray) -> list[dict[str, float]]:
    """
    Precisión y exhaustividad a distintos umbrales.

    Es la tabla que permite elegir un punto de operación: casi siempre hay que
    decidir cuántos falsos positivos tolera el equipo a cambio de cuánta
    cobertura, y esa decisión no la debe tomar un valor por defecto.
    """
    sweep: list[dict[str, float]] = []
    for percentile in (50, 75, 90, 95, 97.5, 99, 99.5):
        threshold = float(np.percentile(scores, percentile))
        predicted = (scores >= threshold).astype(int)
        confusion = ConfusionMatrix(
            true_positives=int(np.sum((predicted == 1) & (truth == 1))),
            false_positives=int(np.sum((predicted == 1) & (truth == 0))),
            true_negatives=int(np.sum((predicted == 0) & (truth == 0))),
            false_negatives=int(np.sum((predicted == 0) & (truth == 1))),
        )
        sweep.append({
            "percentile": percentile,
            "threshold": round(threshold, 4),
            "precision": round(confusion.precision, 4),
            "recall": round(confusion.recall, 4),
            "f1": round(confusion.f1, 4),
            "false_positive_rate": round(confusion.false_positive_rate, 4),
        })
    return sweep


def save_curves(evaluation: DetectionEvaluation, path: str | Path) -> Path | None:
    """
    Dibuja la ROC y la curva precisión-exhaustividad en un PNG.

    matplotlib es una dependencia opcional (`pip install cybersentinel[viz]`):
    sin ella la evaluación funciona igual y los puntos de ambas curvas quedan en
    el JSON del reporte, que es lo que hace falta para reproducir la figura.
    """
    try:
        import matplotlib
        matplotlib.use("Agg")           # sin entorno grafico: se escribe a archivo
        import matplotlib.pyplot as plt
    except ImportError:
        logger.info("matplotlib no esta instalado; se omite la figura de las curvas.")
        return None

    figure, (roc_ax, pr_ax) = plt.subplots(1, 2, figsize=(11, 4.5))

    if evaluation.roc_points:
        x, y = zip(*evaluation.roc_points)
        roc_ax.plot(x, y, linewidth=2, label=f"AUC = {evaluation.roc_auc:.3f}")
    roc_ax.plot([0, 1], [0, 1], "--", color="gray", linewidth=1, label="azar")
    roc_ax.set_xlabel("Tasa de falsos positivos")
    roc_ax.set_ylabel("Tasa de verdaderos positivos")
    roc_ax.set_title(f"Curva ROC — {evaluation.dataset}")
    roc_ax.legend(loc="lower right")

    if evaluation.pr_points:
        x, y = zip(*evaluation.pr_points)
        pr_ax.plot(x, y, linewidth=2, color="darkorange",
                   label=f"AUC-PR = {evaluation.pr_auc:.3f}")
    pr_ax.axhline(evaluation.attack_ratio, linestyle="--", color="gray", linewidth=1,
                  label=f"azar = {evaluation.attack_ratio:.3f}")
    pr_ax.set_xlabel("Exhaustividad (recall)")
    pr_ax.set_ylabel("Precisión")
    pr_ax.set_title("Curva precisión-exhaustividad")
    pr_ax.legend(loc="upper right")

    figure.tight_layout()
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(path, dpi=150)
    plt.close(figure)
    return path
