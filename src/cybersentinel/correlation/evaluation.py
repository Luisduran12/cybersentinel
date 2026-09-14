"""
Evaluación cuantitativa de los modelos de predicción de kill-chain.

Responde a la pregunta que un tribunal hará: *¿qué tan bueno es?* Y a la que la
hace pertinente: *¿mejor que qué?*

Protocolo
---------
De cada secuencia retenida se derivan varios ejemplos por *prefijo*: dada una
campaña ``[A, B, C, D]``, se pregunta al modelo por la fase siguiente tras ``[A]``,
tras ``[A, B]`` y tras ``[A, B, C]``, y se compara con ``B``, ``C`` y ``D``. Así
se mide la predicción en cada punto de la cadena, no solo al final — que es
justo el momento en que la predicción tiene valor operativo.

Métricas
--------
- **precisión@k**: proporción de prefijos en los que la táctica real aparece
  entre las k propuestas. Es la métrica que importa para un analista: un panel
  que muestra tres hipótesis acierta si la buena está entre ellas.
- **Matriz de confusión** y **F1 por clase** sobre la predicción top-1, para ver
  *qué* confunde el modelo y no solo cuánto.
- **Cobertura**: proporción de prefijos en los que el modelo se atreve a
  responder. Un modelo que responde poco puede tener buena precisión y ser
  inútil, así que se reporta junto a ella.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Sequence

from .sequence_model import SequenceModel


@dataclass
class PredictionExample:
    """Un prefijo de campaña y la táctica que realmente vino después."""
    history: list[str]
    expected: str
    profile: str = ""


@dataclass
class EvaluationResult:
    """Resultado de evaluar un modelo sobre un conjunto de prefijos."""
    model_name: str
    n_examples: int
    n_answered: int
    precision_at: dict[int, float]
    labels: list[str] = field(default_factory=list)
    confusion: list[list[int]] = field(default_factory=list)
    per_class_f1: dict[str, float] = field(default_factory=dict)
    macro_f1: float = 0.0
    weighted_f1: float = 0.0

    @property
    def coverage(self) -> float:
        """Proporción de prefijos en los que el modelo emitió alguna predicción."""
        return self.n_answered / self.n_examples if self.n_examples else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model_name,
            "n_examples": self.n_examples,
            "coverage": round(self.coverage, 4),
            "precision_at": {f"p@{k}": round(v, 4) for k, v in self.precision_at.items()},
            "macro_f1": round(self.macro_f1, 4),
            "weighted_f1": round(self.weighted_f1, 4),
            "per_class_f1": {k: round(v, 4) for k, v in self.per_class_f1.items()},
            "labels": self.labels,
            "confusion_matrix": self.confusion,
        }


def build_examples(
    sequences: Sequence[Sequence[str]], labels: Sequence[str] | None = None
) -> list[PredictionExample]:
    """Descompone cada secuencia en todos sus prefijos con su continuación real."""
    profiles = list(labels) if labels else [""] * len(sequences)
    examples: list[PredictionExample] = []
    for sequence, profile in zip(sequences, profiles):
        for cut in range(1, len(sequence)):
            examples.append(PredictionExample(
                history=list(sequence[:cut]),
                expected=sequence[cut],
                profile=profile,
            ))
    return examples


def evaluate(
    model: SequenceModel,
    examples: Sequence[PredictionExample],
    ks: Sequence[int] = (1, 3),
) -> EvaluationResult:
    """Evalúa un modelo sobre un conjunto de prefijos."""
    from sklearn.metrics import confusion_matrix, f1_score

    max_k = max(ks)
    hits = {k: 0 for k in ks}
    answered = 0
    y_true: list[str] = []
    y_pred: list[str] = []

    for example in examples:
        predictions = [t for t, _ in model.predict_next(example.history, k=max_k)]
        if not predictions:
            continue
        answered += 1
        y_true.append(example.expected)
        y_pred.append(predictions[0])
        for k in ks:
            if example.expected in predictions[:k]:
                hits[k] += 1

    n = len(examples)
    result = EvaluationResult(
        model_name=model.name,
        n_examples=n,
        n_answered=answered,
        # Se divide entre TODOS los prefijos, no solo los respondidos: no
        # responder es fallar. La cobertura se reporta aparte para poder
        # distinguir un modelo prudente de uno impreciso.
        precision_at={k: (hits[k] / n if n else 0.0) for k in ks},
    )

    if y_true:
        present = sorted(set(y_true) | set(y_pred))
        result.labels = present
        result.confusion = confusion_matrix(y_true, y_pred, labels=present).tolist()
        per_class = f1_score(y_true, y_pred, labels=present, average=None, zero_division=0)
        result.per_class_f1 = dict(zip(present, (float(v) for v in per_class)))
        result.macro_f1 = float(
            f1_score(y_true, y_pred, labels=present, average="macro", zero_division=0)
        )
        result.weighted_f1 = float(
            f1_score(y_true, y_pred, labels=present, average="weighted", zero_division=0)
        )
    return result


def compare(
    models: dict[str, SequenceModel],
    examples: Sequence[PredictionExample],
    ks: Sequence[int] = (1, 3),
) -> dict[str, EvaluationResult]:
    """Evalúa varios modelos sobre exactamente los mismos prefijos."""
    return {name: evaluate(model, examples, ks) for name, model in models.items()}


def format_confusion(result: EvaluationResult, max_labels: int = 14) -> str:
    """Matriz de confusión en texto, con las tácticas abreviadas a 4 letras."""
    if not result.labels:
        return "(sin predicciones)"
    labels = result.labels[:max_labels]
    header = "        " + " ".join(f"{l[:4]:>4s}" for l in labels)
    lines = [header]
    for name, row in zip(labels, result.confusion):
        cells = " ".join(f"{v:>4d}" for v in row[: len(labels)])
        lines.append(f"{name[:7]:<7s} {cells}")
    lines.append("(filas = táctica real, columnas = predicción top-1)")
    return "\n".join(lines)
