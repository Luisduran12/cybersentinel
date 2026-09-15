"""
Detección de anomalías mediante ML no supervisado (Isolation Forest).

Complementa al motor de reglas: las reglas capturan patrones conocidos; el
detector de anomalías captura lo que se desvía del comportamiento aprendido.

Dos decisiones de diseño que condicionan la validez de los resultados:

1. **La puntuación es absoluta, no relativa al lote.** Una normalización min-max
   dentro del lote garantiza que el evento más raro de cualquier lote reciba 1.0,
   aunque el lote sea inofensivo, y hace que los scores de dos ejecuciones no
   sean comparables. Aquí se usa directamente la puntuación de Isolation Forest
   (`-score_samples`), acotada en (0, 1) y con 0.5 como frontera de decisión del
   propio modelo. Un score de 0.62 significa lo mismo hoy que mañana.

2. **`contamination="auto"` por defecto.** Fijar `contamination=0.08` obliga al
   modelo a marcar un 8% de los eventos como anómalos *por construcción*, haya o
   no ataques. "auto" usa el umbral estándar del algoritmo y permite que un lote
   limpio no produzca ninguna anomalía.

Las características son interpretables (rareza de la entidad, entropía del
comando, hora cíclica), de modo que `top_features` explique algo al analista.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

import numpy as np

from ..schema import SecurityEvent, Severity
from ..ml.base import MLModel, Dataset
from ..ml.features import FeatureExtractor, FEATURE_LABELS_ES



@dataclass
class AnomalyResult:
    """Resultado del detector de anomalías para un evento."""
    event: SecurityEvent
    is_anomaly: bool
    anomaly_score: float          # 0..1 absoluto; 0.5 = frontera de decision
    top_features: list[tuple[str, float]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_fingerprint": self.event.fingerprint(),
            "is_anomaly": self.is_anomaly,
            "anomaly_score": round(self.anomaly_score, 3),
            "top_features": [(k, round(v, 3)) for k, v in self.top_features],
        }

    @property
    def top_features_es(self) -> list[str]:
        """Características desviadas, en lenguaje natural."""
        seen: set[str] = set()
        out: list[str] = []
        for name, _ in self.top_features:
            label = FEATURE_LABELS_ES.get(name, name)
            if label not in seen:
                seen.add(label)
                out.append(label)
        return out


class AnomalyDetector(MLModel):
    """Detector de anomalías basado en Isolation Forest (Fase 4)."""

    MIN_TRAINING_EVENTS = 5
    BASELINE_PERCENTILE = 99.0

    def __init__(
        self,
        contamination: float | str = "auto",
        random_state: int = 42,
        n_estimators: int = 200,
    ) -> None:
        self.contamination = contamination
        self.random_state = random_state
        self.n_estimators = n_estimators
        self.extractor = FeatureExtractor()
        self._model = None
        self._means: np.ndarray | None = None
        self._stds: np.ndarray | None = None
        self._baseline_scores: np.ndarray | None = None

    @property
    def is_fitted(self) -> bool:
        return self._model is not None

    @property
    def suggested_threshold(self) -> float:
        if self._baseline_scores is None or self._baseline_scores.size == 0:
            return 0.5
        return float(
            max(np.percentile(self._baseline_scores, self.BASELINE_PERCENTILE), 0.5)
        )

    def fit(self, dataset_or_events: Dataset | list[SecurityEvent]) -> "AnomalyDetector":
        """
        Entrena el modelo (y el FeatureExtractor) estrictamente usando el dataset provisto,
        que DEBE ser únicamente el set de entrenamiento.
        """
        from sklearn.ensemble import IsolationForest

        if isinstance(dataset_or_events, list):
            dataset = Dataset(X=np.array([]), events=dataset_or_events)
        else:
            dataset = dataset_or_events

        # Si el dataset trae eventos, entrena los léxicos (usuarios, IPs, puertos)
        if dataset.events and not self.extractor._is_fitted:
            self.extractor.fit(dataset.events)
        
        # Si el Dataset X no viene pre-calculado pero hay eventos, extraemos
        if dataset.X.size == 0 and dataset.events:
            dataset.X = self.extractor.extract_batch(dataset.events)

        X = dataset.X
        if X.shape[0] < self.MIN_TRAINING_EVENTS:
            self._model = None
            return self

        self._means = X.mean(axis=0)
        stds = X.std(axis=0)
        stds[stds < 1e-5] = 1.0
        self._stds = stds
        
        Xn = (X - self._means) / self._stds
        
        self._model = IsolationForest(
            contamination=self.contamination,
            random_state=self.random_state,
            n_estimators=self.n_estimators,
        ).fit(Xn)
        
        self._baseline_scores = np.clip(-self._model.score_samples(Xn), 0.0, 1.0)
        return self



    def predict(self, dataset: Dataset) -> np.ndarray:
        if not self.is_fitted or self._means is None:
            return np.ones(dataset.X.shape[0])
        Xn = (dataset.X - self._means) / self._stds
        return self._model.predict(Xn)

    def predict_proba(self, dataset: Dataset) -> np.ndarray:
        if not self.is_fitted or self._means is None:
            return np.zeros(dataset.X.shape[0])
        Xn = (dataset.X - self._means) / self._stds
        return np.clip(-self._model.score_samples(Xn), 0.0, 1.0)

    def evaluate(self, dataset: Dataset) -> dict[str, float]:
        from sklearn.metrics import roc_auc_score
        preds = self.predict(dataset)
        proba = self.predict_proba(dataset)
        metrics = {}
        if dataset.y is not None:
            # -1 is anomaly (label 1), 1 is normal (label 0)
            binary_preds = (preds == -1).astype(int)
            metrics["accuracy"] = (binary_preds == dataset.y).mean()
            if len(set(dataset.y)) > 1:
                metrics["roc_auc"] = roc_auc_score(dataset.y, proba)
        return metrics

    def score(self, events: list[SecurityEvent]) -> list[AnomalyResult]:
        """
        Puntúa eventos en una escala absoluta y comparable entre ejecuciones.

        `anomaly_score` es `-score_samples` de Isolation Forest: mide cuán corto
        es el camino medio de aislamiento del evento en el bosque. Vive en (0, 1)
        y 0.5 es la frontera de decisión estándar del algoritmo. No depende del
        resto del lote, así que un lote sin ataques no produce un 1.0 artificial.
        """
        if not self.is_fitted or self._means is None:
            return [AnomalyResult(e, False, 0.0, []) for e in events]
        if not events:
            return []

        # Soporte para backwards compatibility con `score(events)` pero
        # usando `predict_proba` por debajo, lo que previene reentrenamiento indeseado.
        
        # Generar dataset dummy para usar predict_proba
        X = self.extractor.extract_batch(events)
        dataset = Dataset(X=X, events=events)
        
        scores = self.predict_proba(dataset)
        preds = self.predict(dataset)
        
        Xn = (X - self._means) / self._stds

        return [
            AnomalyResult(
                event=event,
                is_anomaly=bool(pred == -1),
                anomaly_score=float(score),
                top_features=self._explain(xn),
            )
            for event, score, pred, xn in zip(events, scores, preds, Xn)
        ]

    def _explain(self, xn: np.ndarray, k: int = 3) -> list[tuple[str, float]]:
        """Devuelve las k características que más se desvían de la línea base."""
        deviations = np.abs(xn)
        idx = np.argsort(deviations)[::-1][:k]
        return [(self.extractor.FEATURE_NAMES[i], float(deviations[i])) for i in idx]


# Umbrales sobre la escala absoluta de Isolation Forest, donde 0.5 es la frontera
# de decision. El techo es MEDIUM a proposito: ver severity_from_anomaly.
SEVERITY_THRESHOLDS: list[tuple[float, Severity]] = [
    (0.60, Severity.MEDIUM),
    (0.50, Severity.LOW),
]

#: Severidad maxima que puede alcanzar una anomalia por si sola.
MAX_ANOMALY_SEVERITY = Severity.MEDIUM


def severity_from_anomaly(score: float) -> Severity:
    """
    Traduce un score absoluto de anomalía a severidad, con techo en MEDIUM.

    Una anomalía no corroborada por ninguna regla es una **pista**, no un
    veredicto: el modelo detecta que algo se sale de la norma aprendida, no que
    sea malicioso. Dejar que un evento raro llegue solo a CRITICAL es lo que
    producía incidentes críticos sobre tráfico limpio.

    La severidad sí puede subir por la vía correcta: si la correlación agrupa la
    anomalía con hallazgos de reglas en el mismo incidente, el riesgo agregado
    del incidente sube por la severidad de esas reglas y por la progresión en la
    cadena de ataque.
    """
    for threshold, severity in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return severity
    return Severity.INFO


def _ratio(out_bytes: int | None, in_bytes: int | None) -> float:
    """Proporción de bytes salientes sobre el total del flujo."""
    total = (out_bytes or 0) + (in_bytes or 0)
    return (out_bytes or 0) / total if total else 0.5


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: Counter[str] = Counter(text)
    n = len(text)
    return float(-sum((c / n) * np.log2(c / n) for c in counts.values()))
