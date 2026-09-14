"""
Detección de anomalías mediante ML no supervisado (Isolation Forest).

Complementa al motor de reglas: las reglas capturan patrones conocidos; el
detector de anomalías captura lo desconocido / lo que se desvía del
comportamiento normal aprendido.

Se extraen características numéricas y categóricas (codificadas) de cada evento
y se entrena un Isolation Forest. Los eventos con score bajo se marcan como
anómalos. Es explicable a nivel de característica (qué features empujaron el
score), lo que alimenta la narrativa del módulo de explicación.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np

from ..schema import SecurityEvent, Severity


@dataclass
class AnomalyResult:
    """Resultado del detector de anomalías para un evento."""
    event: SecurityEvent
    is_anomaly: bool
    anomaly_score: float          # 0..1, mayor = más anómalo
    top_features: list[tuple[str, float]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_fingerprint": self.event.fingerprint(),
            "is_anomaly": self.is_anomaly,
            "anomaly_score": round(self.anomaly_score, 3),
            "top_features": [(k, round(v, 3)) for k, v in self.top_features],
        }


class FeatureExtractor:
    """Convierte SecurityEvent en un vector numérico estable."""

    FEATURE_NAMES = [
        "hour", "is_night", "is_failure",
        "cmd_len", "cmd_special_chars", "cmd_entropy",
        "dst_port", "bytes_out_log", "is_rare_port",
        "user_hash", "src_ip_hash",
    ]

    COMMON_PORTS = {80, 443, 22, 53, 25, 3389, 445, 139, 21, 23, 3306, 8080}

    def extract(self, event: SecurityEvent) -> np.ndarray:
        cmd = (event.command_line or "")
        hour = event.timestamp.hour
        vec = [
            hour,
            1.0 if (hour < 6 or hour > 22) else 0.0,
            1.0 if str(event.outcome).lower() in ("failure", "failed", "denied", "401", "403") else 0.0,
            float(len(cmd)),
            float(sum(1 for ch in cmd if not ch.isalnum() and not ch.isspace())),
            _shannon_entropy(cmd),
            float(event.dst_port or 0),
            float(np.log1p(event.bytes_out or 0)),
            1.0 if (event.dst_port and event.dst_port not in self.COMMON_PORTS) else 0.0,
            float(_stable_hash(event.user or "")),
            float(_stable_hash(event.src_ip or "")),
        ]
        return np.array(vec, dtype=float)

    def matrix(self, events: list[SecurityEvent]) -> np.ndarray:
        if not events:
            return np.empty((0, len(self.FEATURE_NAMES)))
        return np.vstack([self.extract(e) for e in events])


class AnomalyDetector:
    """Detector de anomalías basado en Isolation Forest."""

    def __init__(self, contamination: float = 0.08, random_state: int = 42) -> None:
        self.contamination = contamination
        self.random_state = random_state
        self.extractor = FeatureExtractor()
        self._model = None
        self._means: np.ndarray | None = None
        self._stds: np.ndarray | None = None

    def fit(self, events: list[SecurityEvent]) -> "AnomalyDetector":
        """Entrena el modelo sobre una línea base de comportamiento."""
        from sklearn.ensemble import IsolationForest

        X = self.extractor.matrix(events)
        if X.shape[0] < 5:
            # Muy pocos datos para ML fiable; el modelo queda inactivo.
            self._model = None
            return self
        self._means = X.mean(axis=0)
        self._stds = X.std(axis=0) + 1e-9
        Xn = (X - self._means) / self._stds
        self._model = IsolationForest(
            contamination=self.contamination,
            random_state=self.random_state,
            n_estimators=200,
        ).fit(Xn)
        return self

    def score(self, events: list[SecurityEvent]) -> list[AnomalyResult]:
        """Puntúa una lista de eventos. Si el modelo no está entrenado, devuelve no-anomalías."""
        results: list[AnomalyResult] = []
        if self._model is None or self._means is None:
            return [AnomalyResult(e, False, 0.0, []) for e in events]

        X = self.extractor.matrix(events)
        Xn = (X - self._means) / self._stds
        raw_scores = -self._model.score_samples(Xn)   # mayor = más anómalo
        preds = self._model.predict(Xn)               # -1 anómalo, 1 normal

        lo, hi = raw_scores.min(), raw_scores.max()
        span = (hi - lo) or 1.0

        for event, raw, pred, xn in zip(events, raw_scores, preds, Xn):
            norm_score = float((raw - lo) / span)
            top = self._explain(xn)
            results.append(AnomalyResult(
                event=event,
                is_anomaly=bool(pred == -1),
                anomaly_score=norm_score,
                top_features=top,
            ))
        return results

    def _explain(self, xn: np.ndarray, k: int = 3) -> list[tuple[str, float]]:
        """Devuelve las k características que más se desvían de lo normal."""
        deviations = np.abs(xn)
        idx = np.argsort(deviations)[::-1][:k]
        return [(self.extractor.FEATURE_NAMES[i], float(deviations[i])) for i in idx]


def severity_from_anomaly(score: float) -> Severity:
    """Traduce un score de anomalía a severidad."""
    if score >= 0.9:
        return Severity.CRITICAL
    if score >= 0.75:
        return Severity.HIGH
    if score >= 0.55:
        return Severity.MEDIUM
    if score >= 0.35:
        return Severity.LOW
    return Severity.INFO


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return float(-sum((c / n) * np.log2(c / n) for c in counts.values()))


def _stable_hash(text: str, mod: int = 997) -> int:
    h = 0
    for ch in text:
        h = (h * 31 + ord(ch)) % mod
    return h
