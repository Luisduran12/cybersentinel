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

# Etiquetas legibles para la narrativa explicable.
FEATURE_LABELS_ES: dict[str, str] = {
    "hour_sin": "hora del dia",
    "hour_cos": "hora del dia",
    "is_night": "actividad nocturna",
    "is_failure": "resultado fallido",
    "cmd_len": "longitud del comando",
    "cmd_special_chars": "caracteres especiales en el comando",
    "cmd_entropy": "entropia del comando (ofuscacion)",
    "bytes_out_log": "volumen de datos saliente",
    "bytes_in_log": "volumen de datos entrante",
    "bytes_ratio": "asimetria entre datos enviados y recibidos",
    "is_rare_port": "puerto de destino poco comun",
    "port_rarity": "rareza del puerto en la linea base",
    "user_rarity": "rareza del usuario en la linea base",
    "src_ip_rarity": "rareza de la IP de origen en la linea base",
}


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


class FeatureExtractor:
    """
    Convierte SecurityEvent en un vector numérico estable e interpretable.

    Debe ajustarse (`fit`) sobre la línea base antes de extraer: las
    características de rareza se calculan contra las frecuencias observadas en
    esa línea base. Un valor nunca visto tiene rareza máxima (1.0).
    """

    FEATURE_NAMES = [
        "hour_sin", "hour_cos", "is_night", "is_failure",
        "cmd_len", "cmd_special_chars", "cmd_entropy",
        "bytes_out_log", "bytes_in_log", "bytes_ratio",
        "is_rare_port", "port_rarity",
        "user_rarity", "src_ip_rarity",
    ]

    COMMON_PORTS = {80, 443, 22, 53, 25, 3389, 445, 139, 21, 23, 3306, 8080}
    FAILURE_TOKENS = {"failure", "failed", "denied", "deny", "block", "401", "403"}

    def __init__(self) -> None:
        self._users: Counter[str] = Counter()
        self._ips: Counter[str] = Counter()
        self._ports: Counter[str] = Counter()
        self._total = 0

    def fit(self, events: list[SecurityEvent]) -> "FeatureExtractor":
        """Aprende las frecuencias de entidades en la línea base."""
        self._users = Counter(e.user or "" for e in events)
        self._ips = Counter(e.src_ip or "" for e in events)
        self._ports = Counter(str(e.dst_port or "") for e in events)
        self._total = len(events)
        return self

    def _rarity(self, counter: Counter[str], value: str) -> float:
        """
        Rareza en [0, 1]: 0 = valor omnipresente, 1 = nunca visto en la base.

        Es una frecuencia relativa invertida, no un hash: a diferencia de
        codificar el usuario como un entero, esto sí tiene sentido ordinal
        (más alto = más inusual) y por tanto es explicable.
        """
        if self._total == 0:
            return 0.0
        return 1.0 - (counter.get(value, 0) / self._total)

    def extract(self, event: SecurityEvent) -> np.ndarray:
        cmd = event.command_line or ""
        hour = event.timestamp.hour
        angle = 2.0 * np.pi * hour / 24.0
        port = event.dst_port
        vec = [
            # La hora es cíclica: 23:00 y 00:00 son adyacentes, no opuestas.
            float(np.sin(angle)),
            float(np.cos(angle)),
            1.0 if (hour < 6 or hour > 22) else 0.0,
            1.0 if str(event.outcome).lower() in self.FAILURE_TOKENS else 0.0,
            float(len(cmd)),
            float(sum(1 for ch in cmd if not ch.isalnum() and not ch.isspace())),
            _shannon_entropy(cmd),
            float(np.log1p(event.bytes_out or 0)),
            float(np.log1p(event.bytes_in or 0)),
            # Asimetria del flujo: una exfiltracion envia mucho y recibe poco;
            # una descarga hace lo contrario. 0.5 = simetrico o sin datos.
            _ratio(event.bytes_out, event.bytes_in),
            1.0 if (port and port not in self.COMMON_PORTS) else 0.0,
            self._rarity(self._ports, str(port or "")),
            self._rarity(self._users, event.user or ""),
            self._rarity(self._ips, event.src_ip or ""),
        ]
        return np.array(vec, dtype=float)

    def matrix(self, events: list[SecurityEvent]) -> np.ndarray:
        if not events:
            return np.empty((0, len(self.FEATURE_NAMES)))
        return np.vstack([self.extract(e) for e in events])


class AnomalyDetector:
    """Detector de anomalías basado en Isolation Forest."""

    MIN_TRAINING_EVENTS = 5

    #: Percentil de la línea base que marca el umbral sugerido de alerta.
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
        """
        Umbral de alerta derivado de la línea base, no de una constante mágica.

        Es el percentil 99 de las puntuaciones observadas al entrenar: por
        definición, un lote que se parece a su línea base produce alrededor de un
        1% de hallazgos, no un 8% fijado de antemano. Si el modelo no está
        entrenado, cae a la frontera de decisión del algoritmo (0.5).
        """
        if self._baseline_scores is None or self._baseline_scores.size == 0:
            return 0.5
        return float(
            max(np.percentile(self._baseline_scores, self.BASELINE_PERCENTILE), 0.5)
        )

    def fit(self, events: list[SecurityEvent]) -> "AnomalyDetector":
        """
        Entrena el modelo sobre una línea base de comportamiento.

        Nota metodológica: el pipeline entrena y puntúa sobre el mismo lote, lo
        que es aceptable para una demo no supervisada pero no para medir. Para la
        evaluación cuantitativa (Fase 4) hay que entrenar sobre tráfico
        etiquetado como benigno y puntuar sobre un conjunto separado.
        """
        from sklearn.ensemble import IsolationForest

        self.extractor.fit(events)
        X = self.extractor.matrix(events)
        if X.shape[0] < self.MIN_TRAINING_EVENTS:
            # Muy pocos datos para ML fiable; el modelo queda inactivo.
            self._model = None
            return self
        self._means = X.mean(axis=0)
        self._stds = X.std(axis=0) + 1e-9
        Xn = (X - self._means) / self._stds
        self._model = IsolationForest(
            contamination=self.contamination,
            random_state=self.random_state,
            n_estimators=self.n_estimators,
        ).fit(Xn)
        # Distribución de la línea base: define qué es "raro aquí".
        self._baseline_scores = np.clip(-self._model.score_samples(Xn), 0.0, 1.0)
        return self

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

        X = self.extractor.matrix(events)
        Xn = (X - self._means) / self._stds
        scores = np.clip(-self._model.score_samples(Xn), 0.0, 1.0)
        preds = self._model.predict(Xn)   # -1 anómalo, 1 normal

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
