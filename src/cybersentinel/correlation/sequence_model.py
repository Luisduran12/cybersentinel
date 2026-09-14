"""
Modelos de secuencia para predecir la fase siguiente de la cadena de ataque.

Este módulo es el diferenciador del proyecto: convierte "detecté X" en "esto es
la fase N de un ataque y lo más probable es que siga Z", con una probabilidad
que se aprende de datos en vez de postularse.

Contiene tres piezas:

- `SequenceModel`: la interfaz. Cualquier modelo que prediga la táctica
  siguiente la implementa. Está pensada para que sustituir la cadena de Markov
  por un LSTM (o un transformer) no obligue a tocar el correlador: basta con
  implementar `fit`, `predict_next` y la (de)serialización.
- `MarkovChainModel`: cadena de Markov de primer orden sobre tácticas ATT&CK,
  con suavizado de Laplace. Aprende la matriz de transición de secuencias
  etiquetadas.
- `CanonicalBaseline`: la heurística actual (el orden canónico de la cadena)
  expuesta con la misma interfaz, para poder compararlas numéricamente. Sin una
  línea base, decir que el modelo "funciona" no significa nada.

Dos decisiones de diseño que conviene poder defender:

1. **Estado de condicionamiento.** Una cadena de Markov pura condiciona en el
   último estado observado. Aquí el valor por defecto es condicionar en la fase
   **más profunda** alcanzada (`condition_on="deepest"`), porque un atacante que
   ya exfiltró no ha "vuelto" a la fase de credenciales porque llegue un evento
   tardío de esa fase: la fase efectiva del incidente es la más avanzada. Es una
   desviación deliberada de la propiedad de Markov y se puede desactivar
   (`condition_on="last"`) para medir ambas variantes.
2. **Exclusión de fases ya observadas.** Predecir una fase que el incidente ya
   atravesó no aporta nada operativamente. Se filtra por defecto, igual que las
   fases anteriores a la actual (`monotonic`).
3. **Las probabilidades no se renormalizan** tras esos filtros. Son la
   probabilidad condicional que sale de la matriz de transición, así que la suma
   de las k devueltas puede ser mucho menor que 1: la masa restante está en el
   estado final `<END>` y en las fases descartadas. Renormalizar produciría un
   "Impacto: 100%" cuando solo queda una candidata, aunque el modelo estime que
   el ataque se detiene ahí nueve de cada diez veces.
"""
from __future__ import annotations

import json
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Literal, Sequence

from . import mitre

#: Estado ficticio que marca el final de una campaña (el ataque se detuvo ahí).
END_STATE = "<END>"

ConditionOn = Literal["deepest", "last"]


def _conditioning_state(history: Sequence[str], condition_on: ConditionOn) -> str | None:
    """Elige sobre qué táctica de la historia se condiciona la predicción."""
    known = [t for t in history if mitre.tactic_index(t) >= 0]
    if not known:
        return None
    if condition_on == "last":
        return known[-1]
    return max(known, key=mitre.tactic_index)


class SequenceModel(ABC):
    """
    Interfaz de un modelo de predicción de la táctica siguiente.

    Implementar un LSTM en el futuro significa heredar de aquí y respetar el
    contrato de `predict_next`: devolver pares (táctica, probabilidad) ordenados
    de mayor a menor, con probabilidades en [0, 1].
    """

    name: str = "sequence-model"

    @abstractmethod
    def fit(self, sequences: Iterable[Sequence[str]]) -> "SequenceModel":
        """Aprende de un corpus de secuencias de tácticas."""

    @abstractmethod
    def predict_next(
        self, history: Sequence[str], k: int = 3, exclude_observed: bool = True
    ) -> list[tuple[str, float]]:
        """Devuelve las k tácticas siguientes más probables, con su probabilidad."""

    @abstractmethod
    def to_dict(self) -> dict[str, Any]:
        """Representación serializable del modelo entrenado."""

    @property
    def is_fitted(self) -> bool:
        return True

    def save(self, path: str | Path) -> Path:
        """Persiste el modelo en JSON (auditable a ojo, a diferencia de un pickle)."""
        path = Path(path)
        path.write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8"
        )
        return path

    def probability_of_end(self, history: Sequence[str]) -> float:
        """Probabilidad de que el ataque se detenga aquí. 0 si el modelo no la estima."""
        return 0.0


@dataclass
class MarkovChainModel(SequenceModel):
    """
    Cadena de Markov de primer orden sobre tácticas MITRE ATT&CK.

    La matriz de transición se estima por conteo con suavizado de Laplace: una
    transición nunca observada recibe probabilidad pequeña pero no nula, para que
    el modelo no sea imposible de sorprender (y para que la perplejidad esté
    definida sobre datos nuevos).
    """

    alpha: float = 0.5                       # suavizado de Laplace
    condition_on: ConditionOn = "deepest"
    #: Si True, solo se proponen fases posteriores a la actual en la cadena.
    #: Sin esto, cuando la fase actual es terminal (p. ej. exfiltración) casi
    #: toda la masa de probabilidad se la lleva `<END>`, el resto queda repartido
    #: por el suavizado y el modelo acaba proponiendo una fase ya superada.
    monotonic: bool = True
    name: str = "markov-orden-1"

    #: transiciones[origen][destino] = veces observadas
    transitions: dict[str, dict[str, int]] = field(default_factory=dict)
    n_sequences: int = 0

    @property
    def states(self) -> list[str]:
        """Estados posibles de destino: las tácticas conocidas más el fin."""
        return list(mitre.TACTIC_ORDER) + [END_STATE]

    @property
    def is_fitted(self) -> bool:
        return self.n_sequences > 0

    def fit(self, sequences: Iterable[Sequence[str]]) -> "MarkovChainModel":
        """
        Cuenta transiciones entre tácticas consecutivas de cada secuencia.

        Cada secuencia aporta además una transición a `<END>`, que es lo que
        permite al modelo estimar si un ataque suele detenerse en esa fase.
        """
        counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        total = 0
        for raw in sequences:
            seq = [t for t in raw if mitre.tactic_index(t) >= 0]
            if not seq:
                continue
            total += 1
            for origin, target in zip(seq, seq[1:]):
                counts[origin][target] += 1
            counts[seq[-1]][END_STATE] += 1

        self.transitions = {o: dict(t) for o, t in counts.items()}
        self.n_sequences = total
        return self

    def transition_probabilities(self, origin: str) -> dict[str, float]:
        """Distribución suavizada de la táctica siguiente dada `origin`."""
        observed = self.transitions.get(origin, {})
        states = self.states
        denominator = sum(observed.values()) + self.alpha * len(states)
        return {
            state: (observed.get(state, 0) + self.alpha) / denominator
            for state in states
        }

    def predict_next(
        self, history: Sequence[str], k: int = 3, exclude_observed: bool = True
    ) -> list[tuple[str, float]]:
        origin = _conditioning_state(history, self.condition_on)
        if origin is None or not self.is_fitted:
            return []

        probabilities = self.transition_probabilities(origin)
        probabilities.pop(END_STATE, None)
        if exclude_observed:
            for seen in set(history):
                probabilities.pop(seen, None)
        if self.monotonic:
            frontier = mitre.tactic_index(origin)
            probabilities = {
                tactic: p for tactic, p in probabilities.items()
                if mitre.tactic_index(tactic) > frontier
            }
        if not probabilities:
            return []

        # Se devuelve la probabilidad condicional TAL CUAL sale de la matriz, sin
        # renormalizar sobre las candidatas que quedan. Renormalizar daría un
        # "Impacto: 100%" cuando solo queda una candidata, aunque el modelo
        # estime un 91% de que el ataque se detenga ahí. La masa que falta para
        # sumar 1 está en `<END>` y en las fases descartadas, y se consulta con
        # `probability_of_end`.
        ranked = sorted(probabilities.items(), key=lambda kv: (-kv[1], kv[0]))
        return ranked[:k]

    def probability_of_end(self, history: Sequence[str]) -> float:
        origin = _conditioning_state(history, self.condition_on)
        if origin is None or not self.is_fitted:
            return 0.0
        return self.transition_probabilities(origin)[END_STATE]

    def matrix(self) -> tuple[list[str], list[list[float]]]:
        """Matriz de transición completa (para inspección o para la memoria)."""
        origins = list(mitre.TACTIC_ORDER)
        targets = self.states
        rows = [
            [self.transition_probabilities(origin)[target] for target in targets]
            for origin in origins
        ]
        return targets, rows

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.name,
            "alpha": self.alpha,
            "condition_on": self.condition_on,
            "monotonic": self.monotonic,
            "n_sequences": self.n_sequences,
            "transitions": self.transitions,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MarkovChainModel":
        model = cls(
            alpha=float(data.get("alpha", 0.5)),
            condition_on=data.get("condition_on", "deepest"),
            monotonic=bool(data.get("monotonic", True)),
        )
        model.transitions = {o: dict(t) for o, t in data.get("transitions", {}).items()}
        model.n_sequences = int(data.get("n_sequences", 0))
        return model

    @classmethod
    def load(cls, path: str | Path) -> "MarkovChainModel":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


@dataclass
class CanonicalBaseline(SequenceModel):
    """
    Línea base: la heurística del orden canónico de la cadena de ataque.

    No aprende nada; predice las fases que siguen en `mitre.TACTIC_ORDER`. Es
    exactamente lo que hacía el sistema antes de esta fase, expuesto con la misma
    interfaz para que la comparación sea honesta: mismo conjunto de evaluación,
    mismo criterio de acierto, misma forma de salida.

    Las "probabilidades" son un decaimiento geométrico normalizado: no son
    estimaciones, solo un orden de preferencia. Se declara como tal.
    """

    decay: float = 0.5
    condition_on: ConditionOn = "deepest"
    name: str = "heuristica-canonica"

    def fit(self, sequences: Iterable[Sequence[str]]) -> "CanonicalBaseline":
        """No-op: la heurística no se entrena. Está aquí por contrato de interfaz."""
        return self

    def predict_next(
        self, history: Sequence[str], k: int = 3, exclude_observed: bool = True
    ) -> list[tuple[str, float]]:
        origin = _conditioning_state(history, self.condition_on)
        if origin is None:
            return []
        index = mitre.tactic_index(origin)
        candidates = [
            t for t in mitre.TACTIC_ORDER[index + 1:]
            if not (exclude_observed and t in set(history))
        ][:k]
        if not candidates:
            return []
        weights = [self.decay ** i for i in range(len(candidates))]
        total = sum(weights)
        return [(t, w / total) for t, w in zip(candidates, weights)]

    def to_dict(self) -> dict[str, Any]:
        return {"model": self.name, "decay": self.decay, "condition_on": self.condition_on}


def sequences_from_incidents(incidents: Iterable[Any]) -> list[list[str]]:
    """
    Extrae secuencias de tácticas de incidentes ya correlacionados.

    Permite reentrenar el modelo con los incidentes que el propio sistema
    detectó (o con los de un dataset real en la Fase 4) sin acoplar este módulo
    al tipo `Incident`: basta con que el objeto exponga `.tactics`.
    """
    return [list(getattr(inc, "tactics", [])) for inc in incidents if getattr(inc, "tactics", None)]
