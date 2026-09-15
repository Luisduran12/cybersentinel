"""
Base interface para modelos de Machine Learning en CyberSentinel.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any
import numpy as np

from ..schema import SecurityEvent

class Dataset:
    """Contenedor de datos estructurados para ML."""
    def __init__(self, X: np.ndarray, y: np.ndarray | None = None, events: list[SecurityEvent] | None = None):
        self.X = X
        self.y = y
        self.events = events or []

class MLModel(ABC):
    """
    Interfaz base para modelos de ML.
    Permite intercambiar algoritmos (Isolation Forest, Random Forest, etc.)
    sin modificar el resto del sistema.
    """
    @abstractmethod
    def fit(self, dataset: Dataset) -> "MLModel":
        """Entrena el modelo con el dataset."""
        pass

    @abstractmethod
    def predict(self, dataset: Dataset) -> np.ndarray:
        """Devuelve predicciones duras (ej. -1 para anómalo, 1 para normal)."""
        pass

    def predict_proba(self, dataset: Dataset) -> np.ndarray:
        """Devuelve puntuaciones o probabilidades si el algoritmo lo soporta."""
        raise NotImplementedError("predict_proba no está implementado para este modelo")

    @abstractmethod
    def evaluate(self, dataset: Dataset) -> dict[str, float]:
        """Evalúa métricas de rendimiento sobre un dataset etiquetado."""
        pass
