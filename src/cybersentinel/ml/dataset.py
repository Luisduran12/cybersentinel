"""
Manejo de Datasets y Data Splits (Fase 4).
Implementa un TimeBasedSplitter estricto para evitar data leakage.
"""
from __future__ import annotations
from typing import Tuple

from ..schema import SecurityEvent

class TimeBasedSplitter:
    """
    Divide una lista cronológica de eventos en Train, Validation y Test.
    Garantiza 0 leakage temporal:
      - Pasado -> Entrenamiento
      - Posterior -> Validación
      - Futuro -> Test
    """
    def __init__(self, train_ratio: float = 0.6, val_ratio: float = 0.2):
        self.train_ratio = train_ratio
        self.val_ratio = val_ratio
        
        if train_ratio + val_ratio >= 1.0:
            raise ValueError("train_ratio + val_ratio debe ser < 1.0 para dejar datos de test")

    def split(self, events: list[SecurityEvent]) -> Tuple[list[SecurityEvent], list[SecurityEvent], list[SecurityEvent]]:
        """
        Ordena y divide los eventos temporalmente.
        Devuelve: (train_events, val_events, test_events)
        """
        if not events:
            return [], [], []
            
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        n = len(sorted_events)
        
        train_end = int(n * self.train_ratio)
        val_end = train_end + int(n * self.val_ratio)
        
        train_events = sorted_events[:train_end]
        val_events = sorted_events[train_end:val_end]
        test_events = sorted_events[val_end:]
        
        return train_events, val_events, test_events
