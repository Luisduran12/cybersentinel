"""
Analítica de comportamiento (Fase 4-B).

Aprende qué es "normal" por usuario y por host a partir de la telemetría real
que ya atraviesa el pipeline, y detecta cuándo un evento se desvía de ese
perfil. No es un pipeline paralelo: `DeviationDetector` alimenta el mismo
`DetectionEvidence` que Sigma, ML y correlación temporal (ver
`cybersentinel.pipeline`).
"""
from .baseline import BaselineStore, EntityBaseline
from .deviation import Deviation, DeviationDetector
from .profiler import EntityProfiler
from .risk_score import EntityRisk, RiskScoreTracker

__all__ = [
    "BaselineStore", "EntityBaseline",
    "Deviation", "DeviationDetector",
    "EntityProfiler",
    "EntityRisk", "RiskScoreTracker",
]
