"""
Carga de configuración de CyberSentinel.

`config/config.yaml` existía pero no lo leía nadie: los parámetros estaban
duplicados como valores por defecto dentro de `Pipeline`. Este módulo lo
convierte en la única fuente de verdad, con los mismos defaults embebidos por si
el archivo no está.

Cualquier valor puede sobreescribirse por CLI; la precedencia es:

    argumento de CLI  >  config.yaml  >  default embebido
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

import yaml

#: Raíz del proyecto (…/cybersentinel), tres niveles por encima de este archivo.
ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = ROOT / "config" / "config.yaml"
DEFAULT_RULES_DIR = ROOT / "config" / "rules"
DEFAULT_POLICY_PATH = ROOT / "config" / "governance_policy.yaml"


@dataclass
class DetectionSettings:
    """Parámetros del detector de anomalías."""

    #: "auto" deja que Isolation Forest use su umbral estándar. Un número fija la
    #: proporción de anomalías por construcción, haya ataques o no.
    anomaly_contamination: float | str = "auto"

    #: None = usar el umbral sugerido por la línea base (percentil 99).
    anomaly_threshold: float | None = None


@dataclass
class CorrelationSettings:
    """Parámetros de agrupación de hallazgos en incidentes."""
    time_window_minutes: int = 30


@dataclass
class PredictionSettings:
    """Parámetros del modelo de predicción de kill-chain."""

    #: Ruta a un modelo de secuencia entrenado (JSON). None = heurística canónica.
    model_path: str | None = None

    #: Cuántas fases siguientes se proponen por incidente.
    top_k: int = 2


@dataclass
class ExplanationSettings:
    """Parámetros de la capa de explicabilidad."""
    use_llm: bool = False
    model: str = "claude-opus-5"


@dataclass
class Settings:
    """Configuración completa del sistema."""
    detection: DetectionSettings = field(default_factory=DetectionSettings)
    correlation: CorrelationSettings = field(default_factory=CorrelationSettings)
    prediction: PredictionSettings = field(default_factory=PredictionSettings)
    explanation: ExplanationSettings = field(default_factory=ExplanationSettings)

    @classmethod
    def load(cls, path: str | Path | None = None) -> "Settings":
        """
        Carga la configuración desde YAML. Si el archivo no existe, devuelve los
        valores por defecto (el sistema debe arrancar sin configuración).
        """
        path = Path(path) if path else DEFAULT_CONFIG_PATH
        if not path.exists():
            return cls()
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Settings":
        """Construye la configuración ignorando claves desconocidas."""
        def _section(cls_: type, key: str):
            raw = data.get(key) or {}
            known = {f for f in cls_.__dataclass_fields__}
            return cls_(**{k: v for k, v in raw.items() if k in known})

        return cls(
            detection=_section(DetectionSettings, "detection"),
            correlation=_section(CorrelationSettings, "correlation"),
            prediction=_section(PredictionSettings, "prediction"),
            explanation=_section(ExplanationSettings, "explanation"),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
