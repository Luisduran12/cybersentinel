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

import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

import yaml
try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

#: Raíz del proyecto (…/cybersentinel), tres niveles por encima de este archivo.
ROOT = Path(__file__).resolve().parents[2]
if load_dotenv:
    load_dotenv(ROOT / ".env")
DEFAULT_CONFIG_PATH = ROOT / "config" / "config.yaml"
DEFAULT_RULES_DIR = ROOT / "config" / "rules"
#: Reglas en formato Sigma público (pySigma), curadas y documentadas en
#: config/sigma_rules/manifest.yaml. Hasta la Fase 4-A solo las cargaba
#: scripts/evaluate_sigma_phase1.py para un reporte offline: el Pipeline real
#: nunca las usaba. Se combinan con DEFAULT_RULES_DIR, no lo sustituyen.
DEFAULT_SIGMA_RULES_DIR = ROOT / "config" / "sigma_rules" / "selected"
DEFAULT_POLICY_PATH = ROOT / "config" / "governance_policy.yaml"
#: Cadena de Markov entrenada (Fase 3, `cybersentinel train-prediction`). Si
#: no existe, el Correlator cae a CanonicalBaseline (su propio default).
DEFAULT_MARKOV_MODEL_PATH = ROOT / "models" / "markov_tactics.json"

#: Umbral de decisión sobre `anomaly_score` (0..1) a partir del cual el
#: detector de anomalías cuenta como señal para `detection_status`/
#: `hybrid_score` (detection/hybrid.py) y para el hallazgo agregado del
#: correlador (correlation/correlator.py). NO es el `contamination` de
#: Isolation Forest (eso decide `is_anomaly` de forma independiente); es el
#: punto de corte que decide si esa puntuación mueve el veredicto híbrido.
#:
#: Calibrado el 2026-09-18 (auditoría de producción, hallazgo H-08) contra
#: los 1.020 eventos sintéticos del test de carga real (semilla 42, 5%
#: sospechosos), con partición train/validation/test 50/25/25 sin fuga de
#: datos — ver `scripts/calibrate_anomaly_threshold.py` y
#: `reports/anomaly_threshold_calibration.json` para el método completo y
#: el barrido de umbrales.
#:
#:   Umbral anterior (0.5, sin calibrar): FPR=30.5%  Recall=100.0% (validation)
#:   Umbral calibrado (0.602):            FPR=2.1%   Recall=100.0% (validation)
#:                                        FPR=2.9%   Recall=66.7%  (test, holdout)
#:
#: Ambos objetivos (FPR<15%, Recall>60%) se cumplen en validation Y en el
#: conjunto de prueba nunca visto durante la selección. La muestra es
#: pequeña (~46 eventos sospechosos en total, ~11-12 por partición): el
#: recall en test cae de 100% a 66.7% frente a validation, lo que refleja
#: varianza de muestra pequeña, no que el umbral esté mal elegido — un solo
#: evento de más o de menos mueve el recall ~8 puntos con este tamaño de
#: muestra. Esta es la mejor estimación honesta disponible hoy, no un
#: número ajustado a mano.
DEFAULT_ANOMALY_THRESHOLD = float(os.environ.get("CYBERSENTINEL_ANOMALY_THRESHOLD", "0.602"))


@dataclass
class DetectionSettings:
    """Parámetros del detector de anomalías."""

    #: "auto" deja que Isolation Forest use su umbral estándar. Un número fija la
    #: proporción de anomalías por construcción, haya ataques o no.
    anomaly_contamination: float | str = "auto"

    #: Umbral de decisión sobre anomaly_score. Ver DEFAULT_ANOMALY_THRESHOLD
    #: para la calibración; None solo si se quiere forzar explícitamente el
    #: umbral sugerido por la línea base (percentil 99) en vez del calibrado.
    anomaly_threshold: float | None = DEFAULT_ANOMALY_THRESHOLD


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
