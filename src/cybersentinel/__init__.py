"""
CyberSentinel — Agente defensivo de ciberseguridad (blue team).

Analiza telemetría, detecta anomalías, correlaciona incidentes, los mapea a
MITRE ATT&CK, predice la fase siguiente de la cadena de ataque, explica cada
decisión en lenguaje natural y clasifica contramedidas bajo una capa de
gobernanza ética con human-in-the-loop.

Ámbito: estrictamente DEFENSIVO y de LABORATORIO.
"""
__version__ = "0.1.0"
__author__ = "Luis Emir — Proyecto de grado (Especialización en Ciberseguridad)"

from .schema import SecurityEvent, Severity  # noqa: F401
