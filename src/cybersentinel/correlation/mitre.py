"""
Mapeo a MITRE ATT&CK y ordenamiento de la cadena de ataque (kill-chain).

Contiene un subconjunto embebido de tácticas y técnicas ATT&CK suficiente para
un laboratorio de grado. En producción esto se sustituiría por la matriz
completa descargada del STIX oficial de MITRE (ver docs/ARCHITECTURE.md).

El orden de las tácticas modela la progresión típica de un ataque, que es lo
que permite predecir la fase siguiente.
"""
from __future__ import annotations

# Orden canónico de tácticas ATT&CK (Enterprise) — base para la predicción.
TACTIC_ORDER: list[str] = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

TACTIC_LABELS_ES: dict[str, str] = {
    "reconnaissance": "Reconocimiento",
    "resource-development": "Desarrollo de recursos",
    "initial-access": "Acceso inicial",
    "execution": "Ejecución",
    "persistence": "Persistencia",
    "privilege-escalation": "Escalada de privilegios",
    "defense-evasion": "Evasión de defensas",
    "credential-access": "Acceso a credenciales",
    "discovery": "Descubrimiento",
    "lateral-movement": "Movimiento lateral",
    "collection": "Recolección",
    "command-and-control": "Comando y control",
    "exfiltration": "Exfiltración",
    "impact": "Impacto",
}

# Subconjunto de técnicas (id -> nombre, táctica).
TECHNIQUES: dict[str, dict[str, str]] = {
    "T1595": {"name": "Active Scanning", "tactic": "reconnaissance"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "initial-access"},
    "T1078": {"name": "Valid Accounts", "tactic": "initial-access"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "execution"},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "persistence"},
    "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": "persistence"},
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "privilege-escalation"},
    "T1562": {"name": "Impair Defenses", "tactic": "defense-evasion"},
    "T1110": {"name": "Brute Force", "tactic": "credential-access"},
    "T1003": {"name": "OS Credential Dumping", "tactic": "credential-access"},
    "T1087": {"name": "Account Discovery", "tactic": "discovery"},
    "T1046": {"name": "Network Service Discovery", "tactic": "discovery"},
    "T1021": {"name": "Remote Services", "tactic": "lateral-movement"},
    "T1560": {"name": "Archive Collected Data", "tactic": "collection"},
    "T1071": {"name": "Application Layer Protocol", "tactic": "command-and-control"},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "exfiltration"},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "exfiltration"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "impact"},
    "T1490": {"name": "Inhibit System Recovery", "tactic": "impact"},
}


def technique_name(technique_id: str) -> str:
    return TECHNIQUES.get(technique_id, {}).get("name", technique_id)


def tactic_of(technique_id: str) -> str:
    return TECHNIQUES.get(technique_id, {}).get("tactic", "unknown")


def tactic_index(tactic: str) -> int:
    """Posición de la táctica en la cadena (para ordenar/predecir). -1 si desconocida."""
    try:
        return TACTIC_ORDER.index(tactic)
    except ValueError:
        return -1


def next_tactics(tactic: str, k: int = 2) -> list[str]:
    """Devuelve las siguientes k tácticas probables tras la actual."""
    idx = tactic_index(tactic)
    if idx == -1:
        return []
    return TACTIC_ORDER[idx + 1: idx + 1 + k]
