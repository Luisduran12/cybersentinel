"""
Acceso a MITRE ATT&CK: tácticas, técnicas y orden de la cadena de ataque.

Este módulo es una **fachada**. Los datos salen, por orden de preferencia, de:

1. la caché generada del STIX oficial (`data/attack/attack_cache.json`),
2. el subconjunto embebido de más abajo, como respaldo.

El subconjunto embebido se conserva a propósito: garantiza que el sistema
arranque y las pruebas pasen en un clon recién descargado, sin la matriz oficial
ni dependencias pesadas. Cubre las técnicas que citan las reglas propias.

Lo que la matriz oficial cambió respecto al subconjunto escrito a mano
---------------------------------------------------------------------
- La táctica `defense-evasion` **ya no existe**: MITRE la dividió en `stealth` y
  `defense-impairment`, y la matriz pasó de 14 a 15 fases. Los nombres retirados
  se siguen resolviendo mediante alias, para que reglas y corpus anteriores no se
  rompan.
- **Una técnica puede pertenecer a varias tácticas.** `T1053` (Scheduled
  Task/Job) está en ejecución, persistencia y escalada de privilegios a la vez;
  `T1078` (Valid Accounts), en cuatro. El modelo embebido asumía una sola, que es
  una simplificación que la matriz real no respalda.
- Hay técnicas revocadas (p. ej. `T1562`) que un subconjunto manual mantiene
  vivas indefinidamente.
"""
from __future__ import annotations

from typing import Any

from .attack_data import TACTIC_ALIASES, AttackData, Technique  # noqa: F401

# --- Respaldo embebido --------------------------------------------------------
# Orden canónico de tácticas ATT&CK (Enterprise) anterior a la reestructuración.
# Se conserva como respaldo; el orden vigente lo aporta la caché oficial.
EMBEDDED_TACTIC_ORDER: list[str] = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "stealth",
    "defense-impairment",
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
    "stealth": "Sigilo",
    "defense-impairment": "Degradación de defensas",
    "defense-evasion": "Evasión de defensas",   # nombre retirado, se mantiene por compatibilidad
    "credential-access": "Acceso a credenciales",
    "discovery": "Descubrimiento",
    "lateral-movement": "Movimiento lateral",
    "collection": "Recolección",
    "command-and-control": "Comando y control",
    "exfiltration": "Exfiltración",
    "impact": "Impacto",
}

#: Subconjunto embebido: las técnicas que citan las reglas propias.
TECHNIQUES: dict[str, dict[str, str]] = {
    "T1595": {"name": "Active Scanning", "tactic": "reconnaissance"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "initial-access"},
    "T1078": {"name": "Valid Accounts", "tactic": "initial-access"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "execution"},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "execution"},
    "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": "persistence"},
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "privilege-escalation"},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "stealth"},
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


def _embedded() -> AttackData:
    """Construye la matriz de respaldo a partir del subconjunto embebido."""
    return AttackData(
        techniques={
            tid: Technique(id=tid, name=info["name"], tactics=[info["tactic"]])
            for tid, info in TECHNIQUES.items()
        },
        tactic_order=list(EMBEDDED_TACTIC_ORDER),
        tactic_names={t: TACTIC_LABELS_ES.get(t, t) for t in EMBEDDED_TACTIC_ORDER},
        version="subconjunto embebido",
        source="embebido",
    )


# --- Fuente activa ------------------------------------------------------------
_DATA: AttackData = AttackData.load() or _embedded()

#: Orden vigente de tácticas. Lo define la matriz oficial cuando hay caché.
TACTIC_ORDER: list[str] = list(_DATA.tactic_order)


def attack_data() -> AttackData:
    """La matriz activa, para quien necesite consultas que la fachada no expone."""
    return _DATA


def using_official_matrix() -> bool:
    """¿Se están usando los datos oficiales o el respaldo embebido?"""
    return _DATA.source != "embebido"


def describe_source() -> str:
    """Resumen legible de qué matriz se está usando (para la CLI y la memoria)."""
    if not using_official_matrix():
        return (
            f"subconjunto embebido ({len(TECHNIQUES)} técnicas). Ejecuta "
            "'cybersentinel attack-sync' para usar la matriz oficial."
        )
    return (
        f"MITRE ATT&CK v{_DATA.version} ({_DATA.n_techniques} técnicas, "
        f"{_DATA.n_subtechniques} subtécnicas, {len(TACTIC_ORDER)} tácticas)"
    )


def reload(path: str | Any = None) -> AttackData:
    """
    Recarga la matriz desde una caché concreta (o vuelve a buscar la de por
    defecto). Devuelve la matriz activa resultante.
    """
    global _DATA, TACTIC_ORDER
    _DATA = (AttackData.load(path) if path else AttackData.load()) or _embedded()
    TACTIC_ORDER = list(_DATA.tactic_order)
    return _DATA


def use(data: AttackData) -> AttackData:
    """Inyecta una matriz concreta. Pensado para las pruebas."""
    global _DATA, TACTIC_ORDER
    _DATA = data
    TACTIC_ORDER = list(data.tactic_order)
    return _DATA


# --- Interfaz pública (estable desde la primera versión) ----------------------
def technique_name(technique_id: str) -> str:
    """Nombre de una técnica. Resuelve subtécnicas por su técnica madre."""
    found = _DATA.technique(technique_id)
    return found.name if found else technique_id


def tactics_of(technique_id: str) -> list[str]:
    """Todas las tácticas de una técnica. Una técnica puede estar en varias."""
    return _DATA.tactics_of(technique_id)


def tactic_of(technique_id: str) -> str:
    """
    Una sola táctica por técnica, la más temprana de la cadena.

    Se mantiene por compatibilidad y porque el correlador necesita un valor
    escalar. Cuando la técnica pertenece a varias fases, usa `tactics_of`.
    """
    return _DATA.primary_tactic(technique_id)


def normalize_tactic(tactic: str) -> str:
    """Traduce un nombre de táctica retirado a su equivalente vigente."""
    return _DATA.normalize_tactic(tactic)


def tactic_index(tactic: str) -> int:
    """Posición de la táctica en la cadena. -1 si es desconocida."""
    try:
        return TACTIC_ORDER.index(_DATA.normalize_tactic(tactic))
    except ValueError:
        return -1


def tactic_label(tactic: str) -> str:
    """Nombre legible en español de una táctica."""
    return TACTIC_LABELS_ES.get(tactic, _DATA.tactic_names.get(tactic, tactic))


def next_tactics(tactic: str, k: int = 2) -> list[str]:
    """Las k tácticas que siguen a la actual en el orden de la cadena."""
    index = tactic_index(tactic)
    if index == -1:
        return []
    return TACTIC_ORDER[index + 1: index + 1 + k]
