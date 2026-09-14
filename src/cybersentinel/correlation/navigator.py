"""
Exportación de incidentes como capa de MITRE ATT&CK Navigator.

Navigator (<https://mitre-attack.github.io/attack-navigator/>) pinta la matriz
ATT&CK completa y colorea las técnicas según una puntuación. Una capa es un JSON
que se arrastra a la herramienta.

Para qué sirve en la memoria
----------------------------
Convierte una lista de incidentes en **una sola figura** que responde a dos
preguntas a la vez: qué técnicas detectó el sistema y, sobre todo, **qué partes
de la matriz quedan a oscuras**. Ese hueco es un resultado en sí mismo: una
cobertura del 3% de ATT&CK es un dato honesto y defendible, y señala el trabajo
que falta mejor que cualquier párrafo.

La capa se puede generar de dos formas:

- **por incidentes detectados** (`layer_from_incidents`): qué se vio realmente,
  coloreado por el riesgo del incidente;
- **por cobertura de reglas** (`layer_from_rules`): qué es capaz de detectar el
  sistema, exista o no un ataque. Es la que mide el alcance del proyecto.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from . import mitre

#: Versiones del formato de capa que entiende Navigator.
LAYER_VERSION = "4.5"
NAVIGATOR_VERSION = "5.1.0"
DOMAIN = "enterprise-attack"

#: Degradado de blanco a rojo: a más riesgo, más intenso.
GRADIENT = {"colors": ["#ffffff", "#ffe766", "#ff6666"], "minValue": 0, "maxValue": 100}

#: Color plano para la capa de cobertura (sí/no, sin gradación).
COVERAGE_COLOR = "#2f7ed8"


def _attack_version() -> str:
    """Versión de ATT&CK a la que corresponde la capa (Navigator la valida)."""
    version = mitre.attack_data().version
    # Navigator espera la version mayor, "19", no "19.2".
    return version.split(".")[0] if version[:1].isdigit() else "17"


def _base_layer(name: str, description: str) -> dict[str, Any]:
    return {
        "name": name,
        "versions": {
            "attack": _attack_version(),
            "navigator": NAVIGATOR_VERSION,
            "layer": LAYER_VERSION,
        },
        "domain": DOMAIN,
        "description": description,
        "filters": {"platforms": ["Windows", "Linux", "macOS", "Network"]},
        "sorting": 3,                      # por puntuación, descendente
        "layout": {"layout": "side", "showName": True, "showID": True},
        "hideDisabled": False,
        "gradient": dict(GRADIENT),
        "legendItems": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "techniques": [],
        "metadata": [
            {"name": "generado por", "value": "CyberSentinel"},
            {"name": "fecha", "value": datetime.now(tz=timezone.utc).isoformat(timespec="seconds")},
            {"name": "matriz", "value": mitre.describe_source()},
        ],
    }


def layer_from_incidents(
    incidents: Iterable[Any],
    name: str = "CyberSentinel — incidentes detectados",
    description: str = "",
) -> dict[str, Any]:
    """
    Capa coloreada por el riesgo del incidente en el que apareció cada técnica.

    Cuando una técnica aparece en varios incidentes se queda con el riesgo más
    alto: la matriz debe destacar el peor caso observado, no la media.
    """
    incidents = list(incidents)
    scores: dict[str, int] = {}
    comments: dict[str, list[str]] = {}

    for incident in incidents:
        for technique_id in getattr(incident, "techniques", []):
            score = int(getattr(incident, "risk_score", 0))
            scores[technique_id] = max(scores.get(technique_id, 0), score)
            comments.setdefault(technique_id, []).append(
                f"{incident.incident_id} · {incident.entity} · riesgo {score}/100"
            )

    layer = _base_layer(
        name,
        description or (
            f"{len(scores)} técnicas observadas en {len(incidents)} incidente(s). "
            "El color indica el riesgo del incidente más grave en el que apareció "
            "cada técnica."
        ),
    )
    layer["techniques"] = [
        {
            "techniqueID": technique_id,
            "score": score,
            "comment": "\n".join(comments[technique_id]),
            "enabled": True,
            "showSubtechniques": False,
            "metadata": [
                {"name": "nombre", "value": mitre.technique_name(technique_id)},
                {"name": "tácticas", "value": ", ".join(mitre.tactics_of(technique_id)) or "desconocida"},
            ],
        }
        for technique_id, score in sorted(scores.items(), key=lambda kv: -kv[1])
    ]
    return layer


def layer_from_rules(
    rules: Iterable[Any],
    name: str = "CyberSentinel — cobertura de detección",
    description: str = "",
) -> dict[str, Any]:
    """
    Capa con lo que el sistema **es capaz** de detectar, haya ataque o no.

    Es la figura que mide el alcance real del proyecto: sobre las 222 técnicas de
    la matriz empresarial, colorea las que tienen al menos una regla. El resto de
    la matriz, en blanco, es el trabajo pendiente.
    """
    rules = list(rules)
    por_tecnica: dict[str, list[Any]] = {}
    for rule in rules:
        technique_id = getattr(rule, "mitre_technique", "unknown")
        if technique_id and technique_id != "unknown":
            por_tecnica.setdefault(technique_id, []).append(rule)

    total = max(mitre.attack_data().n_techniques, 1)
    cobertura = len(por_tecnica) / total

    layer = _base_layer(
        name,
        description or (
            f"{len(por_tecnica)} de {total} técnicas de la matriz empresarial "
            f"tienen al menos una regla ({cobertura:.1%}). Las técnicas sin color "
            "son las que el sistema no detecta hoy."
        ),
    )
    layer["gradient"] = {"colors": ["#ffffff", COVERAGE_COLOR], "minValue": 0, "maxValue": 1}
    layer["legendItems"] = [{"label": "cubierta por al menos una regla", "color": COVERAGE_COLOR}]
    layer["techniques"] = [
        {
            "techniqueID": technique_id,
            "score": 1,
            "color": COVERAGE_COLOR,
            "comment": "\n".join(
                f"{r.id}: {r.title} (severidad {r.severity.value})" for r in reglas
            ),
            "enabled": True,
            "showSubtechniques": False,
            "metadata": [
                {"name": "nombre", "value": mitre.technique_name(technique_id)},
                {"name": "reglas", "value": str(len(reglas))},
            ],
        }
        for technique_id, reglas in sorted(por_tecnica.items())
    ]
    return layer


def coverage_summary(rules: Iterable[Any]) -> dict[str, Any]:
    """
    Resumen numérico de la cobertura, por táctica.

    Complementa a la figura: un tribunal pide el número, no solo el dibujo.
    """
    rules = list(rules)
    tecnicas_cubiertas = {
        getattr(r, "mitre_technique", "unknown") for r in rules
    } - {"unknown", None, ""}

    por_tactica: dict[str, set[str]] = {t: set() for t in mitre.TACTIC_ORDER}
    for technique_id in tecnicas_cubiertas:
        for tactic in mitre.tactics_of(technique_id):
            por_tactica.setdefault(tactic, set()).add(technique_id)

    data = mitre.attack_data()
    totales: dict[str, int] = {t: 0 for t in mitre.TACTIC_ORDER}
    for technique in data.techniques.values():
        if technique.is_subtechnique:
            continue
        for tactic in technique.tactics:
            totales[tactic] = totales.get(tactic, 0) + 1

    return {
        "matriz": mitre.describe_source(),
        "tecnicas_cubiertas": len(tecnicas_cubiertas),
        "tecnicas_totales": data.n_techniques,
        "cobertura": round(len(tecnicas_cubiertas) / max(data.n_techniques, 1), 4),
        "por_tactica": [
            {
                "tactica": tactic,
                "tactica_es": mitre.tactic_label(tactic),
                "cubiertas": len(por_tactica.get(tactic, set())),
                "totales": totales.get(tactic, 0),
            }
            for tactic in mitre.TACTIC_ORDER
        ],
    }


def save_layer(layer: dict[str, Any], path: str | Path) -> Path:
    """Escribe la capa en disco, lista para arrastrar a Navigator."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(layer, indent=2, ensure_ascii=False), encoding="utf-8")
    return path
