"""
Cargador de reglas en formato Sigma público.

Carga archivos .yml/.yaml de un directorio, los valida con pySigma 1.5.0
y devuelve una lista de SigmaBackedRule listos para RulesEngine.

CONTRATO:
  - Una regla que no puede parsearse NO interrumpe la carga del resto.
  - Cada error o exclusión se registra en el log con nivel WARNING.
  - Las reglas NOT_EVALUABLE (campos no disponibles, aggregation Sigma) se
    registran pero NO se añaden al engine. No se silencian en silencio.
"""
from __future__ import annotations

import logging
from pathlib import Path

from sigma.exceptions import SigmaError
from sigma.rule import SigmaRule

from .rules_engine import DetectionRule
from .sigma_adapter import SigmaBackedRule, SigmaParseError, sigma_rule_to_detection_rule

logger = logging.getLogger(__name__)


def load_sigma_rules(directory: str | Path) -> list[DetectionRule]:
    """
    Carga todas las reglas Sigma (.yml / .yaml) de un directorio.

    Cada archivo se parsea con SigmaRule.from_yaml() y se convierte a
    SigmaBackedRule con sigma_rule_to_detection_rule(). Los archivos que
    fallen (YAML inválido, error pySigma, regla no evaluable) se omiten
    con una advertencia en el log.

    Returns:
        Lista de SigmaBackedRule evaluables. Puede estar vacía si ningún
        archivo del directorio es válido.
    """
    directory = Path(directory)
    if not directory.exists():
        logger.warning(
            "Directorio de reglas Sigma '%s' no existe; no se carga ninguna regla.",
            directory,
        )
        return []

    rules: list[DetectionRule] = []
    files = sorted(directory.glob("*.y*ml"))

    if not files:
        logger.warning(
            "Directorio '%s' no contiene archivos .yml/.yaml.", directory
        )
        return []

    for file in files:
        _load_single_file(file, rules)

    logger.info(
        "Sigma loader: %d reglas cargadas de %d archivos en '%s'.",
        len(rules), len(files), directory,
    )
    return rules


def _load_single_file(file: Path, rules: list[DetectionRule]) -> None:
    """
    Intenta cargar un único archivo Sigma y añade la regla a la lista.

    Registra advertencias sin relanzar excepciones para que el bucle
    principal continue con el resto de los archivos.
    """
    try:
        with open(file, encoding="utf-8") as fh:
            raw_yaml = fh.read()
    except OSError as exc:
        logger.warning("No se pudo leer '%s': %s", file.name, exc)
        return

    # ── Parseo con pySigma ──────────────────────────────────────────────────
    try:
        sigma_rule = SigmaRule.from_yaml(raw_yaml)
    except SigmaError as exc:
        logger.warning(
            "pySigma no pudo parsear '%s': %s — regla omitida.", file.name, exc
        )
        return
    except Exception as exc:
        logger.warning(
            "Error inesperado al parsear '%s': %s — regla omitida.", file.name, exc
        )
        return

    # ── Conversión a SigmaBackedRule ────────────────────────────────────────
    try:
        rule = sigma_rule_to_detection_rule(sigma_rule, source_file=str(file))
    except (SigmaParseError, Exception) as exc:
        logger.warning(
            "No se pudo convertir '%s' a DetectionRule: %s — regla omitida.",
            file.name, exc,
        )
        return

    if rule is None:
        # sigma_rule_to_detection_rule ya registró el motivo
        return

    if not rule.is_evaluable:
        logger.warning(
            "Regla '%s' (%s) cargada pero NOT_EVALUABLE: AST nulo. Omitida.",
            rule.title, file.name,
        )
        return

    rules.append(rule)
    logger.debug(
        "Regla Sigma cargada: '%s' [%s] técnica=%s táctica=%s",
        rule.title, rule.id, rule.mitre_technique, rule.mitre_tactic,
    )
