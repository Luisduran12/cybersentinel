"""
Adaptador pySigma → motor de detección de CyberSentinel.

Convierte el AST interno de pySigma (ConditionAND / OR / NOT +
ConditionFieldEqualsValueExpression) en evaluaciones directas contra
SecurityEvent usando un evaluador recursivo propio, determinista y auditable.

DECISIÓN DE DISEÑO — pySigma como parser, evaluador propio:
  pySigma 1.5.0 es un motor de *traducción* (YAML → SPL/KQL/Elastic), no de
  evaluación en tiempo real. Su AST interno (ConditionAND, ConditionOR,
  ConditionNOT, ConditionFieldEqualsValueExpression) es, sin embargo,
  suficiente para construir un evaluador recursivo sin dependencias adicionales.

  Alternativas descartadas:
  - sigma-rule-matcher: librería comunitaria, mantenimiento incierto.
  - eval() sobre la condición: inseguro con reglas de terceros.
  - Backend personalizado pySigma: complejidad innecesaria para evaluación inline.

MAPEO DE CAMPOS (FIELD_MAP):
  Los campos Sigma estándar (ej. CommandLine, Image) se traducen a los campos
  de SecurityEvent mediante FIELD_MAP. Los campos CyberSentinel-nativos
  (command_line, dst_port, bytes_out…) se usan tal cual, sin mapeo adicional.

SEMÁNTICA DE TIPOS Sigma:
  - SigmaString sin especiales  → igualdad exacta (case-insensitive)
  - SigmaString con WILDCARD_*  → regex (fullmatch, IGNORECASE)
  - SigmaRegularExpression      → re.search (IGNORECASE)
  - SigmaNumber                 → igualdad numérica
  - SigmaCompareExpression      → comparación numérica (gt/lt/gte/lte/neq)

LIMITACIONES EXPLÍCITAS:
  - ConditionValueExpression (keyword sin campo) no está soportado: se registra
    como advertencia y devuelve False. Las 15 reglas seleccionadas no lo usan.
  - Reglas con `count()` / `near` (agregación Sigma) no se cargan: se registran
    como NOT_EVALUABLE y no se añaden al engine.
  - Campos Sigma sin mapeo y ausentes en event.raw devuelven False (no se
    inventa telemetría).
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.rule import SigmaRule
from sigma.types import (
    CompareOperators,
    SigmaCompareExpression,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaString,
    SigmaType,
    SpecialChars,
)

from ..schema import SecurityEvent, Severity
from .rules_engine import DetectionRule, Aggregation

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Mapeo de campos Sigma estándar → atributos de SecurityEvent
# ---------------------------------------------------------------------------
#
# Regla: si el campo de la regla Sigma está en FIELD_MAP, se usa el atributo
# de SecurityEvent indicado. Si no, se intenta `event.raw.get(sigma_field)`.
# Si tampoco está en raw, el campo se considera ausente → la condición falla.
# NO se inventa ni se convierte silenciosamente ningún campo.

FIELD_MAP: dict[str, str] = {
    # ── Proceso (Sysmon / Windows) ──────────────────────────────────────────
    "CommandLine":       "command_line",
    "Image":             "process_name",   # NOTA: Image=ruta completa; process_name=solo nombre base
    "ParentImage":       "parent_process", # NOTA: misma limitación que Image
    "ParentCommandLine": "parent_command_line",
    "OriginalFileName":  "original_file_name",
    "CurrentDirectory":  "current_directory",
    "IntegrityLevel":    "integrity_level",
    "Hashes":            "hashes",
    # ── Red ─────────────────────────────────────────────────────────────────
    "DestinationIp":     "dst_ip",
    "DestinationPort":   "dst_port",
    "SourceIp":          "src_ip",
    "SourcePort":        "src_port",
    "Protocol":          "protocol",
    "DestinationHostname": "dst_hostname",
    "Initiated":         "initiated",
    # ── Autenticación ───────────────────────────────────────────────────────
    "User":              "user",
    "IpAddress":         "src_ip",
    "WorkstationName":   "host",
    "TargetUserName":    "user",           # NOTA: SecurityEvent no distingue subject/target
    "SubjectUserName":   "subject_user_name",
    "LogonType":         "logon_type",
    "Status":            "status",
    # ── CyberSentinel-nativos (identidad) ────────────────────────────────────
    "command_line":      "command_line",
    "process_name":      "process_name",
    "parent_process":    "parent_process",
    "src_ip":            "src_ip",
    "dst_ip":            "dst_ip",
    "src_port":          "src_port",
    "dst_port":          "dst_port",
    "protocol":          "protocol",
    "bytes_out":         "bytes_out",
    "bytes_in":          "bytes_in",
    "outcome":           "outcome",
    "user":              "user",
    "host":              "host",
    "category":          "category",
    "action":            "action",
    "source":            "source",
}

# Campos Sigma explícitamente no disponibles (None en FIELD_MAP).
_UNAVAILABLE_FIELDS = {k for k, v in FIELD_MAP.items() if v is None}

# Mapeo de categoría logsource Sigma → category de SecurityEvent.
LOGSOURCE_CATEGORY_MAP: dict[str, str] = {
    "process_creation":   "process",
    "network_connection": "network",
    "network_flow":       "network",
    "authentication":     "authentication",
    "dns_query":          "dns",
    "file_event":         "file",
    "web_request":        "web",
    # CyberSentinel-nativos (ya normalizados)
    "process":            "process",
    "network":            "network",
}

# Mapeo de nivel Sigma → Severity de CyberSentinel.
_LEVEL_MAP: dict[str, Severity] = {
    "informational": Severity.INFO,
    "low":           Severity.LOW,
    "medium":        Severity.MEDIUM,
    "high":          Severity.HIGH,
    "critical":      Severity.CRITICAL,
}


# ---------------------------------------------------------------------------
# Excepciones
# ---------------------------------------------------------------------------

class SigmaParseError(Exception):
    """Error al parsear o convertir una regla Sigma."""


class SigmaNotEvaluableError(SigmaParseError):
    """La regla Sigma no puede evaluarse con la telemetría disponible."""


# ---------------------------------------------------------------------------
# Utilidades de evaluación
# ---------------------------------------------------------------------------

def _get_event_field(event: SecurityEvent, field_name: str) -> Any:
    """
    Devuelve el valor de un campo del evento, con event.properties y event.raw como respaldo.

    Devuelve None si el campo no existe en ninguno de los lugares.
    No lanza excepción: un campo ausente es una condición que no se cumple.
    """
    val = getattr(event, field_name, None)
    if val is None:
        val = event.properties.get(field_name)
    if val is None:
        val = event.raw.get(field_name)
    return val


def _sigma_string_match(sigma_str: SigmaString, actual_str: str) -> bool:
    """
    Evalúa una SigmaString (con o sin wildcards) contra un string real.

    - Sin wildcards (ej. exacto, no modifier)  → igualdad exacta, IGNORECASE
    - Con WILDCARD_MULTI / WILDCARD_SINGLE     → patrón regex, fullmatch IGNORECASE
    """
    if not sigma_str.contains_special():
        # Igualdad exacta: reconstruye el string plano de las partes
        plain = "".join(str(p) for p in sigma_str.s if isinstance(p, str))
        return plain.lower() == actual_str.lower()

    # Construye regex a partir de las partes de la SigmaString
    parts: list[str] = []
    for part in sigma_str.s:
        if part is SpecialChars.WILDCARD_MULTI:
            parts.append(".*")
        elif part is SpecialChars.WILDCARD_SINGLE:
            parts.append(".")
        else:
            parts.append(re.escape(str(part)))
    pattern = "".join(parts)
    return bool(re.fullmatch(pattern, actual_str, re.IGNORECASE))


def _match_sigma_value(sigma_val: SigmaType, actual: Any) -> bool:
    """
    Compara un valor pySigma tipado contra el valor real del campo.

    Tipos soportados: SigmaString, SigmaRegularExpression, SigmaNumber,
    SigmaCompareExpression.

    Tipos no soportados: se registra advertencia y devuelve False. No se lanza
    excepción para no interrumpir la evaluación de otras condiciones.
    """
    if actual is None:
        return False

    actual_str = str(actual)

    if isinstance(sigma_val, SigmaRegularExpression):
        # regexp is stored internally as SigmaString; convert to plain str before compiling.
        # Also apply any flags declared on the SigmaRegularExpression object.
        flags = re.IGNORECASE
        for flag in sigma_val.flags:
            flags |= sigma_val.sigma_to_python_flags.get(flag, 0)
        return bool(re.search(str(sigma_val.regexp), actual_str, flags))

    if isinstance(sigma_val, SigmaString):
        return _sigma_string_match(sigma_val, actual_str)

    if isinstance(sigma_val, SigmaCompareExpression):
        try:
            actual_num = float(actual_str)
            cmp_num = float(sigma_val.number.number)
            op = sigma_val.op
            if op == CompareOperators.GT:
                return actual_num > cmp_num
            if op == CompareOperators.LT:
                return actual_num < cmp_num
            if op == CompareOperators.GTE:
                return actual_num >= cmp_num
            if op == CompareOperators.LTE:
                return actual_num <= cmp_num
            if op == CompareOperators.NEQ:
                return actual_num != cmp_num
            # EQ no existe en CompareOperators enum; cae al final
        except (ValueError, TypeError):
            return False

    if isinstance(sigma_val, SigmaNumber):
        try:
            return float(actual_str) == float(sigma_val.number)
        except (ValueError, TypeError):
            return False

    logger.warning(
        "Tipo SigmaType no soportado en evaluación: %s; devuelve False.",
        type(sigma_val).__name__,
    )
    return False


def _evaluate_ast_node(node: Any, event: SecurityEvent) -> bool:
    """
    Evaluador recursivo del AST de condición pySigma.

    Recorre el árbol AND/OR/NOT y evalúa cada hoja
    ConditionFieldEqualsValueExpression contra los campos de SecurityEvent.

    El árbol es generado por pySigma al parsear la clave `condition:` de la
    regla Sigma. No se usa eval() ni ningún mecanismo de ejecución dinámica.
    """
    if isinstance(node, ConditionAND):
        return all(_evaluate_ast_node(arg, event) for arg in node.args)

    if isinstance(node, ConditionOR):
        return any(_evaluate_ast_node(arg, event) for arg in node.args)

    if isinstance(node, ConditionNOT):
        # ConditionNOT tiene siempre un único hijo
        return not _evaluate_ast_node(node.args[0], event)

    if isinstance(node, ConditionFieldEqualsValueExpression):
        sigma_field = node.field

        # Comprobación de campo no disponible (mapeado explícitamente a None)
        if sigma_field in _UNAVAILABLE_FIELDS:
            logger.debug(
                "Campo Sigma '%s' no disponible en SecurityEvent; condición falla.",
                sigma_field,
            )
            return False

        # Resolución del campo en SecurityEvent
        event_field = FIELD_MAP.get(sigma_field, sigma_field)
        actual = _get_event_field(event, event_field)
        return _match_sigma_value(node.value, actual)

    if isinstance(node, ConditionValueExpression):
        # Búsqueda por keyword (sin campo). No soportada en esta fase:
        # requiere buscar en todos los campos de texto, lo que produce
        # demasiados falsos positivos sin contexto de logsource.
        logger.warning(
            "ConditionValueExpression (keyword sin campo) no soportada; "
            "devuelve False. Usa un campo explícito en la regla."
        )
        return False

    logger.warning(
        "Nodo AST desconocido: %s; devuelve False.", type(node).__name__
    )
    return False


# ---------------------------------------------------------------------------
# SigmaBackedRule
# ---------------------------------------------------------------------------

@dataclass
class SigmaBackedRule(DetectionRule):
    """
    DetectionRule respaldada por un AST de pySigma en lugar de la lista de
    condiciones propia de CyberSentinel.

    Hereda de DetectionRule para ser completamente compatible con RulesEngine,
    Correlator y el resto del pipeline. La evaluación de condiciones se
    reemplaza por _evaluate_ast_node(); el resto (severidad, técnica MITRE,
    aggregation, RuleHit) funciona exactamente igual.

    Campos adicionales (prefijo _sigma_):
      _sigma_rule       : objeto SigmaRule original de pySigma (para auditoría)
      _sigma_ast        : AST ya parseado (ConditionAND/OR/NOT/…)
      _sigma_category   : categoría de logsource mapeada a SecurityEvent.category
      _sigma_source_file: ruta del archivo YAML de origen
    """

    # Campos de SigmaBackedRule (no en DetectionRule)
    # Se declaran con default_factory para cumplir el requisito de dataclass
    # (los campos con default van después de los sin default heredados).
    _sigma_rule:        SigmaRule | None = field(default=None, repr=False)
    _sigma_ast:         Any              = field(default=None, repr=False)
    _sigma_category:    str | None       = field(default=None, repr=False)
    _sigma_source_file: str              = field(default="", repr=False)

    @property
    def is_evaluable(self) -> bool:
        """True si el AST está disponible y puede evaluarse."""
        return self._sigma_ast is not None

    def matches(self, event: SecurityEvent) -> bool:
        """
        Evalúa la regla Sigma contra un SecurityEvent.

        1. Prefiltro de categoría (logsource → category): si la regla declara
           una categoría y el evento no coincide, se descarta sin evaluar el AST.
        2. Evaluación recursiva del AST de pySigma.
        """
        if self._sigma_ast is None:
            return False

        # Prefiltro: categoría logsource vs. evento
        if self._sigma_category and event.category != self._sigma_category:
            return False

        return _evaluate_ast_node(self._sigma_ast, event)


# ---------------------------------------------------------------------------
# Fábrica: SigmaRule → SigmaBackedRule
# ---------------------------------------------------------------------------

def sigma_rule_to_detection_rule(
    sigma_rule: SigmaRule,
    source_file: str = "",
) -> SigmaBackedRule | None:
    """
    Convierte un objeto SigmaRule de pySigma en un SigmaBackedRule.

    Devuelve None (con log de advertencia) si la regla:
    - No tiene condiciones en el bloque detection.
    - Usa características no soportadas (count, near, aggregation Sigma).
    - No tiene tags de ATT&CK identificables.

    NO lanza excepción: una regla problemática no debe interrumpir la carga
    del resto.
    """
    rule_id = str(sigma_rule.id) if sigma_rule.id else "unknown"
    title = sigma_rule.title or "unknown"

    # ── 1. Parsear el AST de la condición ───────────────────────────────────
    if not sigma_rule.detection.parsed_condition:
        logger.warning(
            "Regla '%s' (%s): sin condición parseable; omitida.", title, rule_id
        )
        return None

    if len(sigma_rule.detection.parsed_condition) > 1:
        # Múltiples condiciones producen múltiples queries en backends SIEM.
        # Para nuestro evaluador, tomamos solo la primera.
        logger.warning(
            "Regla '%s' (%s): múltiples condiciones Sigma; se evalúa solo la primera.",
            title, rule_id,
        )

    try:
        ast = sigma_rule.detection.parsed_condition[0].parse()
    except Exception as exc:
        logger.warning(
            "Regla '%s' (%s): no se pudo parsear la condición: %s; omitida.",
            title, rule_id, exc,
        )
        return None

    # ── 2. Extraer técnica y táctica ATT&CK ─────────────────────────────────
    technique = "unknown"
    tactic = "unknown"

    for tag in (sigma_rule.tags or []):
        tag_str = str(tag).lower()
        if tag_str.startswith("attack.t"):
            # "attack.t1059.001" → "T1059.001"
            raw = tag_str.replace("attack.", "").upper()
            technique = raw
        elif tag_str.startswith("attack.") and not tag_str.startswith("attack.t"):
            # "attack.execution" → "execution"
            tactic_raw = tag_str.replace("attack.", "").replace("_", "-")
            if tactic_raw not in ("unknown",):
                tactic = tactic_raw

    # Si no se encontró táctica en los tags, intentar derivarla de la técnica
    if tactic == "unknown" and technique != "unknown":
        try:
            from ..correlation import mitre
            # Usar el técnica padre si es sub-técnica (T1059.001 → T1059)
            parent = technique.split(".")[0]
            derived = mitre.tactic_of(parent)
            if derived and derived != "unknown":
                tactic = derived
        except Exception:
            pass  # Si falla la correlación, mantenemos "unknown"

    # ── 3. Nivel → Severity ──────────────────────────────────────────────────
    level_str = sigma_rule.level.name.lower() if sigma_rule.level else "medium"
    severity = _LEVEL_MAP.get(level_str, Severity.MEDIUM)

    # ── 4. Categoría logsource → category de SecurityEvent ──────────────────
    logsource_category: str | None = None
    if sigma_rule.logsource:
        ls_cat = getattr(sigma_rule.logsource, "category", None)
        if ls_cat:
            logsource_category = LOGSOURCE_CATEGORY_MAP.get(ls_cat.lower())

    # ── 5. Descripción y referencias ─────────────────────────────────────────
    description = sigma_rule.description or ""
    references = [str(r) for r in (sigma_rule.references or [])]

    # ── 6. False positives ───────────────────────────────────────────────────
    false_positives = list(sigma_rule.falsepositives or [])

    rule = SigmaBackedRule(
        id=rule_id,
        title=title,
        description=description,
        severity=severity,
        mitre_technique=technique,
        mitre_tactic=tactic,
        conditions=[],            # No se usan: la evaluación es por AST
        references=references,
        aggregation=None,         # Sólo reglas stateless en esta fase
        false_positives=false_positives,
        _sigma_rule=sigma_rule,
        _sigma_ast=ast,
        _sigma_category=logsource_category,
        _sigma_source_file=source_file,
    )
    return rule
