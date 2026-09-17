"""
Collector de alertas Wazuh (Fase 4-E, tarea E2: Wazuh → CyberSentinel).

Wazuh es el SIEM open-source más usado en PyMEs/Latam, y sus agentes ya
producen exactamente el tipo de telemetría (Sysmon, auditd, syslog) que los
otros cuatro collectors normalizan — la diferencia es que aquí llega
envuelta en el JSON de alerta propio de Wazuh (`rule`, `agent`, `data`,
`full_log`), no en el formato crudo original. Se extrae lo que Wazuh ya
correlacionó (`rule.id`, `rule.level`) como contexto adicional, sin
descartar la telemetría subyacente.

Mismo contrato que los demás: nunca lanza excepción, campo ausente → None,
timestamp inválido → hora de ingesta con etiqueta, payload excesivo se
rechaza.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from ..schema import SecurityEvent
from .base import Collector, CollectorResult

logger = logging.getLogger(__name__)

#: Nivel de severidad de Wazuh (0-16, mayor = más grave) -> severidad propia.
#: Escala documentada en la propia guía de Wazuh (rule levels).
def _severidad_wazuh(level: int | None) -> str:
    if level is None:
        return "unknown"
    if level >= 12:
        return "critical"
    if level >= 8:
        return "high"
    if level >= 4:
        return "medium"
    return "low"


#: Palabras clave del `groups`/`description` de la regla que indican
#: autenticación. Wazuh no tiene un campo `category` como SecurityEvent.
_PALABRAS_AUTH = ("authentication", "auth", "login", "sshd", "pam")


class WazuhCollector(Collector):
    """Alertas Wazuh (JSON de `alerts.json` o del webhook de integración)."""

    source_type = "wazuh"

    def parse(self, raw: Any) -> CollectorResult:
        if isinstance(raw, (bytes, bytearray)):
            raw = self.decode_bytes(bytes(raw))

        if isinstance(raw, str):
            texto = raw.strip()
            if not texto:
                return CollectorResult(errors=["alerta vacía"])
            try:
                campos = json.loads(texto)
            except json.JSONDecodeError as exc:
                return CollectorResult(errors=[f"JSON inválido: {exc}"])
        elif isinstance(raw, dict):
            campos = dict(raw)
        else:
            return CollectorResult(errors=[f"tipo no soportado: {type(raw).__name__}"])

        if not isinstance(campos, dict):
            return CollectorResult(errors=["la alerta Wazuh no es un objeto"])

        return self._to_event(campos)

    def _to_event(self, campos: dict[str, Any]) -> CollectorResult:
        anotaciones: list[str] = []
        ts, anot = self.resolve_timestamp(
            self.first(campos, "timestamp", "@timestamp")
        )
        anotaciones += anot

        regla = campos.get("rule") if isinstance(campos.get("rule"), dict) else {}
        agente = campos.get("agent") if isinstance(campos.get("agent"), dict) else {}
        datos = campos.get("data") if isinstance(campos.get("data"), dict) else {}

        descripcion = str(self.first(regla, "description", default=""))
        nivel = self.to_int(self.first(regla, "level"))
        groups = regla.get("groups") if isinstance(regla.get("groups"), list) else []

        es_auth = any(p in descripcion.lower() for p in _PALABRAS_AUTH) or any(
            p in " ".join(str(g) for g in groups).lower() for p in _PALABRAS_AUTH
        )
        categoria = "authentication" if es_auth else "network" if datos.get("srcip") else "process"

        full_log, anot_log = self.trim(self.first(campos, "full_log", default=""))
        anotaciones += anot_log

        propiedades = {k: v for k, v in {
            "wazuh_rule_id": self.first(regla, "id"),
            "wazuh_rule_level": nivel,
            "wazuh_rule_severity": _severidad_wazuh(nivel),
            "wazuh_rule_groups": groups or None,
            "wazuh_agent_id": self.first(agente, "id"),
            "full_log": full_log or None,
            "location": self.first(campos, "location"),
        }.items() if v is not None}

        evento = SecurityEvent(
            event_id=str(self.first(campos, "id", default="")) or (
                f"wazuh-{self.first(regla, 'id', default='0')}-"
                f"{self.first(agente, 'id', default='0')}-{ts.timestamp():.0f}"
            ),
            timestamp=ts, source=self.source_type, category=categoria,
            action=descripcion[:120] or "wazuh_alert",
            host=self.first(agente, "name"),
            user=self.first(datos, "srcuser", "dstuser", "user"),
            src_ip=self.first(datos, "srcip"),
            dst_ip=self.first(datos, "dstip"),
            src_port=self.to_int(self.first(datos, "srcport")),
            dst_port=self.to_int(self.first(datos, "dstport")),
            outcome=(
                "failure" if any(
                    p in descripcion.lower() or p in " ".join(str(g) for g in groups).lower()
                    for p in ("fail", "denied", "invalid", "brute force")
                )
                else "success" if (
                    "accepted" in descripcion.lower()
                    or "success" in " ".join(str(g) for g in groups).lower()
                )
                else "unknown"
            ),
            properties=propiedades,
            raw=campos, tags=list(anotaciones),
        )
        return CollectorResult(event=evento, annotations=anotaciones)
