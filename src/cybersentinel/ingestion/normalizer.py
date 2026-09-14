"""
Ingesta y normalización de telemetría.

Convierte registros crudos de diferentes fuentes (JSON de Sysmon, logs de
autenticación, firewall, web, netflow) al esquema común SecurityEvent.

Diseño: cada fuente tiene un parser dedicado. Añadir una fuente nueva = añadir
un parser, sin tocar el resto del pipeline.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

from ..schema import SecurityEvent


def _s(record: dict[str, Any], *keys: str, default: Any = None) -> Any:
    """Devuelve el primer valor no nulo entre varias claves candidatas."""
    for k in keys:
        if k in record and record[k] not in (None, ""):
            return record[k]
    return default


def parse_sysmon(record: dict[str, Any]) -> SecurityEvent:
    """Normaliza un evento estilo Sysmon (creación de proceso, red, etc.)."""
    return SecurityEvent(
        event_id=str(_s(record, "event_id", "EventID", default="")) or "sysmon",
        timestamp=SecurityEvent.parse_timestamp(_s(record, "timestamp", "UtcTime", "@timestamp")),
        source="sysmon",
        category=_s(record, "category", default="process"),
        action=_s(record, "action", default="process_create"),
        host=_s(record, "host", "Computer", "hostname"),
        user=_s(record, "user", "User", "SubjectUserName"),
        process_name=_s(record, "process_name", "Image", "process"),
        command_line=_s(record, "command_line", "CommandLine", "cmdline"),
        parent_process=_s(record, "parent_process", "ParentImage"),
        dst_ip=_s(record, "dst_ip", "DestinationIp"),
        dst_port=_maybe_int(_s(record, "dst_port", "DestinationPort")),
        outcome=_s(record, "outcome", default="unknown"),
        raw=record,
    )


def parse_auth(record: dict[str, Any]) -> SecurityEvent:
    """Normaliza un log de autenticación (login exitoso/fallido)."""
    return SecurityEvent(
        event_id=str(_s(record, "event_id", default="auth")),
        timestamp=SecurityEvent.parse_timestamp(_s(record, "timestamp", "@timestamp", "time")),
        source="auth",
        category="authentication",
        action=_s(record, "action", default="user_login"),
        host=_s(record, "host", "hostname", "target"),
        user=_s(record, "user", "username", "account"),
        src_ip=_s(record, "src_ip", "source_ip", "ip"),
        outcome=_s(record, "outcome", "result", default="unknown"),
        raw=record,
    )


def parse_firewall(record: dict[str, Any]) -> SecurityEvent:
    """Normaliza un log de firewall / conexión de red."""
    return SecurityEvent(
        event_id=str(_s(record, "event_id", default="fw")),
        timestamp=SecurityEvent.parse_timestamp(_s(record, "timestamp", "@timestamp")),
        source="firewall",
        category="network",
        action=_s(record, "action", default="connection"),
        host=_s(record, "host", "hostname"),
        src_ip=_s(record, "src_ip", "source_ip"),
        dst_ip=_s(record, "dst_ip", "destination_ip"),
        src_port=_maybe_int(_s(record, "src_port")),
        dst_port=_maybe_int(_s(record, "dst_port", "port")),
        protocol=_s(record, "protocol", "proto"),
        bytes_out=_maybe_int(_s(record, "bytes_out", "bytes_sent")),
        bytes_in=_maybe_int(_s(record, "bytes_in", "bytes_received")),
        outcome=_s(record, "outcome", "action", default="unknown"),
        raw=record,
    )


def parse_web(record: dict[str, Any]) -> SecurityEvent:
    """Normaliza un log de servidor web (acceso HTTP)."""
    return SecurityEvent(
        event_id=str(_s(record, "event_id", default="web")),
        timestamp=SecurityEvent.parse_timestamp(_s(record, "timestamp", "@timestamp")),
        source="web",
        category="web",
        action=_s(record, "method", "action", default="http_request"),
        host=_s(record, "host", "server"),
        src_ip=_s(record, "src_ip", "client_ip", "remote_addr"),
        command_line=_s(record, "url", "request", "uri"),   # reutilizamos command_line para la URL/payload
        outcome=str(_s(record, "status", "status_code", default="unknown")),
        raw=record,
    )


def _maybe_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (ValueError, TypeError):
        return None


# Registro de parsers por nombre de fuente
PARSERS: dict[str, Callable[[dict[str, Any]], SecurityEvent]] = {
    "sysmon": parse_sysmon,
    "auth": parse_auth,
    "firewall": parse_firewall,
    "web": parse_web,
}


class Normalizer:
    """Convierte registros crudos en SecurityEvent usando el parser adecuado."""

    def __init__(self, default_source: str = "sysmon") -> None:
        self.default_source = default_source

    def normalize_record(self, record: dict[str, Any]) -> SecurityEvent:
        source = str(record.get("source", self.default_source)).lower()
        parser = PARSERS.get(source, PARSERS[self.default_source])
        return parser(record)

    def normalize(self, records: Iterable[dict[str, Any]]) -> list[SecurityEvent]:
        return [self.normalize_record(r) for r in records]

    def from_jsonl(self, path: str | Path) -> list[SecurityEvent]:
        """Lee un archivo JSON Lines (un objeto JSON por línea) y lo normaliza."""
        events: list[SecurityEvent] = []
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(self.normalize_record(json.loads(line)))
                except json.JSONDecodeError:
                    continue  # línea corrupta: se ignora (en producción iría a una cola de errores)
        return sorted(events, key=lambda e: e.timestamp)

    def stream_jsonl(self, path: str | Path) -> Iterator[SecurityEvent]:
        """Versión streaming para archivos grandes (no carga todo en memoria)."""
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        yield self.normalize_record(json.loads(line))
                    except json.JSONDecodeError:
                        continue
