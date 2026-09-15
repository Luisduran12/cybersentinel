"""
Ingesta y normalización de telemetría.

Convierte registros crudos de diferentes fuentes (Sysmon, autenticación,
firewall, web, netflow) al esquema común SecurityEvent.

Diseño: cada fuente tiene un parser dedicado. Añadir una fuente nueva = añadir
un parser, sin tocar el resto del pipeline.

Principio de esta capa: **nada se descarta ni se falsea en silencio**. Un registro
con un timestamp ilegible, de una fuente desconocida o con una línea corrupta se
marca con una etiqueta y se registra en el log. En un SOC real, los datos que se
pierden sin dejar rastro son los que acaban explicando por qué no se vio un
ataque.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

from ..schema import SecurityEvent

logger = logging.getLogger(__name__)

#: Etiquetas que el normalizador puede añadir a un evento.
TAG_INVALID_TIMESTAMP = "timestamp_invalido"
TAG_UNKNOWN_SOURCE = "fuente_desconocida"


def _s(record: dict[str, Any], *keys: str, default: Any = None) -> Any:
    """Devuelve el primer valor no nulo entre varias claves candidatas."""
    for k in keys:
        if k in record and record[k] not in (None, ""):
            return record[k]
    return default


def _maybe_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (ValueError, TypeError):
        return None


def _timestamp(record: dict[str, Any], *keys: str) -> tuple[datetime, list[str]]:
    """
    Resuelve la marca de tiempo del registro.

    Si no se reconoce el formato se usa la hora actual —hay que poner algo para
    poder correlacionar— pero el evento queda etiquetado, de modo que el analista
    vea que esa hora no es del dato original.
    """
    raw = _s(record, *keys)
    parsed = SecurityEvent.try_parse_timestamp(raw)
    if parsed is not None:
        return parsed, []
    logger.warning("Timestamp no reconocido (%r); se marca el evento.", raw)
    return datetime.now(tz=timezone.utc), [TAG_INVALID_TIMESTAMP]


def parse_sysmon(record: dict[str, Any]) -> SecurityEvent:
    """Normaliza un evento estilo Sysmon (creación de proceso, red, etc.)."""
    ts, tags = _timestamp(record, "timestamp", "UtcTime", "@timestamp")
    
    properties = {}
    for key, source_keys in {
        "parent_command_line": ("ParentCommandLine",),
        "hashes": ("Hashes",),
        "original_file_name": ("OriginalFileName",),
        "current_directory": ("CurrentDirectory",),
        "integrity_level": ("IntegrityLevel",),
    }.items():
        val = _s(record, *source_keys)
        if val is not None:
            properties[key] = val

    return SecurityEvent(
        event_id=str(_s(record, "event_id", "EventID", default="")) or "sysmon",
        timestamp=ts,
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
        properties=properties,
        raw=record,
        tags=tags,
    )


def parse_auth(record: dict[str, Any]) -> SecurityEvent:
    """Normaliza un log de autenticación (login exitoso/fallido)."""
    ts, tags = _timestamp(record, "timestamp", "@timestamp", "time")
    return SecurityEvent(
        event_id=str(_s(record, "event_id", default="auth")),
        timestamp=ts,
        source="auth",
        category="authentication",
        action=_s(record, "action", default="user_login"),
        host=_s(record, "host", "hostname", "target"),
        user=_s(record, "user", "username", "account"),
        src_ip=_s(record, "src_ip", "source_ip", "ip"),
        outcome=_s(record, "outcome", "result", default="unknown"),
        raw=record,
        tags=tags,
    )


def parse_firewall(record: dict[str, Any]) -> SecurityEvent:
    """Normaliza un log de firewall / conexión de red."""
    ts, tags = _timestamp(record, "timestamp", "@timestamp")
    return SecurityEvent(
        event_id=str(_s(record, "event_id", default="fw")),
        timestamp=ts,
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
        tags=tags,
    )


def parse_netflow(record: dict[str, Any]) -> SecurityEvent:
    """
    Normaliza un registro de flujo de red (NetFlow/IPFIX, Zeek conn.log).

    Es la forma que tienen los datasets de flujos etiquetados (UNSW-NB15,
    CICIDS2017), así que este parser es la puerta de entrada de la Fase 4. Los
    nombres de campo alternativos cubren las convenciones más habituales de esos
    conjuntos (`srcip`/`sport`/`sbytes` en UNSW-NB15, `id.orig_h` en Zeek).
    """
    ts, tags = _timestamp(record, "timestamp", "@timestamp", "ts", "stime", "Stime")
    return SecurityEvent(
        event_id=str(_s(record, "event_id", "uid", default="flow")),
        timestamp=ts,
        source="netflow",
        category="network",
        action=_s(record, "action", default="network_flow"),
        host=_s(record, "host", "hostname", "sensor"),
        src_ip=_s(record, "src_ip", "srcip", "source_ip", "id.orig_h"),
        dst_ip=_s(record, "dst_ip", "dstip", "destination_ip", "id.resp_h"),
        src_port=_maybe_int(_s(record, "src_port", "sport", "id.orig_p")),
        dst_port=_maybe_int(_s(record, "dst_port", "dsport", "dport", "id.resp_p")),
        protocol=_s(record, "protocol", "proto", "service"),
        bytes_out=_maybe_int(_s(record, "bytes_out", "sbytes", "orig_bytes", "bytes_sent")),
        bytes_in=_maybe_int(_s(record, "bytes_in", "dbytes", "resp_bytes", "bytes_received")),
        outcome=_s(record, "outcome", "state", "conn_state", default="unknown"),
        raw=record,
        tags=tags,
    )


def parse_web(record: dict[str, Any]) -> SecurityEvent:
    """Normaliza un log de servidor web (acceso HTTP)."""
    ts, tags = _timestamp(record, "timestamp", "@timestamp")
    return SecurityEvent(
        event_id=str(_s(record, "event_id", default="web")),
        timestamp=ts,
        source="web",
        category="web",
        action=_s(record, "method", "action", default="http_request"),
        host=_s(record, "host", "server"),
        src_ip=_s(record, "src_ip", "client_ip", "remote_addr"),
        # Se reutiliza command_line para la URL/payload. Las reglas de proceso
        # exigen category=process justamente para no evaluar este campo.
        command_line=_s(record, "url", "request", "uri"),
        outcome=str(_s(record, "status", "status_code", default="unknown")),
        raw=record,
        tags=tags,
    )


# Registro de parsers por nombre de fuente
PARSERS: dict[str, Callable[[dict[str, Any]], SecurityEvent]] = {
    "sysmon": parse_sysmon,
    "auth": parse_auth,
    "firewall": parse_firewall,
    "netflow": parse_netflow,
    "web": parse_web,
}


class Normalizer:
    """Convierte registros crudos en SecurityEvent usando el parser adecuado."""

    def __init__(self, default_source: str = "sysmon") -> None:
        self.default_source = default_source
        #: Fuentes desconocidas ya avisadas, para no inundar el log.
        self._warned_sources: set[str] = set()

    def normalize_record(self, record: dict[str, Any]) -> SecurityEvent:
        """
        Normaliza un registro con el parser de su fuente.

        Una fuente sin parser cae al parser por defecto —es preferible a
        descartar el evento— pero se avisa y el evento queda etiquetado: de lo
        contrario un `netflow` mal escrito se procesaría como Sysmon y perdería
        los bytes transferidos sin que nadie se entere.
        """
        source = str(record.get("source", self.default_source)).lower()
        parser = PARSERS.get(source)
        if parser is None:
            if source not in self._warned_sources:
                self._warned_sources.add(source)
                logger.warning(
                    "Fuente '%s' sin parser; se usa '%s'. Fuentes conocidas: %s.",
                    source, self.default_source, ", ".join(sorted(PARSERS)),
                )
            event = PARSERS[self.default_source](record)
            event.tags.append(TAG_UNKNOWN_SOURCE)
            return event
        return parser(record)

    def normalize(self, records: Iterable[dict[str, Any]]) -> list[SecurityEvent]:
        return [self.normalize_record(r) for r in records]

    def stream_jsonl(self, path: str | Path) -> Iterator[SecurityEvent]:
        """
        Lee un archivo JSON Lines evento a evento, sin cargarlo entero en memoria.

        Las líneas corruptas se saltan con aviso; en producción irían a una cola
        de errores para revisarlas, no al olvido.
        """
        with open(path, "r", encoding="utf-8") as fh:
            for number, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    logger.warning("Línea %d de %s ilegible, se omite: %s", number, path, exc)
                    continue
                yield self.normalize_record(record)

    def from_jsonl(self, path: str | Path) -> list[SecurityEvent]:
        """Lee un archivo JSON Lines completo y lo devuelve ordenado por tiempo."""
        return sorted(self.stream_jsonl(path), key=lambda e: e.timestamp)
