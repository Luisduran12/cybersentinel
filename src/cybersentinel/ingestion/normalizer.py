"""
Ingesta y normalización de telemetría.

Convierte registros crudos de diferentes fuentes (Sysmon, autenticación,
firewall, web, netflow) al esquema común SecurityEvent.

Diseño: cada fuente tiene un parser dedicado. Añadir una fuente nueva = añadir
un parser, sin tocar el resto del pipeline.

Las 5 fuentes que tienen un `Collector` real en `collectors/` (linux, suricata,
wazuh, sysmon, firewall) delegan en él vía `_parse_via_collector` en vez de
reimplementar el mapeo de campos aquí — auth/netflow/web no tienen collector
propio y se normalizan directamente en este módulo.

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
    """
    Delegado a `SysmonCollector` (JSON o XML del canal de eventos).

    Antes normalizaba a mano con un mapeo de campos mucho más pobre que el
    collector (sin categoría/acción por EventID, sin src_ip/src_port/
    protocol, sin parseo de hashes ni soporte XML): el mismo patrón de
    collector huérfano ya corregido para linux/suricata/wazuh.
    """
    from ..collectors.sysmon import SysmonCollector
    return _parse_via_collector(SysmonCollector, record)


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
    """
    Delegado a `FirewallCollector` (JSON o syslog clave=valor, multi-fabricante).

    Antes normalizaba a mano con 1-2 alias por campo y sin los sinónimos de
    fabricante (Palo Alto/Fortinet/pfSense/Zeek), sin normalizar outcome a
    success/failure y sin soporte de líneas syslog crudas: el mismo patrón de
    collector huérfano ya corregido para linux/suricata/wazuh.
    """
    from ..collectors.firewall import FirewallCollector
    return _parse_via_collector(FirewallCollector, record)


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


def _parse_via_collector(collector_cls, record: dict[str, Any]) -> SecurityEvent:
    """
    Delega en un `Collector` real (`collectors/`) en vez de duplicar su
    lógica de mapeo de campos aquí.

    Hallazgo de la auditoría de producción: `linux`, `suricata` y `wazuh`
    nunca tuvieron parser propio en este módulo — un evento con
    `source: "linux"` caía en silencio al parser por defecto (con el aviso de
    "fuente sin parser" y la etiqueta `fuente_desconocida`), así que la API
    HTTP real nunca pudo detectar telemetría Linux, Suricata o Wazuh aunque
    sus collectors ya existían, estaban probados y funcionaban por su cuenta.

    `Collector.collect()` nunca lanza excepción; aquí sí se relanza como
    `ValueError` cuando falla, porque el contrato de `PARSERS` es devolver un
    `SecurityEvent` o fallar — `IngestService.ingest()` ya captura esa
    excepción y la cuenta como rechazo, igual que un JSON malformado.

    Si el registro trae `event_id` explícito, prevalece sobre el identificador
    nativo que resuelva el collector (p.ej. el `EventID` numérico de Sysmon).
    `incidents.py` usa `SecurityEvent.event_id` como clave del incidente, y
    `parse_auth`/`parse_web`/`parse_netflow` ya honran `event_id` del cliente
    para idempotencia; los collectors priorizan su identificador nativo (útil
    para telemetría cruda real, que nunca trae `event_id`) por encima de él,
    lo que sin este ajuste colapsaría en el mismo incidente cualquier par de
    eventos con el mismo id nativo (p.ej. todos los `EventID=1` de Sysmon).
    """
    resultado = collector_cls().collect(record)
    if not resultado.ok:
        raise ValueError("; ".join(resultado.errors) or "el collector no produjo un evento")
    event = resultado.event
    if isinstance(record, dict) and record.get("event_id"):
        event.event_id = str(record["event_id"])
    return event


def parse_linux(record: dict[str, Any]) -> SecurityEvent:
    """
    Delegado a `LinuxCollector` (journald/syslog/auditd).

    LIMITACIÓN: el contrato JSON de la API (`RawEvent`) exige un objeto, no
    una cadena — así que solo el modo journald (JSON) de `LinuxCollector` es
    alcanzable por HTTP. Una línea syslog o auditd cruda no tiene forma de
    viajar como valor de un campo JSON sin que el cliente la envuelva
    explícitamente; por ingesta HTTP real, hoy, solo journald funciona.
    """
    from ..collectors.linux import LinuxCollector
    return _parse_via_collector(LinuxCollector, record)


def parse_suricata(record: dict[str, Any]) -> SecurityEvent:
    """Delegado a `SuricataCollector` (EVE JSON: alert/flow)."""
    from ..collectors.suricata import SuricataCollector
    return _parse_via_collector(SuricataCollector, record)


def parse_wazuh(record: dict[str, Any]) -> SecurityEvent:
    """Delegado a `WazuhCollector` (alertas Wazuh: rule/agent/data)."""
    from ..collectors.wazuh import WazuhCollector
    return _parse_via_collector(WazuhCollector, record)


# Registro de parsers por nombre de fuente
PARSERS: dict[str, Callable[[dict[str, Any]], SecurityEvent]] = {
    "sysmon": parse_sysmon,
    "auth": parse_auth,
    "linux": parse_linux,
    "suricata": parse_suricata,
    "wazuh": parse_wazuh,
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
