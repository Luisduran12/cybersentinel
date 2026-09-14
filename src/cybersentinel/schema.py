"""
Esquema común de eventos de seguridad (inspirado en ECS de Elastic y OCSF).

Toda telemetría heterogénea (Sysmon, auth, firewall, web, flows de red) se
normaliza a esta estructura única. Trabajar sobre un esquema común es lo que
permite que el resto del pipeline (detección, correlación, predicción) no dependa
del formato original de cada fuente.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    """Nivel de severidad normalizado de un evento o hallazgo."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def score(self) -> int:
        return {"info": 0, "low": 25, "medium": 50, "high": 75, "critical": 100}[self.value]


@dataclass
class SecurityEvent:
    """
    Evento de seguridad normalizado.

    Campos alineados conceptualmente con ECS. No todos los eventos usan todos los
    campos; los que no aplican quedan en None.
    """
    # Identidad y tiempo
    event_id: str
    timestamp: datetime
    source: str                      # fuente de la telemetría: sysmon, auth, firewall, web, netflow
    category: str                    # process, authentication, network, file, dns, web, etc.
    action: str                      # descripción corta de la acción (p.ej. "process_create")

    # Host / usuario
    host: Optional[str] = None
    user: Optional[str] = None

    # Red
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    bytes_out: Optional[int] = None
    bytes_in: Optional[int] = None

    # Proceso
    process_name: Optional[str] = None
    command_line: Optional[str] = None
    parent_process: Optional[str] = None

    # Resultado
    outcome: Optional[str] = None     # success | failure | unknown

    # Metadatos libres + campos crudos originales
    raw: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)

    def fingerprint(self) -> str:
        """Huella estable del evento para deduplicación y auditoría."""
        basis = f"{self.timestamp.isoformat()}|{self.source}|{self.action}|{self.host}|{self.user}|{self.command_line}"
        return hashlib.sha256(basis.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str, ensure_ascii=False)

    @staticmethod
    def parse_timestamp(value: Any) -> datetime:
        """Convierte múltiples formatos de tiempo a datetime timezone-aware (UTC)."""
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value, tz=timezone.utc)
        if isinstance(value, str):
            for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
                        "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
                try:
                    dt = datetime.strptime(value.replace("Z", "+0000"), fmt)
                    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
        return datetime.now(tz=timezone.utc)
