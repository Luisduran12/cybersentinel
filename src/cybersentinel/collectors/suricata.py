"""
Collector de IDS: Suricata en formato EVE JSON.

EVE mezcla muchos tipos de registro en el mismo archivo (`alert`, `flow`, `dns`,
`http`, `tls`, `fileinfo`…). Aquí se procesan las **alertas** como detecciones y
los `flow` como telemetría de red; el resto se acepta con su tipo declarado, sin
forzarlo a una categoría que no le corresponde.

Una alerta de Suricata ya es una detección hecha por otro sistema. Se conserva
como tal —firma, categoría y severidad— en lugar de reinterpretarla: el valor de
integrarla es correlacionarla con el resto, no repetir su trabajo.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from ..schema import SecurityEvent
from .base import Collector, CollectorResult

logger = logging.getLogger(__name__)

#: Severidad de Suricata (1 = más grave) -> severidad normalizada del proyecto.
SEVERIDAD = {1: "critical", 2: "high", 3: "medium", 4: "low"}


class SuricataCollector(Collector):
    """Suricata EVE JSON."""

    source_type = "suricata"

    def parse(self, raw: Any) -> CollectorResult:
        if isinstance(raw, (bytes, bytearray)):
            raw = raw.decode("utf-8", errors="replace")
        if isinstance(raw, str):
            texto = raw.strip()
            if not texto:
                return CollectorResult(errors=["registro vacío"])
            campos = json.loads(texto)
        elif isinstance(raw, dict):
            campos = dict(raw)
        else:
            return CollectorResult(errors=[f"tipo no soportado: {type(raw).__name__}"])

        if not isinstance(campos, dict):
            return CollectorResult(errors=["el registro EVE no es un objeto"])

        anotaciones: list[str] = []
        ts, anot = self.resolve_timestamp(self.first(campos, "timestamp", "@timestamp"))
        anotaciones += anot

        tipo = str(self.first(campos, "event_type", default="desconocido")).lower()
        alerta = campos.get("alert") if isinstance(campos.get("alert"), dict) else {}

        if tipo == "alert" and alerta:
            categoria, accion = "ids", "ids_alert"
            firma, anot_f = self.trim(self.first(alerta, "signature", default=""))
            anotaciones += anot_f
            severidad = self.to_int(self.first(alerta, "severity"))
            propiedades = {
                "format": "suricata_eve", "event_type": tipo,
                "signature": firma,
                "signature_id": self.first(alerta, "signature_id"),
                "category": self.first(alerta, "category"),
                "severity": severidad,
                "severity_label": SEVERIDAD.get(severidad or 0, "unknown"),
                "action": self.first(alerta, "action"),
                # La detección la hizo Suricata, no CyberSentinel. Se declara
                # para que nadie atribuya al agente un acierto ajeno.
                "detected_by": "suricata",
            }
            # La firma va a `command_line` porque es el campo textual que las
            # reglas y las características léxicas del detector saben leer.
            texto_detec = firma
        elif tipo == "flow":
            categoria, accion, texto_detec = "network", "network_flow", None
            propiedades = {"format": "suricata_eve", "event_type": tipo,
                           "state": self.first(campos.get("flow", {}), "state")}
        else:
            categoria, accion, texto_detec = "network", f"suricata_{tipo}", None
            propiedades = {"format": "suricata_eve", "event_type": tipo}

        flujo = campos.get("flow", {}) if isinstance(campos.get("flow"), dict) else {}

        return CollectorResult(event=SecurityEvent(
            event_id=str(self.first(campos, "flow_id", "event_id", default="suricata")),
            timestamp=ts, source=self.source_type, category=categoria, action=accion,
            host=self.first(campos, "host", "hostname", "sensor_name"),
            src_ip=self.first(campos, "src_ip", "source_ip"),
            dst_ip=self.first(campos, "dest_ip", "dst_ip", "destination_ip"),
            src_port=self.to_int(self.first(campos, "src_port")),
            dst_port=self.to_int(self.first(campos, "dest_port", "dst_port")),
            protocol=self.first(campos, "proto", "protocol", "app_proto"),
            bytes_out=self.to_int(self.first(flujo, "bytes_toserver")),
            bytes_in=self.to_int(self.first(flujo, "bytes_toclient")),
            command_line=texto_detec,
            outcome=self.first(campos, "outcome", default="unknown"),
            properties={k: v for k, v in propiedades.items() if v is not None},
            raw=campos, tags=list(anotaciones),
        ), annotations=anotaciones)
