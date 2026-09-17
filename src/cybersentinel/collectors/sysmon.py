"""
Collector de Windows / Sysmon.

Acepta los dos formatos en que llega Sysmon en la práctica: JSON (reenviado por
Winlogbeat, NXLog o la propia API de Windows) y XML renderizado por el canal de
eventos.

Se extrae únicamente lo que el evento trae. Sysmon emite EventIDs distintos con
campos distintos —un EventID 1 (creación de proceso) no tiene `DestinationIp`,
y un EventID 3 (conexión de red) no tiene `CommandLine`—, así que rellenar los
huecos sería inventar telemetría.
"""
from __future__ import annotations

import json
import logging
import xml.etree.ElementTree as ET
from typing import Any

from ..schema import SecurityEvent
from .base import Collector, CollectorResult

logger = logging.getLogger(__name__)

#: EventID de Sysmon -> (categoría, acción). El resto se acepta con la categoría
#: genérica: una versión nueva de Sysmon no puede romper la ingestión.
SYSMON_EVENTS: dict[int, tuple[str, str]] = {
    1:  ("process", "process_create"),
    2:  ("file", "file_time_changed"),
    3:  ("network", "network_connection"),
    5:  ("process", "process_terminate"),
    6:  ("driver", "driver_load"),
    7:  ("process", "image_load"),
    8:  ("process", "create_remote_thread"),
    9:  ("file", "raw_access_read"),
    10: ("process", "process_access"),
    11: ("file", "file_create"),
    12: ("registry", "registry_create_delete"),
    13: ("registry", "registry_value_set"),
    14: ("registry", "registry_rename"),
    15: ("file", "file_create_stream_hash"),
    17: ("pipe", "pipe_created"),
    18: ("pipe", "pipe_connected"),
    22: ("dns", "dns_query"),
    23: ("file", "file_delete"),
    25: ("process", "process_tampering"),
}


class SysmonCollector(Collector):
    """Windows / Sysmon en JSON o XML."""

    source_type = "sysmon"

    def parse(self, raw: Any) -> CollectorResult:
        if isinstance(raw, (bytes, bytearray)):
            raw = self.decode_bytes(bytes(raw))

        if isinstance(raw, str):
            texto = raw.strip()
            if texto.startswith("<"):
                campos = self._from_xml(texto)
            else:
                campos = json.loads(texto)
        elif isinstance(raw, dict):
            campos = dict(raw)
        else:
            return CollectorResult(errors=[f"tipo no soportado: {type(raw).__name__}"])

        if not isinstance(campos, dict):
            return CollectorResult(errors="el evento no es un objeto")

        return self._to_event(campos)

    # --- XML --------------------------------------------------------------
    @staticmethod
    def _from_xml(texto: str) -> dict[str, Any]:
        """
        Aplana el XML del canal de eventos a un diccionario plano.

        El XML de Windows lleva espacio de nombres y separa `<System>` de
        `<EventData><Data Name="X">`. Se ignora el espacio de nombres por
        `tag.rpartition('}')` para no depender de su URI, que cambia entre
        versiones de Windows.
        """
        raiz = ET.fromstring(texto)
        campos: dict[str, Any] = {}

        for nodo in raiz.iter():
            etiqueta = nodo.tag.rpartition("}")[2]
            if etiqueta == "Data":
                nombre = nodo.attrib.get("Name")
                if nombre:
                    campos[nombre] = (nodo.text or "").strip()
            elif etiqueta == "TimeCreated":
                campos["UtcTime"] = nodo.attrib.get("SystemTime", "")
            elif etiqueta in ("EventID", "Computer", "Channel", "Provider"):
                if etiqueta == "Provider":
                    campos["Provider"] = nodo.attrib.get("Name", "")
                elif nodo.text:
                    campos[etiqueta] = nodo.text.strip()
        return campos

    # --- Conversión -------------------------------------------------------
    def _to_event(self, campos: dict[str, Any]) -> CollectorResult:
        anotaciones: list[str] = []

        event_id = self.to_int(self.first(campos, "EventID", "event_id", "eventid"))
        categoria, accion = SYSMON_EVENTS.get(
            event_id or -1, ("process", f"sysmon_event_{event_id}" if event_id else "sysmon_event")
        )

        ts, anot_ts = self.resolve_timestamp(
            self.first(campos, "UtcTime", "@timestamp", "timestamp", "TimeCreated")
        )
        anotaciones += anot_ts

        linea, anot_cmd = self.trim(self.first(campos, "CommandLine", "command_line"))
        anotaciones += anot_cmd

        # Los hashes de Sysmon vienen como "SHA256=AB..,MD5=CD..". Se separan
        # para que puedan cruzarse contra indicadores de inteligencia.
        hashes: dict[str, str] = {}
        crudo_hashes = self.first(campos, "Hashes", "hashes")
        if isinstance(crudo_hashes, str):
            for parte in crudo_hashes.split(","):
                if "=" in parte:
                    algo, _, valor = parte.partition("=")
                    hashes[algo.strip().lower()] = valor.strip()
        elif isinstance(crudo_hashes, dict):
            hashes = {k.lower(): v for k, v in crudo_hashes.items()}

        propiedades: dict[str, Any] = {}
        if hashes:
            propiedades["hashes"] = hashes
        for clave, destino in (
            ("ParentCommandLine", "parent_command_line"),
            ("OriginalFileName", "original_file_name"),
            ("CurrentDirectory", "current_directory"),
            ("IntegrityLevel", "integrity_level"),
            ("TargetFilename", "target_filename"),
            ("TargetObject", "target_object"),
            ("ProcessGuid", "process_guid"),
            ("LogonId", "logon_id"),
            ("QueryName", "query_name"),
        ):
            valor = self.first(campos, clave, destino)
            if valor is not None:
                recortado, anot = self.trim(valor)
                propiedades[destino] = recortado
                anotaciones += anot
        if event_id is not None:
            propiedades["sysmon_event_id"] = event_id

        evento = SecurityEvent(
            event_id=str(event_id) if event_id is not None else "sysmon",
            timestamp=ts,
            source=self.source_type,
            category=categoria,
            action=accion,
            host=self.first(campos, "Computer", "Hostname", "host", "hostname"),
            user=self.first(campos, "User", "SubjectUserName", "TargetUserName", "user"),
            process_name=self.first(campos, "Image", "process_name", "SourceImage"),
            command_line=linea,
            parent_process=self.first(campos, "ParentImage", "parent_process"),
            src_ip=self.first(campos, "SourceIp", "src_ip"),
            dst_ip=self.first(campos, "DestinationIp", "dst_ip"),
            src_port=self.to_int(self.first(campos, "SourcePort", "src_port")),
            dst_port=self.to_int(self.first(campos, "DestinationPort", "dst_port")),
            protocol=self.first(campos, "Protocol", "protocol"),
            outcome=self.first(campos, "outcome", default="unknown"),
            properties=propiedades,
            raw=campos,
            tags=list(anotaciones),
        )
        return CollectorResult(event=evento, annotations=anotaciones)
