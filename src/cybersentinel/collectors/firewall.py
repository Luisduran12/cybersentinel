"""
Collector de cortafuegos, genérico por diseño.

No se acopla a ningún fabricante: acepta JSON y syslog con pares `clave=valor`,
que es el denominador común de lo que emiten Palo Alto, Fortinet, pfSense,
iptables y los cortafuegos de nube. Cada uno usa nombres distintos para lo
mismo, así que el mapeo se resuelve con listas de sinónimos en vez de con un
adaptador por marca.

Añadir un fabricante nuevo debería ser añadir sinónimos, no escribir un módulo.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any

from ..schema import SecurityEvent
from .base import Collector, CollectorResult

logger = logging.getLogger(__name__)

KV_RE = re.compile(r'(?P<k>[\w.\-]+)=(?P<v>"[^"]*"|\S+)')

#: Sinónimos por campo. El orden importa: el primero que aparezca es el que gana.
SINONIMOS: dict[str, tuple[str, ...]] = {
    "src_ip":   ("src_ip", "srcip", "src", "source_ip", "saddr", "source-address",
                 "id.orig_h", "sourceaddress", "client_ip"),
    "dst_ip":   ("dst_ip", "dstip", "dst", "destination_ip", "daddr",
                 "destination-address", "id.resp_h", "destinationaddress"),
    "src_port": ("src_port", "srcport", "spt", "sport", "source_port", "id.orig_p"),
    "dst_port": ("dst_port", "dstport", "dpt", "dport", "destination_port", "id.resp_p"),
    "protocol": ("protocol", "proto", "ip_proto", "service", "app"),
    "action":   ("action", "act", "disposition", "verdict", "rule_action"),
    "bytes_out":("bytes_out", "bytes_sent", "sentbyte", "out", "sbytes",
                 "orig_bytes", "tx_bytes"),
    "bytes_in": ("bytes_in", "bytes_received", "rcvdbyte", "in", "dbytes",
                 "resp_bytes", "rx_bytes"),
    "packets_out": ("packets_out", "pkts_out", "sentpkt", "spkts",
                    "orig_pkts", "tx_packets", "packets_sent"),
    "packets_in": ("packets_in", "pkts_in", "rcvdpkt", "dpkts",
                   "resp_pkts", "rx_packets", "packets_received"),
    "host":     ("host", "hostname", "devname", "device", "fw", "serial"),
    "timestamp":("timestamp", "@timestamp", "time", "date", "eventtime", "start"),
    "rule":     ("rule", "policyid", "rule_name", "ruleid", "policy"),
    "interface":("interface", "in_interface", "out_interface", "iface", "srcintf"),
}

#: Acciones que significan "bloqueado". Cada fabricante la escribe a su manera.
BLOQUEO = {"deny", "denied", "drop", "dropped", "block", "blocked", "reject",
           "rejected", "discard", "fail"}


class FirewallCollector(Collector):
    """Cortafuegos en JSON o syslog con pares clave=valor."""

    source_type = "firewall"

    def parse(self, raw: Any) -> CollectorResult:
        if isinstance(raw, (bytes, bytearray)):
            raw = self.decode_bytes(bytes(raw))

        if isinstance(raw, dict):
            campos = dict(raw)
        elif isinstance(raw, str):
            texto = raw.strip()
            if not texto:
                return CollectorResult(errors=["registro vacío"])
            campos = json.loads(texto) if texto.startswith("{") else self._kv(texto)
            if not campos:
                return CollectorResult(
                    errors=["no se reconoció ningún par clave=valor en la línea"]
                )
        else:
            return CollectorResult(errors=[f"tipo no soportado: {type(raw).__name__}"])

        return self._to_event(campos, raw)

    @staticmethod
    def _kv(linea: str) -> dict[str, Any]:
        """Extrae pares clave=valor de una línea syslog, respetando comillas."""
        return {
            m.group("k").lower(): m.group("v").strip('"')
            for m in KV_RE.finditer(linea)
        }

    def _busca(self, campos: dict[str, Any], destino: str) -> Any:
        """Busca un campo lógico entre todos sus sinónimos conocidos."""
        normalizados = {str(k).lower(): v for k, v in campos.items()}
        return self.first(normalizados, *SINONIMOS[destino])

    def _marca_temporal(self, campos: dict[str, Any]) -> Any:
        """
        Resuelve la marca de tiempo, uniendo fecha y hora cuando vienen aparte.

        Fortinet y otros emiten `date=2025-03-10 time=10:00:00` en campos
        separados. Tomar solo uno da una marca inservible: `time` sin fecha cae
        a la hora de ingesta y `date` sin hora pierde la precisión que la
        correlación necesita.
        """
        normalizados = {str(k).lower(): v for k, v in campos.items()}
        fecha, hora = normalizados.get("date"), normalizados.get("time")
        if fecha and hora and "-" in str(fecha):
            return f"{fecha} {hora}"
        return self.first(normalizados, *SINONIMOS["timestamp"])

    def _to_event(self, campos: dict[str, Any], original: Any) -> CollectorResult:
        anotaciones: list[str] = []
        ts, anot = self.resolve_timestamp(self._marca_temporal(campos))
        anotaciones += anot

        accion_cruda = self._busca(campos, "action")
        bloqueado = str(accion_cruda or "").lower() in BLOQUEO
        # `outcome` se normaliza a failure/success para que las reglas y las
        # características del detector no tengan que conocer cada vocabulario.
        outcome = "failure" if bloqueado else ("success" if accion_cruda else "unknown")

        propiedades = {"format": "firewall",
                       "raw_action": accion_cruda,
                       "rule": self._busca(campos, "rule"),
                       "interface": self._busca(campos, "interface"),
                       "packets_out": self.to_int(self._busca(campos, "packets_out")),
                       "packets_in": self.to_int(self._busca(campos, "packets_in"))}

        return CollectorResult(event=SecurityEvent(
            event_id=str(self.first(campos, "event_id", "sessionid", "id", default="fw")),
            timestamp=ts, source=self.source_type, category="network",
            action=str(accion_cruda).lower() if accion_cruda else "connection",
            host=self._busca(campos, "host"),
            src_ip=self._busca(campos, "src_ip"),
            dst_ip=self._busca(campos, "dst_ip"),
            src_port=self.to_int(self._busca(campos, "src_port")),
            dst_port=self.to_int(self._busca(campos, "dst_port")),
            protocol=self._busca(campos, "protocol"),
            bytes_out=self.to_int(self._busca(campos, "bytes_out")),
            bytes_in=self.to_int(self._busca(campos, "bytes_in")),
            outcome=outcome,
            properties={k: v for k, v in propiedades.items() if v is not None},
            raw=campos if isinstance(original, (dict, str)) else {},
            tags=list(anotaciones),
        ), annotations=anotaciones)
