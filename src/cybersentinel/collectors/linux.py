"""
Collector de Linux: journald (JSON), syslog y auditd.

Los tres formatos conviven en cualquier máquina Linux y describen lo mismo desde
ángulos distintos, así que un único collector los cubre y decide por la forma
del registro.

La categoría (`authentication`, `process`, `file`, `network`) se infiere del
contenido, porque ni syslog ni journald la traen explícita y las reglas de
detección la necesitan para no evaluar campos que no corresponden.
"""
from __future__ import annotations

import json
import logging
import re
import shlex
from typing import Any

from ..schema import SecurityEvent
from .base import Collector, CollectorResult

logger = logging.getLogger(__name__)

#: syslog RFC3164: <prioridad>MMM DD HH:MM:SS host proceso[pid]: mensaje
SYSLOG_RE = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?"
    r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\S+T\S+)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<msg>.*)$"
)

#: auditd: type=X msg=audit(epoch:serial): clave=valor ...
AUDITD_RE = re.compile(r"^type=(?P<type>\S+)\s+msg=audit\((?P<ts>[\d.]+):(?P<serial>\d+)\):\s*(?P<body>.*)$")

#: Señales de autenticación en el texto del mensaje.
AUTH_FAIL = ("failed password", "authentication failure", "invalid user",
             "failed publickey", "auth fail")
AUTH_OK = ("accepted password", "accepted publickey", "session opened", "new session")

IP_RE = re.compile(r"\bfrom\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})")
USER_RE = re.compile(r"\bfor\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\b")


class LinuxCollector(Collector):
    """journald JSON, syslog y auditd."""

    source_type = "linux"

    def parse(self, raw: Any) -> CollectorResult:
        if isinstance(raw, (bytes, bytearray)):
            raw = raw.decode("utf-8", errors="replace")

        if isinstance(raw, dict):
            return self._journald(raw)

        if not isinstance(raw, str):
            return CollectorResult(errors=[f"tipo no soportado: {type(raw).__name__}"])

        texto = raw.strip()
        if not texto:
            return CollectorResult(errors=["registro vacío"])

        if texto.startswith("{"):
            return self._journald(json.loads(texto))
        if texto.startswith("type=") and "msg=audit(" in texto:
            return self._auditd(texto)
        return self._syslog(texto)

    # --- journald ---------------------------------------------------------
    def _journald(self, campos: dict[str, Any]) -> CollectorResult:
        anotaciones: list[str] = []

        # __REALTIME_TIMESTAMP viene en MICROsegundos desde epoch.
        crudo_ts = self.first(campos, "__REALTIME_TIMESTAMP", "@timestamp", "timestamp")
        if crudo_ts is not None and str(crudo_ts).isdigit() and len(str(crudo_ts)) >= 16:
            crudo_ts = int(crudo_ts) / 1_000_000
        ts, anot = self.resolve_timestamp(crudo_ts)
        anotaciones += anot

        mensaje, anot_msg = self.trim(self.first(campos, "MESSAGE", "message", default=""))
        anotaciones += anot_msg

        comando = self.first(campos, "_CMDLINE", "cmdline")
        proceso = self.first(campos, "_COMM", "SYSLOG_IDENTIFIER", "comm")
        categoria, accion, outcome = self._clasificar(str(mensaje), proceso)

        return CollectorResult(event=SecurityEvent(
            event_id=str(self.first(campos, "_PID", "MESSAGE_ID", default="journald")),
            timestamp=ts, source=self.source_type, category=categoria, action=accion,
            host=self.first(campos, "_HOSTNAME", "hostname", "host"),
            user=self._usuario(campos, str(mensaje)),
            process_name=proceso,
            command_line=comando or mensaje,
            parent_process=self.first(campos, "_PPID"),
            src_ip=self._ip(str(mensaje)),
            outcome=outcome,
            properties={"format": "journald", "unit": self.first(campos, "_SYSTEMD_UNIT"),
                        "priority": self.first(campos, "PRIORITY")},
            raw=campos, tags=list(anotaciones),
        ), annotations=anotaciones)

    # --- syslog -----------------------------------------------------------
    def _syslog(self, linea: str) -> CollectorResult:
        coincide = SYSLOG_RE.match(linea)
        if not coincide:
            return CollectorResult(errors=["la línea no tiene formato syslog reconocible"])

        g = coincide.groupdict()
        anotaciones: list[str] = []
        ts, anot = self.resolve_timestamp(self._completa_anio(g["ts"]))
        anotaciones += anot

        mensaje, anot_msg = self.trim(g["msg"])
        anotaciones += anot_msg
        categoria, accion, outcome = self._clasificar(mensaje, g["proc"])

        return CollectorResult(event=SecurityEvent(
            event_id=g.get("pid") or "syslog", timestamp=ts, source=self.source_type,
            category=categoria, action=accion, host=g["host"],
            user=self._usuario({}, mensaje), process_name=g["proc"],
            command_line=mensaje, src_ip=self._ip(mensaje), outcome=outcome,
            properties={"format": "syslog", "priority": g.get("pri"), "pid": g.get("pid")},
            raw={"raw_line": linea, **g}, tags=list(anotaciones),
        ), annotations=anotaciones)

    @staticmethod
    def _completa_anio(marca: str) -> str:
        """
        Añade el año a una marca RFC3164, que no lo lleva.

        No es inventar un dato: es la convención estándar para ese formato. Se
        asume el año en curso y, si la fecha resultante cae en el futuro —caso
        típico del 31 de diciembre leído el 1 de enero—, el anterior. Sin esto,
        *todas* las líneas syslog caerían a la hora de ingesta y se perdería la
        precisión temporal que la correlación necesita.
        """
        from datetime import datetime, timedelta, timezone

        if "T" in marca or "-" in marca:
            return marca                       # ya es ISO-8601
        ahora = datetime.now(tz=timezone.utc)
        for anio in (ahora.year, ahora.year - 1):
            try:
                fecha = datetime.strptime(f"{marca} {anio}", "%b %d %H:%M:%S %Y")
            except ValueError:
                continue
            fecha = fecha.replace(tzinfo=timezone.utc)
            if fecha <= ahora + timedelta(days=1):
                return fecha.isoformat()
        return marca

    # --- auditd -----------------------------------------------------------
    def _auditd(self, linea: str) -> CollectorResult:
        coincide = AUDITD_RE.match(linea)
        if not coincide:
            return CollectorResult(errors=["la línea no tiene formato auditd reconocible"])

        g = coincide.groupdict()
        campos: dict[str, Any] = {"type": g["type"], "serial": g["serial"]}
        # Los valores de auditd van entre comillas cuando contienen espacios;
        # shlex respeta ese entrecomillado sin romper las rutas.
        try:
            piezas = shlex.split(g["body"])
        except ValueError:
            piezas = g["body"].split()
        for pieza in piezas:
            if "=" in pieza:
                clave, _, valor = pieza.partition("=")
                campos[clave] = valor

        anotaciones: list[str] = []
        ts, anot = self.resolve_timestamp(float(g["ts"]))
        anotaciones += anot

        tipo = g["type"].upper()
        if tipo in ("USER_AUTH", "USER_LOGIN", "USER_ACCT", "CRED_ACQ", "USER_START"):
            categoria, accion = "authentication", "user_login"
        elif tipo in ("SYSCALL", "EXECVE"):
            categoria, accion = "process", "process_create"
        elif tipo in ("PATH", "OPEN", "FILE"):
            categoria, accion = "file", "file_access"
        elif tipo in ("SOCKADDR", "NETFILTER_PKT"):
            categoria, accion = "network", "network_connection"
        else:
            categoria, accion = "audit", f"auditd_{tipo.lower()}"

        exito = self.first(campos, "success", "res")
        outcome = ("success" if str(exito).lower() in ("yes", "success", "1")
                   else "failure" if exito is not None else "unknown")

        comando, anot_cmd = self.trim(self.first(campos, "proctitle", "exe", "comm"))
        anotaciones += anot_cmd

        return CollectorResult(event=SecurityEvent(
            event_id=g["serial"], timestamp=ts, source=self.source_type,
            category=categoria, action=accion,
            host=self.first(campos, "node", "hostname"),
            user=self.first(campos, "acct", "auid", "uid", "AUID"),
            process_name=self.first(campos, "exe", "comm"),
            command_line=comando,
            src_ip=self.first(campos, "addr", "laddr"),
            outcome=outcome,
            properties={"format": "auditd", "audit_type": tipo,
                        "syscall": self.first(campos, "syscall"),
                        "key": self.first(campos, "key")},
            raw={"raw_line": linea, **campos}, tags=list(anotaciones),
        ), annotations=anotaciones)

    # --- heurísticas compartidas -----------------------------------------
    @staticmethod
    def _clasificar(mensaje: str, proceso: Any) -> tuple[str, str, str]:
        """Deduce categoría, acción y resultado del texto del mensaje."""
        bajo = (mensaje or "").lower()
        proc = (str(proceso) or "").lower()

        if any(s in bajo for s in AUTH_FAIL):
            return "authentication", "user_login", "failure"
        if any(s in bajo for s in AUTH_OK):
            return "authentication", "user_login", "success"
        if proc in ("sshd", "sudo", "su", "login", "polkitd"):
            return "authentication", "user_login", "unknown"
        if "connection" in bajo or "connect from" in bajo:
            return "network", "network_connection", "unknown"
        return "process", "process_event", "unknown"

    @staticmethod
    def _ip(mensaje: str) -> str | None:
        coincide = IP_RE.search(mensaje or "")
        return coincide.group("ip") if coincide else None

    @staticmethod
    def _usuario(campos: dict[str, Any], mensaje: str) -> str | None:
        for clave in ("_UID", "USER", "user", "acct"):
            valor = campos.get(clave)
            if valor:
                return str(valor)
        coincide = USER_RE.search(mensaje or "")
        return coincide.group("user") if coincide else None
