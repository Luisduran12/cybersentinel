"""
Adapter del dataset oficial UNSW-NB15 al esquema interno de CyberSentinel.

Fuente: UNSW Canberra Cyber, https://research.unsw.edu.au/projects/unsw-nb15-dataset

El dataset se publica en dos formatos con propiedades **muy distintas** para lo
que aquí interesa, y confundirlos produce evaluaciones incorrectas:

+----------------------------+-----------+-------+--------+-------------------+
| Archivo                    | Cabecera  | IPs   | Tiempo | Registros         |
+----------------------------+-----------+-------+--------+-------------------+
| UNSW-NB15_1..4.csv (crudo) | NO        | SI    | SI     | 2 540 044 (total) |
| UNSW_NB15_training-set.csv | SI        | NO    | NO     | 175 341           |
| UNSW_NB15_testing-set.csv  | SI        | NO    | NO     | 82 332            |
+----------------------------+-----------+-------+--------+-------------------+

La consecuencia metodológica es concreta: **la partición oficial train/test no
tiene marca de tiempo ni direcciones IP**. Sin tiempo no hay correlación
temporal; sin IPs no hay enriquecimiento CTI ni rareza de entidad. Este módulo
no inventa ninguno de los dos: lo declara en `unavailable` y deja que la
evaluación excluya esos componentes en lugar de fabricar una cifra.

Trazabilidad
------------
Cada registro conserva su origen:

    unsw_row_id  ->  event_id  ->  run_id

`unsw_row_id` identifica el archivo y la línea de la que salió el registro, de
modo que cualquier predicción puede devolverse al dato original del dataset.
"""
from __future__ import annotations

import csv
import hashlib
import logging
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from ..schema import SecurityEvent

logger = logging.getLogger(__name__)

csv.field_size_limit(min(sys.maxsize, 2**31 - 1))

#: Marca de que el dataset no puede alimentar un componente.
NOT_AVAILABLE = "NOT_AVAILABLE"

#: Columnas de los CSV crudos UNSW-NB15_1..4.csv, que se publican SIN cabecera.
#: El orden está definido en NUSW-NB15_features.csv, distribuido con el dataset.
RAW_COLUMNS: list[str] = [
    "srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes",
    "dbytes", "sttl", "dttl", "sloss", "dloss", "service", "sload", "dload",
    "spkts", "dpkts", "swin", "dwin", "stcpb", "dtcpb", "smeansz", "dmeansz",
    "trans_depth", "res_bdy_len", "sjit", "djit", "stime", "ltime", "sintpkt",
    "dintpkt", "tcprtt", "synack", "ackdat", "is_sm_ips_ports", "ct_state_ttl",
    "ct_flw_http_mthd", "is_ftp_login", "ct_ftp_cmd", "ct_srv_src", "ct_srv_dst",
    "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm",
    "ct_dst_src_ltm", "attack_cat", "label",
]

#: Mapeo explícito UNSW-NB15 -> SecurityEvent.
#:
#: Se documenta aquí y se exporta en los metadatos de cada ejecución: un lector
#: de la memoria tiene que poder comprobar qué variable del dataset alimentó qué
#: campo, sin leer el código.
FIELD_MAPPING: dict[str, str] = {
    "srcip": "src_ip",
    "dstip": "dst_ip",
    "sport": "src_port",
    "dsport": "dst_port",
    "proto": "protocol",
    "service": "protocol (respaldo si falta proto)",
    "sbytes": "bytes_out",
    "dbytes": "bytes_in",
    "state": "outcome",
    "stime": "timestamp (epoch Unix; solo en los CSV crudos)",
    "dur": "properties.duration_s",
    "spkts": "properties.packets_out",
    "dpkts": "properties.packets_in",
    "sttl": "properties.ttl_out",
    "dttl": "properties.ttl_in",
    "sloss": "properties.loss_out",
    "dloss": "properties.loss_in",
    "sload": "properties.load_out",
    "dload": "properties.load_in",
    "attack_cat": "etiqueta de verdad-terreno (categoría)",
    "label": "etiqueta de verdad-terreno (0/1)",
}

#: Variables del dataset que NO tienen destino en SecurityEvent porque el
#: esquema no modela ese concepto. Se conservan en `properties` para no perder
#: información, pero no alimentan ninguna característica del detector.
UNMAPPED_KEPT_IN_PROPERTIES = [
    "sjit", "djit", "sinpkt", "dinpkt", "sintpkt", "dintpkt", "swin", "dwin",
    "stcpb", "dtcpb", "smean", "dmean", "smeansz", "dmeansz", "trans_depth",
    "response_body_len", "res_bdy_len", "tcprtt", "synack", "ackdat", "rate",
    "ct_srv_src", "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm",
    "ct_dst_sport_ltm", "ct_dst_src_ltm", "ct_state_ttl", "ct_flw_http_mthd",
    "ct_ftp_cmd", "is_ftp_login", "is_sm_ips_ports",
]


@dataclass
class UNSWRecord:
    """Un registro de UNSW-NB15 convertido, con su etiqueta y su procedencia."""

    unsw_row_id: str
    event: SecurityEvent
    label: int
    attack_cat: str
    #: Componentes del pipeline que este registro NO puede alimentar.
    unavailable: list[str] = field(default_factory=list)

    @property
    def is_attack(self) -> bool:
        return self.label == 1


def _clean(name: str) -> str:
    """Normaliza un nombre de columna (la cabecera del train-set trae BOM)."""
    return name.strip().lstrip("﻿").lower().replace(" ", "_")


def _value(row: dict[str, Any], key: str) -> Any:
    raw = row.get(key)
    if isinstance(raw, str):
        raw = raw.strip()
    return None if raw in (None, "", "-", "0x000b") else raw


def _to_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        # UNSW-NB15 trae puertos en hexadecimal en algunas filas ("0x20").
        try:
            return int(str(value), 16)
        except (TypeError, ValueError):
            return None


def _to_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _timestamp(row: dict[str, Any]) -> tuple[datetime | None, bool]:
    """
    Marca de tiempo del flujo, si el formato la trae.

    Devuelve (None, False) cuando no existe. **No se inventa una**: una hora
    falsa contaminaría la correlación temporal y las características cíclicas
    del detector, produciendo resultados que parecerían válidos y no lo serían.
    """
    epoch = _to_int(_value(row, "stime") or _value(row, "ltime"))
    if epoch is None:
        return None, False
    try:
        return datetime.fromtimestamp(epoch, tz=timezone.utc), True
    except (OverflowError, OSError, ValueError):
        return None, False


class UNSWNB15Adapter:
    """
    Convierte registros UNSW-NB15 en `SecurityEvent`, conservando procedencia.

    No modifica `SecurityEvent`: todo lo que el esquema no modela se guarda en
    `properties`, de modo que la información del dataset no se pierde aunque no
    alimente ninguna característica.
    """

    #: Marca temporal sintética usada SOLO cuando el formato no trae tiempo.
    #: Es un índice de orden, no una hora real: se declara como no disponible en
    #: `unavailable` y las etapas que dependen del tiempo quedan excluidas.
    SYNTHETIC_EPOCH = datetime(2015, 1, 1, tzinfo=timezone.utc)

    def __init__(self, source_name: str = "unsw-nb15") -> None:
        self.source_name = source_name

    # --- Lectura ---------------------------------------------------------
    def _has_header(self, first_row: list[str]) -> bool:
        nombres = {_clean(c) for c in first_row}
        return "label" in nombres or "attack_cat" in nombres or "dur" in nombres

    def read_csv(self, path: str | Path, limit: int | None = None) -> Iterator[UNSWRecord]:
        """
        Lee un CSV del dataset en cualquiera de sus dos formatos.

        Detecta si hay cabecera: los cuatro archivos crudos se publican sin ella
        y hay que aplicar los nombres canónicos por posición.
        """
        path = Path(path)
        with open(path, "r", encoding="utf-8", errors="replace", newline="") as fh:
            reader = csv.reader(fh)
            try:
                primera = next(reader)
            except StopIteration:
                return

            if self._has_header(primera):
                columnas = [_clean(c) for c in primera]
                filas = reader
                offset = 2                      # la línea 1 es la cabecera
            else:
                columnas = list(RAW_COLUMNS)
                filas = self._prepend(primera, reader)
                offset = 1

            for indice, valores in enumerate(filas):
                if limit is not None and indice >= limit:
                    return
                if not valores or not any(valores):
                    continue
                fila = dict(zip(columnas, valores))
                yield self.to_record(fila, f"{path.name}:{indice + offset}")

    @staticmethod
    def _prepend(primera: list[str], reader: Any) -> Iterator[list[str]]:
        yield primera
        yield from reader

    # --- Conversión ------------------------------------------------------
    def to_record(self, row: dict[str, Any], unsw_row_id: str) -> UNSWRecord:
        """Convierte una fila en `UNSWRecord`, declarando lo que no puede aportar."""
        timestamp, tiene_tiempo = _timestamp(row)
        no_disponible: list[str] = []

        if not tiene_tiempo:
            no_disponible.append("timestamp")
            # Orden estable derivado del número de línea: permite que el
            # pipeline procese el registro, pero NO es una hora real.
            numero = _to_int(unsw_row_id.rsplit(":", 1)[-1]) or 0
            timestamp = self.SYNTHETIC_EPOCH.replace(
                microsecond=0
            ) + (numero * __import__("datetime").timedelta(seconds=1))

        src_ip = _value(row, "srcip")
        dst_ip = _value(row, "dstip")
        if src_ip is None and dst_ip is None:
            no_disponible.append("ip_addresses")

        # Todo lo que el esquema no modela se conserva aquí.
        propiedades: dict[str, Any] = {"unsw_row_id": unsw_row_id}
        for columna in UNMAPPED_KEPT_IN_PROPERTIES:
            valor = _value(row, columna)
            if valor is not None:
                propiedades[columna] = valor
        for columna, destino in (
            ("dur", "duration_s"), ("spkts", "packets_out"), ("dpkts", "packets_in"),
            ("sttl", "ttl_out"), ("dttl", "ttl_in"), ("sloss", "loss_out"),
            ("dloss", "loss_in"), ("sload", "load_out"), ("dload", "load_in"),
        ):
            valor = _to_float(_value(row, columna))
            if valor is not None:
                propiedades[destino] = valor

        etiqueta = _to_int(_value(row, "label")) or 0
        categoria = str(_value(row, "attack_cat") or "").strip() or "Normal"
        # UNSW-NB15 escribe la misma categoría de varias formas entre archivos.
        categoria = {"backdoors": "Backdoor", "": "Normal"}.get(
            categoria.lower(), categoria
        )

        evento = SecurityEvent(
            event_id=unsw_row_id,
            timestamp=timestamp,
            source="netflow",
            category="network",
            action="network_flow",
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=_to_int(_value(row, "sport")),
            dst_port=_to_int(_value(row, "dsport")),
            protocol=_value(row, "proto") or _value(row, "service"),
            bytes_out=_to_int(_value(row, "sbytes")),
            bytes_in=_to_int(_value(row, "dbytes")),
            outcome=_value(row, "state") or "unknown",
            properties=propiedades,
            raw=dict(row),
            tags=[f"dataset:{self.source_name}"]
            + ([f"attack:{categoria}"] if etiqueta else ["benign"]),
        )

        return UNSWRecord(
            unsw_row_id=unsw_row_id, event=evento, label=etiqueta,
            attack_cat=categoria, unavailable=no_disponible,
        )


def file_sha256(path: str | Path, chunk: int = 1 << 20) -> str:
    """SHA-256 del archivo, para poder probar qué datos se usaron."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for bloque in iter(lambda: fh.read(chunk), b""):
            digest.update(bloque)
    return digest.hexdigest()


def load(path: str | Path, limit: int | None = None) -> list[UNSWRecord]:
    """Carga un archivo del dataset completo en memoria."""
    return list(UNSWNB15Adapter().read_csv(path, limit=limit))
