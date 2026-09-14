"""
Cargadores de datasets públicos etiquetados.

Traducen datasets de evaluación al esquema `SecurityEvent`, conservando la
etiqueta de verdad-terreno para poder **medir** el detector en vez de solo
demostrarlo.

Datasets soportados
-------------------
- **UNSW-NB15** (flujos de red etiquetados, UNSW Canberra). Dos formatos:
  los cuatro CSV crudos (`UNSW-NB15_1.csv`…`_4.csv`), que **no traen cabecera**,
  y los de partición (`UNSW_NB15_training-set.csv`), que sí.
- **CICIDS2017** (flujos etiquetados, Universidad de New Brunswick). Dos
  formatos: `MachineLearningCVE/` (sin IPs) y `GeneratedLabelledFlows/` (con
  IPs y marca de tiempo).
- **Security-Datasets / Mordor** (OTRF): telemetría Windows en JSON, ya
  asociada a una técnica ATT&CK.
- **Atomic Red Team**: no es un dataset de eventos sino el registro de ejecución
  de las técnicas en tu propio laboratorio; sirve como verdad-terreno temporal
  contra la que contrastar la telemetría que recojas.

Cada dataset trae sus trampas de formato, y están resueltas aquí en lugar de en
el código de evaluación: cabeceras con espacios delante, codificación cp1252,
CSV sin cabecera, marcas de tiempo en tres formatos distintos y etiquetas con
guiones no ASCII.
"""
from __future__ import annotations

import csv
import json
import logging
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from ..schema import SecurityEvent

logger = logging.getLogger(__name__)

# Los CSV de flujos traen campos muy largos; el limite por defecto de csv se queda corto.
csv.field_size_limit(min(sys.maxsize, 2**31 - 1))


@dataclass
class LabeledEvent:
    """Un evento normalizado junto con su etiqueta de verdad-terreno."""
    event: SecurityEvent
    label: int            # 1 = ataque, 0 = benigno
    category: str         # "Normal", "Exploits", "DDoS", "T1059.001"…

    @property
    def is_attack(self) -> bool:
        return self.label == 1


def _clean(name: str) -> str:
    """
    Normaliza un nombre de columna.

    CICIDS2017 publica sus cabeceras con un espacio delante (' Destination Port')
    y mezcla mayúsculas entre archivos; UNSW-NB15 alterna 'Label' y 'label'.
    """
    return name.strip().lower().replace(" ", "_").replace("-", "_")


def _get(row: dict[str, Any], *names: str, default: Any = None) -> Any:
    """
    Primer valor no vacío entre varios nombres de columna ya normalizados.

    Los valores se recortan: CICIDS2017 publica también los datos con un espacio
    delante (' 192.168.10.5'). Una IP con espacio no coincide con la expresión de
    rangos internos ni agrupa con la misma IP vista en otra fuente, así que el
    recorte no es cosmético.
    """
    for name in names:
        value = row.get(name)
        if isinstance(value, str):
            value = value.strip()
        if value not in (None, "", "-"):
            return value
    return default


def _to_int(value: Any) -> int | None:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    # CICIDS2017 contiene Infinity y NaN en las columnas de tasa.
    return number if number == number and abs(number) != float("inf") else default


class DatasetLoader(ABC):
    """Contrato común: un archivo entra, eventos etiquetados salen."""

    name: str = "dataset"
    #: Codificación habitual del dataset. CICIDS2017 no es UTF-8.
    encoding: str = "utf-8"

    @abstractmethod
    def load(self, path: str | Path, limit: int | None = None) -> Iterator[LabeledEvent]:
        """Lee el archivo evento a evento, sin cargarlo entero en memoria."""

    def load_many(
        self, paths: list[str | Path], limit: int | None = None
    ) -> Iterator[LabeledEvent]:
        """Recorre varios archivos del mismo dataset como si fueran uno."""
        emitted = 0
        for path in paths:
            for labeled in self.load(path):
                yield labeled
                emitted += 1
                if limit is not None and emitted >= limit:
                    return

    def _open(self, path: str | Path):
        # errors="replace": las etiquetas de CICIDS2017 traen un guion cp1252
        # que revienta la decodificacion UTF-8 estricta a mitad del archivo.
        return open(path, "r", encoding=self.encoding, errors="replace", newline="")


class UNSWNB15Loader(DatasetLoader):
    """
    UNSW-NB15: flujos de red etiquetados con categoría de ataque.

    Los cuatro CSV crudos no tienen fila de cabecera: las columnas se definen
    aparte, en `NUSW-NB15_features.csv`. Si no se detecta cabecera se aplican los
    nombres canónicos por posición.
    """

    name = "unsw-nb15"

    #: Orden canónico de columnas de UNSW-NB15_1.csv … _4.csv (49 columnas).
    RAW_COLUMNS = [
        "srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes",
        "dbytes", "sttl", "dttl", "sloss", "dloss", "service", "sload", "dload",
        "spkts", "dpkts", "swin", "dwin", "stcpb", "dtcpb", "smeansz", "dmeansz",
        "trans_depth", "res_bdy_len", "sjit", "djit", "stime", "ltime", "sintpkt",
        "dintpkt", "tcprtt", "synack", "ackdat", "is_sm_ips_ports", "ct_state_ttl",
        "ct_flw_http_mthd", "is_ftp_login", "ct_ftp_cmd", "ct_srv_src", "ct_srv_dst",
        "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm",
        "ct_dst_src_ltm", "attack_cat", "label",
    ]

    def _has_header(self, first_row: list[str]) -> bool:
        """La cabecera existe si la primera fila contiene nombres, no datos."""
        joined = {_clean(c) for c in first_row}
        return "label" in joined or "attack_cat" in joined or "dur" in joined

    def load(self, path: str | Path, limit: int | None = None) -> Iterator[LabeledEvent]:
        with self._open(path) as fh:
            reader = csv.reader(fh)
            try:
                first = next(reader)
            except StopIteration:
                return

            if self._has_header(first):
                columns = [_clean(c) for c in first]
                rows = reader
            else:
                columns = list(self.RAW_COLUMNS)
                logger.info("%s: sin cabecera, se aplican los nombres canonicos.", path)
                rows = self._prepend(first, reader)

            for index, values in enumerate(rows):
                if limit is not None and index >= limit:
                    return
                if not values:
                    continue
                yield self._to_labeled(dict(zip(columns, values)))

    @staticmethod
    def _prepend(first: list[str], reader: Any) -> Iterator[list[str]]:
        yield first
        yield from reader

    def _to_labeled(self, row: dict[str, Any]) -> LabeledEvent:
        # attack_cat viene con espacios sobrantes y con 'Backdoors'/'Backdoor'
        # escrito de las dos formas segun el archivo.
        category = str(_get(row, "attack_cat", default="") or "").strip() or "Normal"
        label = _to_int(_get(row, "label", default=0)) or 0

        stime = _get(row, "stime", "ltime")
        timestamp = SecurityEvent.try_parse_timestamp(_to_int(stime)) if stime else None

        event = SecurityEvent(
            event_id=str(_get(row, "id", default="flow")),
            timestamp=timestamp or datetime.now(tz=timezone.utc),
            source="netflow",
            category="network",
            action="network_flow",
            src_ip=_get(row, "srcip"),
            dst_ip=_get(row, "dstip"),
            src_port=_to_int(_get(row, "sport")),
            dst_port=_to_int(_get(row, "dsport")),
            protocol=_get(row, "proto", "service"),
            bytes_out=_to_int(_get(row, "sbytes")),
            bytes_in=_to_int(_get(row, "dbytes")),
            outcome=_get(row, "state", default="unknown"),
            raw=row,
            tags=[f"dataset:{self.name}"],
        )
        return LabeledEvent(event=event, label=label, category=category)


class CICIDS2017Loader(DatasetLoader):
    """
    CICIDS2017: flujos etiquetados de la Universidad de New Brunswick.

    Los archivos de `MachineLearningCVE/` no incluyen IPs (empiezan en
    'Destination Port'); los de `GeneratedLabelledFlows/` sí, y añaden una marca
    de tiempo en un formato que varía entre archivos.
    """

    name = "cicids2017"
    encoding = "cp1252"        # el guion de "Web Attack – Brute Force" no es ASCII

    BENIGN_LABELS = {"benign", "normal"}

    #: Formatos de fecha observados entre los distintos archivos del dataset.
    TIMESTAMP_FORMATS = (
        "%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M", "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M",
        "%d/%m/%Y %I:%M:%S %p", "%m/%d/%Y %I:%M:%S %p", "%Y-%m-%d %H:%M:%S",
    )

    def _timestamp(self, value: Any) -> datetime | None:
        if not value:
            return None
        text = str(value).strip()
        for fmt in self.TIMESTAMP_FORMATS:
            try:
                return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        return SecurityEvent.try_parse_timestamp(text)

    def load(self, path: str | Path, limit: int | None = None) -> Iterator[LabeledEvent]:
        with self._open(path) as fh:
            reader = csv.DictReader(fh)
            if reader.fieldnames is None:
                return
            reader.fieldnames = [_clean(name) for name in reader.fieldnames]

            for index, row in enumerate(reader):
                if limit is not None and index >= limit:
                    return
                if not any(row.values()):
                    continue
                yield self._to_labeled(row)

    def _to_labeled(self, row: dict[str, Any]) -> LabeledEvent:
        raw_label = str(_get(row, "label", default="BENIGN") or "BENIGN").strip()
        # "Web Attack \x96 Brute Force": se normaliza el guion a uno ASCII.
        category = raw_label.replace("\x96", "-").replace("–", "-")
        label = 0 if category.lower() in self.BENIGN_LABELS else 1

        timestamp = self._timestamp(_get(row, "timestamp"))
        if timestamp is None:
            timestamp = datetime.now(tz=timezone.utc)

        event = SecurityEvent(
            event_id=str(_get(row, "flow_id", default="flow")),
            timestamp=timestamp,
            source="netflow",
            category="network",
            action="network_flow",
            src_ip=_get(row, "source_ip", "src_ip"),
            dst_ip=_get(row, "destination_ip", "dst_ip"),
            src_port=_to_int(_get(row, "source_port", "src_port")),
            dst_port=_to_int(_get(row, "destination_port", "dst_port")),
            protocol=str(_get(row, "protocol", default="") or ""),
            bytes_out=_to_int(_get(row, "total_length_of_fwd_packets", "fwd_packets_length_total")),
            bytes_in=_to_int(_get(row, "total_length_of_bwd_packets", "bwd_packets_length_total")),
            outcome="unknown",
            raw=row,
            tags=[f"dataset:{self.name}"],
        )
        return LabeledEvent(event=event, label=label, category=category)


class SecurityDatasetsLoader(DatasetLoader):
    """
    Security-Datasets / Mordor (OTRF): telemetría Windows en JSON Lines.

    A diferencia de los datasets de flujos, aquí la etiqueta **no viene por
    evento**: cada archivo corresponde a la ejecución de una técnica ATT&CK
    concreta. La etiqueta se pasa al construir el cargador (o se lee del
    metadato del dataset) y se aplica a todo el archivo.

    Es un límite metodológico importante: dentro de un archivo de técnica hay
    mucha telemetría benigna de fondo, así que medir "precisión" contra esa
    etiqueta sobreestima los falsos positivos. Sirve para verificar **cobertura
    de detección** (¿se dispara la regla correcta?), no para una tasa de acierto.
    """

    name = "security-datasets"

    def __init__(self, technique: str = "unknown", label: int = 1) -> None:
        self.technique = technique
        self.label = label

    def load(self, path: str | Path, limit: int | None = None) -> Iterator[LabeledEvent]:
        with self._open(path) as fh:
            for index, line in enumerate(fh):
                if limit is not None and index >= limit:
                    return
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    logger.warning("Linea %d de %s ilegible: %s", index + 1, path, exc)
                    continue
                yield self._to_labeled(record)

    def _to_labeled(self, record: dict[str, Any]) -> LabeledEvent:
        event_id = record.get("EventID") or record.get("event_id")
        channel = str(record.get("Channel", ""))
        timestamp = SecurityEvent.try_parse_timestamp(
            record.get("@timestamp") or record.get("UtcTime") or record.get("TimeCreated")
        ) or datetime.now(tz=timezone.utc)

        # Los eventos de autenticacion de Windows (4624/4625) se mapean a la
        # categoria 'authentication' para que las reglas de credenciales los vean.
        if str(event_id) in ("4624", "4625", "4771", "4776"):
            event = SecurityEvent(
                event_id=str(event_id),
                timestamp=timestamp,
                source="auth",
                category="authentication",
                action="user_login",
                host=record.get("Hostname") or record.get("Computer"),
                user=record.get("TargetUserName") or record.get("SubjectUserName"),
                src_ip=record.get("IpAddress") or record.get("SourceIp"),
                outcome="failure" if str(event_id) == "4625" else "success",
                raw=record,
                tags=[f"dataset:{self.name}", f"technique:{self.technique}"],
            )
        else:
            event = SecurityEvent(
                event_id=str(event_id or "sysmon"),
                timestamp=timestamp,
                source="sysmon",
                category="network" if str(event_id) == "3" else "process",
                action=f"event_{event_id}" if event_id else "process_create",
                host=record.get("Hostname") or record.get("Computer"),
                user=record.get("User") or record.get("SubjectUserName"),
                process_name=record.get("Image") or record.get("SourceImage"),
                command_line=record.get("CommandLine"),
                parent_process=record.get("ParentImage"),
                src_ip=record.get("SourceIp"),
                dst_ip=record.get("DestinationIp"),
                dst_port=_to_int(record.get("DestinationPort")),
                protocol=record.get("Protocol"),
                outcome="unknown",
                raw=record,
                tags=[f"dataset:{self.name}", f"technique:{self.technique}"],
            )
        return LabeledEvent(event=event, label=self.label, category=self.technique)


@dataclass
class AtomicExecution:
    """Una ejecución de técnica de Atomic Red Team en el laboratorio propio."""
    technique: str
    test_name: str
    timestamp: datetime
    hostname: str = ""
    user: str = ""

    def covers(self, moment: datetime, window_seconds: int = 120) -> bool:
        """¿Este momento cae dentro de la ventana de la ejecución?"""
        delta = (moment - self.timestamp).total_seconds()
        return 0 <= delta <= window_seconds


class AtomicRedTeamGroundTruth:
    """
    Verdad-terreno construida desde el registro de ejecución de Atomic Red Team.

    `Invoke-AtomicTest` puede escribir un CSV con qué técnica se ejecutó y
    cuándo. Eso convierte la telemetría de tu propio laboratorio en un conjunto
    etiquetado: todo evento dentro de la ventana posterior a una ejecución se
    atribuye a esa técnica.

    Uso previsto (todo en tu laboratorio, nunca contra terceros):

        1. Recoger Sysmon durante la sesión de pruebas.
        2. Ejecutar las técnicas con `Invoke-AtomicTest -ExecutionLogPath log.csv`.
        3. Etiquetar la telemetría con `label_events`.

    La ventana por defecto (120 s) es una aproximación: un artefacto de
    persistencia puede generar eventos mucho después. Conviene declararlo al
    reportar resultados.
    """

    def __init__(self, executions: list[AtomicExecution], window_seconds: int = 120) -> None:
        self.executions = sorted(executions, key=lambda e: e.timestamp)
        self.window_seconds = window_seconds

    @classmethod
    def from_csv(cls, path: str | Path, window_seconds: int = 120) -> "AtomicRedTeamGroundTruth":
        """Lee el CSV de `Invoke-AtomicTest -ExecutionLogPath`."""
        executions: list[AtomicExecution] = []
        with open(path, "r", encoding="utf-8", errors="replace", newline="") as fh:
            reader = csv.DictReader(fh)
            reader.fieldnames = [_clean(n) for n in (reader.fieldnames or [])]
            for row in reader:
                timestamp = SecurityEvent.try_parse_timestamp(
                    _get(row, "execution_time_(utc)", "execution_time_utc", "timestamp")
                )
                technique = _get(row, "technique", "technique_id")
                if timestamp is None or not technique:
                    continue
                executions.append(AtomicExecution(
                    technique=str(technique).strip(),
                    test_name=str(_get(row, "test_name", default="") or ""),
                    timestamp=timestamp,
                    hostname=str(_get(row, "hostname", default="") or ""),
                    user=str(_get(row, "username", "user", default="") or ""),
                ))
        return cls(executions, window_seconds=window_seconds)

    def technique_at(self, moment: datetime, hostname: str | None = None) -> str | None:
        """Técnica que se estaba ejecutando en ese instante, si alguna."""
        for execution in self.executions:
            if hostname and execution.hostname and execution.hostname != hostname:
                continue
            if execution.covers(moment, self.window_seconds):
                return execution.technique
        return None

    def label_events(self, events: list[SecurityEvent]) -> list[LabeledEvent]:
        """Etiqueta telemetría propia según qué técnica se ejecutaba en cada momento."""
        labeled: list[LabeledEvent] = []
        for event in events:
            technique = self.technique_at(event.timestamp, event.host)
            labeled.append(LabeledEvent(
                event=event,
                label=1 if technique else 0,
                category=technique or "Normal",
            ))
        return labeled


#: Cargadores disponibles por nombre, para la CLI.
LOADERS: dict[str, type[DatasetLoader]] = {
    UNSWNB15Loader.name: UNSWNB15Loader,
    CICIDS2017Loader.name: CICIDS2017Loader,
    SecurityDatasetsLoader.name: SecurityDatasetsLoader,
}


def load_dataset(
    name: str, path: str | Path, limit: int | None = None, **kwargs: Any
) -> list[LabeledEvent]:
    """Carga un dataset por nombre. Lanza ValueError si el nombre no existe."""
    if name not in LOADERS:
        raise ValueError(
            f"Dataset desconocido: {name!r}. Disponibles: {', '.join(sorted(LOADERS))}."
        )
    loader = LOADERS[name](**kwargs)
    return list(loader.load(path, limit=limit))
