"""
Pruebas de los cargadores de datasets públicos (Fase 4).

Las fixtures de `tests/fixtures/` reproducen los **encabezados y rarezas reales**
de cada dataset, que es donde falla la ingesta: CSV sin cabecera, nombres de
columna con un espacio delante, codificación cp1252, marcas de tiempo en tres
formatos y valores `Infinity`/`NaN`.
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cybersentinel.ingestion.datasets import (  # noqa: E402
    LOADERS, AtomicRedTeamGroundTruth, CICIDS2017Loader, SecurityDatasetsLoader,
    UNSWNB15Loader, load_dataset,
)
from cybersentinel.schema import SecurityEvent  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures"


# ------------------------------- UNSW-NB15 ----------------------------------
def test_unsw_reads_raw_csv_without_header():
    """Los cuatro CSV crudos no traen cabecera: las columnas van por posición."""
    events = list(UNSWNB15Loader().load(FIXTURES / "unsw_nb15_raw_sample.csv"))
    assert len(events) == 3

    dns = events[0]
    assert dns.label == 0
    assert dns.category == "Normal"
    assert dns.event.src_ip == "59.166.0.0"
    assert dns.event.dst_port == 53
    assert dns.event.bytes_out == 132
    assert dns.event.bytes_in == 164


def test_unsw_raw_csv_keeps_the_attack_category():
    events = list(UNSWNB15Loader().load(FIXTURES / "unsw_nb15_raw_sample.csv"))
    ataques = [e for e in events if e.is_attack]
    assert {e.category for e in ataques} == {"Exploits", "Reconnaissance"}


def test_unsw_reads_the_training_split_with_header():
    """La partición de entrenamiento sí trae cabecera y no trae IPs."""
    events = list(UNSWNB15Loader().load(FIXTURES / "unsw_nb15_training_sample.csv"))
    assert len(events) == 3
    assert [e.label for e in events] == [0, 0, 1]
    assert events[2].category == "Exploits"
    assert events[2].event.bytes_out == 528
    assert events[2].event.src_ip is None      # este formato no incluye IPs


def test_unsw_converts_the_epoch_timestamp():
    """`stime` es un epoch Unix, no una fecha ISO."""
    events = list(UNSWNB15Loader().load(FIXTURES / "unsw_nb15_raw_sample.csv"))
    assert events[0].event.timestamp.year == 2015
    assert events[0].event.timestamp.tzinfo is timezone.utc


def test_unsw_respects_the_limit():
    events = list(UNSWNB15Loader().load(FIXTURES / "unsw_nb15_raw_sample.csv", limit=2))
    assert len(events) == 2


# ------------------------------- CICIDS2017 ---------------------------------
def test_cicids_handles_headers_with_leading_spaces():
    """Las columnas del dataset real se publican como ' Destination Port'."""
    events = list(CICIDS2017Loader().load(FIXTURES / "cicids2017_sample.csv"))
    assert len(events) == 4
    assert events[0].event.src_ip == "192.168.10.5"
    assert events[0].event.dst_port == 443


def test_cicids_decodes_the_non_ascii_label():
    """
    "Web Attack – Brute Force" lleva un guion cp1252 (byte 0x96) que rompe la
    lectura UTF-8 estricta del archivo original.
    """
    events = list(CICIDS2017Loader().load(FIXTURES / "cicids2017_sample.csv"))
    categorias = {e.category for e in events if e.is_attack}
    assert "Web Attack - Brute Force" in categorias
    assert "DDoS" in categorias


def test_cicids_marks_benign_flows_as_label_zero():
    events = list(CICIDS2017Loader().load(FIXTURES / "cicids2017_sample.csv"))
    assert [e.label for e in events] == [0, 0, 1, 1]


def test_cicids_parses_both_timestamp_formats():
    """El dataset mezcla '5/7/2017 8:55' y '7/7/2017 3:30:00 PM'."""
    events = list(CICIDS2017Loader().load(FIXTURES / "cicids2017_sample.csv"))
    assert events[0].event.timestamp.year == 2017
    assert events[2].event.timestamp.hour == 15       # 3:30 PM


def test_cicids_survives_infinity_and_nan():
    """Las columnas de tasa traen Infinity y NaN; no pueden tumbar la carga."""
    events = list(CICIDS2017Loader().load(FIXTURES / "cicids2017_sample.csv"))
    assert all(e.event.bytes_out is not None for e in events)


# --------------------------- Security-Datasets ------------------------------
def test_security_datasets_maps_sysmon_process_events():
    events = list(SecurityDatasetsLoader(technique="T1059.001").load(
        FIXTURES / "security_datasets_sample.json"))
    proceso = events[0]
    assert proceso.event.category == "process"
    assert "powershell" in proceso.event.command_line.lower()
    assert proceso.category == "T1059.001"
    assert "technique:T1059.001" in proceso.event.tags


def test_security_datasets_maps_windows_logons_to_authentication():
    """Un 4625 tiene que llegar como autenticación fallida, o las reglas no lo ven."""
    events = list(SecurityDatasetsLoader().load(FIXTURES / "security_datasets_sample.json"))
    logon = events[2]
    assert logon.event.category == "authentication"
    assert logon.event.outcome == "failure"
    assert logon.event.user == "administrator"
    assert logon.event.src_ip == "172.18.39.5"


def test_security_datasets_maps_network_connections():
    events = list(SecurityDatasetsLoader().load(FIXTURES / "security_datasets_sample.json"))
    red = events[1]
    assert red.event.category == "network"
    assert red.event.dst_port == 4444


def test_security_datasets_labels_the_whole_file():
    """La etiqueta es del archivo, no del evento: es un límite del formato."""
    events = list(SecurityDatasetsLoader(technique="T1003").load(
        FIXTURES / "security_datasets_sample.json"))
    assert all(e.label == 1 for e in events)
    assert all(e.category == "T1003" for e in events)


# ----------------------------- Atomic Red Team ------------------------------
def test_atomic_reads_the_execution_log():
    verdad = AtomicRedTeamGroundTruth.from_csv(FIXTURES / "atomic_execution_log.csv")
    assert [e.technique for e in verdad.executions] == ["T1059.001", "T1053.005"]
    assert verdad.executions[0].hostname == "WKS-01"


def test_atomic_labels_events_inside_the_execution_window():
    verdad = AtomicRedTeamGroundTruth.from_csv(
        FIXTURES / "atomic_execution_log.csv", window_seconds=120
    )
    base = datetime(2025, 3, 10, 10, 5, tzinfo=timezone.utc)
    eventos = [
        SecurityEvent("1", base + timedelta(seconds=30), "sysmon", "process", "c", host="WKS-01"),
        SecurityEvent("2", base + timedelta(minutes=10), "sysmon", "process", "c", host="WKS-01"),
    ]
    etiquetados = verdad.label_events(eventos)

    assert etiquetados[0].label == 1 and etiquetados[0].category == "T1059.001"
    assert etiquetados[1].label == 0 and etiquetados[1].category == "Normal"


def test_atomic_does_not_label_events_from_another_host():
    """La ejecución fue en WKS-01: lo que pase en otra máquina no es esa técnica."""
    verdad = AtomicRedTeamGroundTruth.from_csv(FIXTURES / "atomic_execution_log.csv")
    evento = SecurityEvent("1", datetime(2025, 3, 10, 10, 5, 30, tzinfo=timezone.utc),
                           "sysmon", "process", "c", host="WKS-99")
    assert verdad.label_events([evento])[0].label == 0


def test_atomic_does_not_label_events_before_the_execution():
    """Solo cuenta lo que ocurre *después* de lanzar la técnica."""
    verdad = AtomicRedTeamGroundTruth.from_csv(FIXTURES / "atomic_execution_log.csv")
    evento = SecurityEvent("1", datetime(2025, 3, 10, 10, 4, 0, tzinfo=timezone.utc),
                           "sysmon", "process", "c", host="WKS-01")
    assert verdad.label_events([evento])[0].label == 0


# ------------------------------- registro -----------------------------------
def test_every_loader_is_registered():
    assert set(LOADERS) == {"unsw-nb15", "cicids2017", "security-datasets"}


def test_load_dataset_rejects_an_unknown_name():
    with pytest.raises(ValueError, match="Dataset desconocido"):
        load_dataset("no-existe", FIXTURES / "unsw_nb15_raw_sample.csv")


def test_load_dataset_works_by_name():
    events = load_dataset("unsw-nb15", FIXTURES / "unsw_nb15_raw_sample.csv")
    assert len(events) == 3
    assert all(e.event.source == "netflow" for e in events)
    assert all("dataset:unsw-nb15" in e.event.tags for e in events)
