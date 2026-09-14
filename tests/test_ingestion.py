"""
Pruebas de la capa de ingesta.

El principio que verifican: **nada se pierde ni se falsea en silencio**. Un
registro problemático puede procesarse igual, pero tiene que quedar marcado.
"""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cybersentinel.ingestion import Normalizer  # noqa: E402
from cybersentinel.ingestion.normalizer import (  # noqa: E402
    PARSERS, TAG_INVALID_TIMESTAMP, TAG_UNKNOWN_SOURCE,
)
from cybersentinel.schema import SecurityEvent  # noqa: E402


# ------------------------------- netflow ------------------------------------
def test_netflow_source_has_its_own_parser():
    """El README anunciaba netflow como fuente soportada; ahora lo es."""
    assert "netflow" in PARSERS


def test_netflow_preserves_the_traffic_volume():
    """
    Sin parser propio, un flujo caía al de Sysmon y perdía los bytes: justo el
    campo del que depende la regla de exfiltración.
    """
    event = Normalizer().normalize_record({
        "source": "netflow", "timestamp": "2025-03-10T10:00:00",
        "src_ip": "10.0.0.50", "dst_ip": "203.0.113.66",
        "dst_port": 443, "protocol": "tcp",
        "bytes_out": 524_288_000, "bytes_in": 2048,
    })
    assert event.source == "netflow"
    assert event.category == "network"
    assert event.bytes_out == 524_288_000
    assert event.bytes_in == 2048
    assert TAG_UNKNOWN_SOURCE not in event.tags


def test_netflow_accepts_unsw_nb15_field_names():
    """Los datasets de la Fase 4 usan srcip/sport/sbytes en vez de src_ip/..."""
    event = Normalizer().normalize_record({
        "source": "netflow", "stime": 1741600800,
        "srcip": "175.45.176.0", "dstip": "149.171.126.16",
        "sport": 13284, "dsport": 80, "proto": "tcp",
        "sbytes": 528, "dbytes": 304,
    })
    assert event.src_ip == "175.45.176.0"
    assert event.dst_port == 80
    assert event.bytes_out == 528


def test_netflow_accepts_zeek_field_names():
    event = Normalizer().normalize_record({
        "source": "netflow", "ts": 1741600800,
        "id.orig_h": "10.0.0.1", "id.resp_h": "10.0.0.2", "id.resp_p": 445,
        "orig_bytes": 1000, "conn_state": "SF",
    })
    assert event.dst_ip == "10.0.0.2"
    assert event.dst_port == 445
    assert event.outcome == "SF"


# --------------------------- fuentes desconocidas ---------------------------
def test_unknown_source_is_tagged_and_logged(caplog):
    """Caer al parser por defecto es aceptable; hacerlo en silencio no."""
    with caplog.at_level(logging.WARNING):
        event = Normalizer().normalize_record(
            {"source": "cortafuegos-raro", "timestamp": "2025-03-10T10:00:00"}
        )
    assert TAG_UNKNOWN_SOURCE in event.tags
    assert "cortafuegos-raro" in caplog.text


def test_unknown_source_is_warned_only_once(caplog):
    """Un archivo entero de una fuente desconocida no debe inundar el log."""
    normalizer = Normalizer()
    with caplog.at_level(logging.WARNING):
        for _ in range(5):
            normalizer.normalize_record({"source": "rara", "timestamp": "2025-03-10T10:00:00"})
    assert caplog.text.count("sin parser") == 1


def test_known_sources_are_not_tagged():
    normalizer = Normalizer()
    for source in PARSERS:
        event = normalizer.normalize_record(
            {"source": source, "timestamp": "2025-03-10T10:00:00"}
        )
        assert TAG_UNKNOWN_SOURCE not in event.tags, source


# ------------------------------ timestamps ----------------------------------
def test_unparseable_timestamp_is_tagged(caplog):
    """
    Un timestamp ilegible se sustituía por la hora actual sin dejar rastro, lo
    que desplaza el evento dentro de la ventana de correlación.
    """
    with caplog.at_level(logging.WARNING):
        event = Normalizer().normalize_record(
            {"source": "auth", "timestamp": "ayer por la tarde", "user": "ana"}
        )
    assert TAG_INVALID_TIMESTAMP in event.tags
    assert "Timestamp no reconocido" in caplog.text


def test_valid_timestamps_are_not_tagged():
    normalizer = Normalizer()
    for value in ("2025-03-10T10:00:00", "2025-03-10T10:00:00Z",
                  "2025-03-10 10:00:00", "2025/03/10 10:00:00", 1741600800):
        event = normalizer.normalize_record({"source": "auth", "timestamp": value})
        assert TAG_INVALID_TIMESTAMP not in event.tags, value


def test_try_parse_timestamp_reports_failure_instead_of_guessing():
    assert SecurityEvent.try_parse_timestamp("no es una fecha") is None
    assert SecurityEvent.try_parse_timestamp(True) is None
    assert SecurityEvent.try_parse_timestamp("2025-03-10T10:00:00") is not None


def test_parse_timestamp_keeps_its_fallback_for_compatibility():
    """La función histórica sigue devolviendo siempre una fecha."""
    assert isinstance(SecurityEvent.parse_timestamp("ilegible"), datetime)
    assert SecurityEvent.parse_timestamp("ilegible").tzinfo is timezone.utc


# ------------------------------ lectura JSONL -------------------------------
def _write(path: Path, records: list[dict]) -> Path:
    path.write_text("\n".join(json.dumps(r) for r in records), encoding="utf-8")
    return path


def test_streaming_and_bulk_reading_agree(tmp_path):
    """`from_jsonl` se apoya en `stream_jsonl`: no pueden divergir."""
    path = _write(tmp_path / "logs.jsonl", [
        {"source": "auth", "timestamp": "2025-03-10T10:05:00", "user": "ana"},
        {"source": "auth", "timestamp": "2025-03-10T10:00:00", "user": "carlos"},
    ])
    normalizer = Normalizer()
    streamed = sorted(normalizer.stream_jsonl(path), key=lambda e: e.timestamp)
    assert [e.user for e in streamed] == [e.user for e in normalizer.from_jsonl(path)]


def test_from_jsonl_returns_events_in_chronological_order(tmp_path):
    path = _write(tmp_path / "logs.jsonl", [
        {"source": "auth", "timestamp": "2025-03-10T12:00:00", "user": "c"},
        {"source": "auth", "timestamp": "2025-03-10T10:00:00", "user": "a"},
        {"source": "auth", "timestamp": "2025-03-10T11:00:00", "user": "b"},
    ])
    assert [e.user for e in Normalizer().from_jsonl(path)] == ["a", "b", "c"]


def test_corrupt_lines_are_skipped_with_a_warning(tmp_path, caplog):
    path = tmp_path / "logs.jsonl"
    path.write_text(
        '{"source": "auth", "timestamp": "2025-03-10T10:00:00", "user": "ana"}\n'
        "{esto no es json}\n"
        "\n"
        '{"source": "auth", "timestamp": "2025-03-10T10:01:00", "user": "bob"}\n',
        encoding="utf-8",
    )
    with caplog.at_level(logging.WARNING):
        events = Normalizer().from_jsonl(path)
    assert [e.user for e in events] == ["ana", "bob"]
    assert "Línea 2" in caplog.text
