"""
Pruebas del adapter del dataset oficial UNSW-NB15.

No dependen de tener el dataset descargado: usan fixtures con el formato real.
Lo que verifican es lo que hace válida o inválida una evaluación: que los dos
formatos se lean bien, que la trazabilidad no se pierda y —sobre todo— que el
adapter **no invente** los campos que el dataset no trae.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cybersentinel.data.unsw_nb15_adapter import (  # noqa: E402
    FIELD_MAPPING, RAW_COLUMNS, UNSWNB15Adapter, file_sha256, load,
)

FIXTURES = ROOT / "tests" / "fixtures"


# ------------------------------- formato crudo ------------------------------
def test_raw_csv_without_header_maps_by_position():
    """Los CSV crudos de UNSW se publican SIN cabecera: van por posición."""
    registros = load(FIXTURES / "unsw_nb15_raw_sample.csv")
    assert len(registros) == 3

    dns = registros[0]
    assert dns.event.src_ip == "59.166.0.0"
    assert dns.event.dst_port == 53
    assert dns.event.bytes_out == 132
    assert dns.event.bytes_in == 164
    assert dns.label == 0
    assert dns.attack_cat == "Normal"


def test_raw_csv_has_real_timestamps():
    """`stime` es un epoch Unix: sin él no hay correlación temporal posible."""
    registros = load(FIXTURES / "unsw_nb15_raw_sample.csv")
    assert registros[0].event.timestamp.year == 2015
    assert "timestamp" not in registros[0].unavailable


def test_raw_csv_keeps_attack_categories():
    registros = load(FIXTURES / "unsw_nb15_raw_sample.csv")
    assert {r.attack_cat for r in registros if r.is_attack} == {
        "Exploits", "Reconnaissance"
    }


def test_raw_column_list_matches_the_official_feature_count():
    """UNSW documenta 49 columnas en NUSW-NB15_features.csv."""
    assert len(RAW_COLUMNS) == 49
    assert RAW_COLUMNS[0] == "srcip"
    assert RAW_COLUMNS[-1] == "label"


# --------------------------- partición oficial ------------------------------
def test_training_split_is_read_with_its_header():
    registros = load(FIXTURES / "unsw_nb15_training_sample.csv")
    assert len(registros) == 3
    assert [r.label for r in registros] == [0, 0, 1]
    assert registros[2].attack_cat == "Exploits"
    assert registros[2].event.bytes_out == 528


def test_training_split_declares_what_it_cannot_feed():
    """
    La partición oficial no trae IP, puerto ni tiempo. El adapter tiene que
    decirlo: es lo que permite excluir esos componentes de la evaluación en vez
    de medirlos sobre datos inexistentes.
    """
    registro = load(FIXTURES / "unsw_nb15_training_sample.csv")[0]
    assert "timestamp" in registro.unavailable
    assert "ip_addresses" in registro.unavailable
    assert registro.event.src_ip is None


def test_no_timestamp_is_ever_invented_as_real():
    """
    Cuando no hay tiempo se usa un índice de orden, pero NUNCA se presenta como
    dato del dataset: queda marcado en `unavailable`.
    """
    registros = load(FIXTURES / "unsw_nb15_training_sample.csv")
    assert all("timestamp" in r.unavailable for r in registros)
    # Marcas distintas para conservar el orden, no horas reales.
    assert len({r.event.timestamp for r in registros}) == len(registros)


# ------------------------------ trazabilidad --------------------------------
def test_traceability_from_dataset_row_to_event():
    """unsw_row_id -> event_id: toda predicción vuelve a su fila de origen."""
    registros = load(FIXTURES / "unsw_nb15_raw_sample.csv")
    for registro in registros:
        assert registro.unsw_row_id.startswith("unsw_nb15_raw_sample.csv:")
        assert registro.event.event_id == registro.unsw_row_id
        assert registro.event.properties["unsw_row_id"] == registro.unsw_row_id


def test_row_ids_are_unique():
    registros = load(FIXTURES / "unsw_nb15_raw_sample.csv")
    assert len({r.unsw_row_id for r in registros}) == len(registros)


def test_unmapped_columns_are_preserved_not_discarded():
    """Lo que el esquema no modela se conserva; no se pierde información."""
    registro = load(FIXTURES / "unsw_nb15_raw_sample.csv")[0]
    propiedades = registro.event.properties
    assert "duration_s" in propiedades
    assert any(k in propiedades for k in ("swin", "stcpb", "sjit"))
    # Y la fila original completa sigue accesible.
    assert registro.event.raw["srcip"] == "59.166.0.0"


def test_labels_are_only_ground_truth_never_features():
    """
    La etiqueta viaja fuera del evento: si estuviera en `properties` podría
    filtrarse a las características y contaminar la evaluación.
    """
    registro = load(FIXTURES / "unsw_nb15_raw_sample.csv")[1]
    assert registro.label == 1
    assert "label" not in registro.event.properties
    assert "attack_cat" not in registro.event.properties


# --------------------------------- varios -----------------------------------
def test_limit_is_respected():
    assert len(load(FIXTURES / "unsw_nb15_raw_sample.csv", limit=2)) == 2


def test_field_mapping_is_documented_for_the_report():
    """El mapeo se exporta en los metadatos: debe estar completo."""
    for columna in ("srcip", "dstip", "sbytes", "dbytes", "stime", "label"):
        assert columna in FIELD_MAPPING


def test_file_hash_is_stable():
    ruta = FIXTURES / "unsw_nb15_raw_sample.csv"
    assert file_sha256(ruta) == file_sha256(ruta)
    assert len(file_sha256(ruta)) == 64


def test_bom_does_not_contaminate_the_first_value():
    """
    `UNSW-NB15_1.csv` empieza con un BOM UTF-8. Como ese archivo no tiene
    cabecera, el BOM queda pegado al primer valor de datos: sin limpiarlo, la
    primera IP de origen del archivo seria '\ufeff59.166.0.0'.
    """
    adapter = UNSWNB15Adapter()
    registro = adapter.to_record(
        {"srcip": "\ufeff59.166.0.0", "dsport": "53", "label": "0"}, "prueba:1"
    )
    assert registro.event.src_ip == "59.166.0.0"


def test_adapter_handles_hexadecimal_ports():
    """UNSW-NB15 escribe algunos puertos en hexadecimal."""
    adapter = UNSWNB15Adapter()
    registro = adapter.to_record(
        {"srcip": "10.0.0.1", "dsport": "0x20", "sbytes": "100", "label": "0"},
        "prueba:1",
    )
    assert registro.event.dst_port == 32


def test_adapter_survives_missing_fields():
    """Una fila incompleta no puede tumbar la carga de 2.5 millones."""
    registro = UNSWNB15Adapter().to_record({"label": "1"}, "prueba:1")
    assert registro.label == 1
    assert registro.event.bytes_out is None
    assert "ip_addresses" in registro.unavailable


@pytest.mark.skipif(
    not (ROOT / "data" / "unsw_nb15" / "UNSW_NB15_training-set.csv").exists(),
    reason="el dataset oficial no está descargado",
)
def test_official_training_set_has_the_published_row_count():
    """Control contra la cifra que publica UNSW: 175 341 registros."""
    ruta = ROOT / "data" / "unsw_nb15" / "UNSW_NB15_training-set.csv"
    filas = sum(1 for _ in open(ruta, encoding="utf-8", errors="replace")) - 1
    assert filas == 175_341
