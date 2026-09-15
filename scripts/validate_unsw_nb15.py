"""
Validación del dataset oficial UNSW-NB15 antes de usarlo.

Comprueba lo que hay que comprobar antes de confiar en unos datos: archivos
presentes, tamaños, filas, columnas, etiquetas, valores faltantes, duplicados y
distribución normal/ataque. Contrasta además los conteos con los que publica
UNSW, para detectar una descarga incompleta o un archivo corrupto.

    python scripts/validate_unsw_nb15.py
"""
from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cybersentinel.data.unsw_nb15_adapter import file_sha256  # noqa: E402

DATA_DIR = ROOT / "data" / "unsw_nb15"
RESULTS_DIR = ROOT / "results"

#: Conteos publicados en la pagina oficial de UNSW. Sirven de control: si no
#: cuadran, la descarga esta incompleta o el archivo no es el que dice ser.
EXPECTED = {
    "UNSW_NB15_training-set.csv": 175_341,
    "UNSW_NB15_testing-set.csv": 82_332,
}
EXPECTED_TOTAL_RAW = 2_540_044


def describe_csv(path: Path, has_header: bool | None = None) -> dict:
    """Recorre el archivo una vez y recoge todo lo que hay que reportar."""
    filas = 0
    columnas: list[str] = []
    etiquetas: Counter[str] = Counter()
    categorias: Counter[str] = Counter()
    vacios = 0
    celdas = 0
    huellas: set[int] = set()
    duplicados = 0

    with open(path, "r", encoding="utf-8", errors="replace", newline="") as fh:
        lector = csv.reader(fh)
        try:
            primera = next(lector)
        except StopIteration:
            return {"file": path.name, "rows": 0, "error": "archivo vacio"}

        nombres = {c.strip().lstrip("﻿").lower() for c in primera}
        cabecera = has_header if has_header is not None else (
            "label" in nombres or "attack_cat" in nombres or "dur" in nombres
        )
        if cabecera:
            columnas = [c.strip().lstrip("﻿") for c in primera]
            iterador = lector
        else:
            from cybersentinel.data.unsw_nb15_adapter import RAW_COLUMNS
            columnas = list(RAW_COLUMNS)
            iterador = iter([primera, *lector])

        idx_label = next(
            (i for i, c in enumerate(columnas) if c.strip().lower() == "label"), None
        )
        idx_cat = next(
            (i for i, c in enumerate(columnas) if c.strip().lower() == "attack_cat"), None
        )

        for valores in iterador:
            if not valores or not any(valores):
                continue
            filas += 1
            celdas += len(valores)
            vacios += sum(1 for v in valores if v.strip() in ("", "-"))

            if idx_label is not None and idx_label < len(valores):
                etiquetas[valores[idx_label].strip() or "?"] += 1
            if idx_cat is not None and idx_cat < len(valores):
                cat = valores[idx_cat].strip() or "Normal"
                categorias[cat] += 1

            # Duplicados exactos: se guarda un hash para no retener el dataset.
            huella = hash(tuple(valores))
            if huella in huellas:
                duplicados += 1
            else:
                huellas.add(huella)

    return {
        "file": path.name,
        "size_bytes": path.stat().st_size,
        "size_mb": round(path.stat().st_size / 1024 / 1024, 1),
        "sha256": file_sha256(path),
        "has_header": cabecera,
        "rows": filas,
        "n_columns": len(columnas),
        "columns": columnas,
        "label_distribution": dict(etiquetas),
        "attack_categories": dict(categorias.most_common()),
        "empty_cells": vacios,
        "empty_cell_ratio": round(vacios / celdas, 6) if celdas else 0.0,
        "exact_duplicate_rows": duplicados,
    }


def main() -> int:
    if not DATA_DIR.exists():
        print(f"No existe {DATA_DIR}")
        return 1

    archivos = sorted(DATA_DIR.glob("*.csv"))
    if not archivos:
        print(f"No hay CSV en {DATA_DIR}")
        return 1

    print(f"Validando {len(archivos)} archivo(s) en {DATA_DIR}\n")
    informe = {"data_dir": str(DATA_DIR), "files": []}
    total_raw = 0

    for path in archivos:
        if path.name in ("NUSW-NB15_features.csv", "UNSW-NB15_LIST_EVENTS.csv"):
            # Metadatos del dataset, no registros de trafico.
            info = {
                "file": path.name, "size_bytes": path.stat().st_size,
                "sha256": file_sha256(path),
                "rows": sum(1 for _ in open(path, encoding="utf-8", errors="replace")) - 1,
                "role": "metadatos",
            }
            informe["files"].append(info)
            print(f"  {path.name:34s} {info['rows']:>9,} filas  (metadatos)")
            continue

        info = describe_csv(path)
        informe["files"].append(info)

        esperado = EXPECTED.get(path.name)
        marca = ""
        if esperado:
            marca = " OK" if info["rows"] == esperado else f" DISCREPA (esperado {esperado:,})"
            info["expected_rows"] = esperado
            info["rows_match_official"] = info["rows"] == esperado
        if path.name.startswith("UNSW-NB15_") and path.name[10:11].isdigit():
            total_raw += info["rows"]

        print(f"  {path.name:34s} {info['rows']:>9,} filas  {info['n_columns']:>2} cols  "
              f"{info['size_mb']:>6.1f} MB{marca}")
        if info.get("label_distribution"):
            print(f"      etiquetas: {info['label_distribution']}")
        if info.get("attack_categories"):
            top = list(info["attack_categories"].items())[:6]
            print(f"      categorias: {top}")
        print(f"      celdas vacias: {info['empty_cells']:,} "
              f"({info['empty_cell_ratio']:.4%})   duplicados exactos: "
              f"{info['exact_duplicate_rows']:,}")

    if total_raw:
        informe["raw_total_rows"] = total_raw
        informe["raw_total_expected"] = EXPECTED_TOTAL_RAW
        informe["raw_total_match"] = total_raw == EXPECTED_TOTAL_RAW
        estado = "OK" if total_raw == EXPECTED_TOTAL_RAW else "DISCREPA"
        print(f"\n  Total CSV crudos: {total_raw:,} registros "
              f"(oficial: {EXPECTED_TOTAL_RAW:,}) -> {estado}")

    RESULTS_DIR.mkdir(exist_ok=True)
    destino = RESULTS_DIR / "unsw_nb15_validation.json"
    destino.write_text(json.dumps(informe, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nInforme: {destino}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
