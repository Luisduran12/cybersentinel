"""
Pruebas de la evaluación cuantitativa del detector (Fase 4).

Lo que verifican, en orden de importancia: que el protocolo sea correcto (ningún
ataque se cuela en el entrenamiento, nada se mide sobre datos ya vistos), que las
métricas estén bien calculadas, y que el desglose por familia exista — porque un
F1 global puede esconder que una familia entera no se detecta nunca.
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "data"))

import generate_flow_sample  # noqa: E402
from cybersentinel.detection.evaluation import (  # noqa: E402
    ConfusionMatrix, evaluate_anomaly_detector, save_curves, split_benign_for_training,
)
from cybersentinel.ingestion.datasets import LabeledEvent, load_dataset  # noqa: E402
from cybersentinel.schema import SecurityEvent  # noqa: E402

BASE = datetime(2025, 3, 10, 12, tzinfo=timezone.utc)


def _labeled(index: int, label: int, category: str = "Normal", **kwargs) -> LabeledEvent:
    event = SecurityEvent(
        str(index), BASE + timedelta(seconds=index), "netflow", "network", "network_flow",
        src_ip=f"10.0.0.{index % 50}", dst_port=kwargs.pop("dst_port", 443),
        bytes_out=kwargs.pop("bytes_out", 1000), bytes_in=kwargs.pop("bytes_in", 5000),
        **kwargs,
    )
    return LabeledEvent(event=event, label=label, category=category)


# --------------------------- matriz de confusión ----------------------------
def test_confusion_matrix_metrics():
    matriz = ConfusionMatrix(true_positives=80, false_positives=20,
                             true_negatives=880, false_negatives=20)
    assert matriz.precision == pytest.approx(0.8)
    assert matriz.recall == pytest.approx(0.8)
    assert matriz.f1 == pytest.approx(0.8)
    assert matriz.false_positive_rate == pytest.approx(20 / 900)


def test_confusion_matrix_without_predictions_does_not_divide_by_zero():
    vacia = ConfusionMatrix(0, 0, 100, 10)
    assert vacia.precision == 0.0
    assert vacia.recall == 0.0
    assert vacia.f1 == 0.0


# ------------------------------- protocolo ----------------------------------
def test_training_set_contains_no_attacks():
    """
    Es la condición que hace válida toda la evaluación: si los ataques entran en
    la línea base, el modelo los aprende como normalidad.
    """
    datos = [_labeled(i, 0) for i in range(100)] + [_labeled(i, 1, "DoS") for i in range(100, 120)]
    train, test = split_benign_for_training(datos, train_ratio=0.5)

    assert all(item.label == 0 for item in train)
    assert sum(item.label for item in test) == 20


def test_every_attack_goes_to_the_evaluation_set():
    datos = [_labeled(i, 0) for i in range(50)] + [_labeled(i, 1, "DoS") for i in range(50, 70)]
    _, test = split_benign_for_training(datos, train_ratio=0.8)
    assert sum(item.label for item in test) == 20


def test_training_and_evaluation_sets_are_disjoint():
    """Medir sobre datos ya vistos no mide nada."""
    datos = [_labeled(i, 0) for i in range(100)] + [_labeled(i, 1) for i in range(100, 110)]
    train, test = split_benign_for_training(datos, train_ratio=0.5)
    assert not {id(i.event) for i in train} & {id(i.event) for i in test}
    assert len(train) + len(test) == len(datos)


def test_split_is_reproducible_with_the_seed():
    datos = [_labeled(i, 0) for i in range(80)] + [_labeled(i, 1) for i in range(80, 90)]
    primera, _ = split_benign_for_training(datos, seed=7)
    segunda, _ = split_benign_for_training(datos, seed=7)
    assert [i.event.event_id for i in primera] == [i.event.event_id for i in segunda]


def test_evaluation_refuses_a_dataset_without_benign_traffic():
    solo_ataques = [_labeled(i, 1) for i in range(20)]
    with pytest.raises(ValueError, match="No hay suficientes eventos"):
        evaluate_anomaly_detector(solo_ataques)


# -------------------------------- métricas ----------------------------------
@pytest.fixture(scope="module")
def evaluacion(tmp_path_factory):
    """Una evaluación completa sobre flujos sintéticos, reutilizada por varias pruebas."""
    ruta = tmp_path_factory.mktemp("flows") / "flows.csv"
    generate_flow_sample.generate(ruta, n_benign=1200, n_attacks=150, seed=11)
    datos = load_dataset("unsw-nb15", ruta)
    return evaluate_anomaly_detector(datos, dataset="prueba")


def test_metrics_are_within_range(evaluacion):
    c = evaluacion.confusion
    for valor in (c.precision, c.recall, c.f1, c.false_positive_rate,
                  evaluacion.roc_auc, evaluacion.pr_auc):
        assert 0.0 <= valor <= 1.0


def test_confusion_matrix_accounts_for_every_evaluated_event(evaluacion):
    c = evaluacion.confusion
    total = c.true_positives + c.false_positives + c.true_negatives + c.false_negatives
    assert total == evaluacion.n_test
    assert c.true_positives + c.false_negatives == evaluacion.n_test_attacks


def test_detector_beats_random_guessing(evaluacion):
    """Un AUC de 0.5 es azar; por debajo, el detector estaría invertido."""
    assert evaluacion.roc_auc > 0.6
    assert evaluacion.pr_auc > evaluacion.attack_ratio


def test_recall_is_reported_per_attack_family(evaluacion):
    """Un F1 global aceptable puede esconder una familia que nunca se detecta."""
    familias = {c.category for c in evaluacion.per_category}
    assert {"Reconnaissance", "Exploits", "Exfiltration"} <= familias
    for categoria in evaluacion.per_category:
        assert 0 <= categoria.detected <= categoria.total
        assert categoria.total > 0


def test_category_totals_match_the_attack_count(evaluacion):
    assert sum(c.total for c in evaluacion.per_category) == evaluacion.n_test_attacks


def test_threshold_sweep_trades_precision_for_recall(evaluacion):
    """Subir el umbral no puede aumentar la exhaustividad."""
    barrido = evaluacion.threshold_sweep
    assert len(barrido) >= 5
    recalls = [fila["recall"] for fila in barrido]
    umbrales = [fila["threshold"] for fila in barrido]
    assert umbrales == sorted(umbrales)
    assert recalls == sorted(recalls, reverse=True)


def test_report_is_serializable(evaluacion):
    reporte = evaluacion.to_dict()
    assert reporte["protocol"]["training"] == "solo eventos benignos"
    assert "roc_auc" in reporte["metrics"]
    assert reporte["per_category_recall"]
    assert reporte["roc_points"] and reporte["pr_points"]


def test_curves_are_subsampled_for_the_report(evaluacion):
    """La curva completa tiene miles de puntos; el reporte no los necesita."""
    assert len(evaluacion.roc_points) <= 200
    assert len(evaluacion.pr_points) <= 200


def test_a_fixed_threshold_overrides_the_suggested_one():
    datos = [_labeled(i, 0) for i in range(200)] + [
        _labeled(i, 1, "Exfiltration", bytes_out=500_000_000, dst_port=4444)
        for i in range(200, 240)
    ]
    evaluacion = evaluate_anomaly_detector(datos, threshold=0.55)
    assert evaluacion.threshold == pytest.approx(0.55)


# -------------------------------- figuras -----------------------------------
def test_curves_are_written_to_a_png(evaluacion, tmp_path):
    pytest.importorskip("matplotlib")
    destino = save_curves(evaluacion, tmp_path / "curvas.png")
    assert destino is not None and destino.exists()
    assert destino.stat().st_size > 5000


def test_missing_matplotlib_does_not_break_the_evaluation(evaluacion, tmp_path, monkeypatch):
    """La figura es opcional: sin matplotlib la evaluación sigue siendo válida."""
    monkeypatch.setitem(sys.modules, "matplotlib", None)
    assert save_curves(evaluacion, tmp_path / "curvas.png") is None
