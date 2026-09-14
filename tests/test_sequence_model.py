"""
Pruebas del modelo de predicción de kill-chain (Fase 3).

Cubren tres cosas: que la cadena de Markov aprende lo que dice aprender, que la
evaluación mide lo que dice medir, y que el correlador ya no predice hacia atrás.
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "data"))

import generate_campaigns as campaigns  # noqa: E402
from cybersentinel.correlation import evaluation, mitre  # noqa: E402
from cybersentinel.correlation.correlator import Correlator, Finding  # noqa: E402
from cybersentinel.correlation.sequence_model import (  # noqa: E402
    END_STATE, CanonicalBaseline, MarkovChainModel, sequences_from_incidents,
)
from cybersentinel.schema import SecurityEvent, Severity  # noqa: E402

BASE = datetime(2025, 3, 10, 10, tzinfo=timezone.utc)


def _finding(tactic: str, technique: str, minutes: int) -> Finding:
    event = SecurityEvent("e", BASE + timedelta(minutes=minutes), "firewall",
                          "network", "connection", host="SRV")
    return Finding("rule", event, Severity.HIGH, 0.8, technique, tactic, "titulo")


# ------------------------------ cadena de Markov ----------------------------
def test_markov_learns_a_deterministic_corpus():
    """Si en el corpus A siempre lleva a B, la predicción tras A debe ser B."""
    corpus = [["execution", "persistence", "discovery"]] * 20
    top, probability = MarkovChainModel().fit(corpus).predict_next(["execution"], k=1)[0]
    assert top == "persistence"
    assert probability > 0.7


def test_smoothing_trades_confidence_for_robustness():
    """
    Con alpha alto el modelo nunca está seguro del todo, aunque el corpus sea
    determinista: es el precio de no asignar probabilidad cero a lo no visto.
    """
    corpus = [["execution", "persistence", "discovery"]] * 20
    conservador = MarkovChainModel(alpha=0.5).fit(corpus).predict_next(["execution"], k=1)
    confiado = MarkovChainModel(alpha=0.01).fit(corpus).predict_next(["execution"], k=1)
    assert confiado[0][1] > conservador[0][1]
    assert confiado[0][1] > 0.95


def test_laplace_smoothing_keeps_unseen_transitions_possible():
    """Una transición nunca vista no puede tener probabilidad cero."""
    model = MarkovChainModel(alpha=0.5).fit([["execution", "persistence"]] * 10)
    probabilities = model.transition_probabilities("execution")
    assert probabilities["impact"] > 0
    assert probabilities["persistence"] > probabilities["impact"]


def test_transition_probabilities_form_a_distribution():
    """Cada fila de la matriz de transición suma 1 (incluyendo el estado final)."""
    sequences, _ = campaigns.generate_sequences(n=100, seed=3)
    model = MarkovChainModel().fit(sequences)
    for tactic in mitre.TACTIC_ORDER:
        assert model.transition_probabilities(tactic)[END_STATE] >= 0
        assert sum(model.transition_probabilities(tactic).values()) == pytest.approx(1.0)


def test_predictions_are_raw_conditional_probabilities():
    """
    Lo devuelto es la probabilidad que sale de la matriz, sin renormalizar: la
    masa que falta está en `<END>` y en las fases descartadas. Renormalizar daría
    un 100% engañoso cuando solo queda una candidata.
    """
    sequences, _ = campaigns.generate_sequences(n=200, seed=3)
    model = MarkovChainModel().fit(sequences)
    ranked = model.predict_next(["initial-access"], k=len(mitre.TACTIC_ORDER))

    fila = model.transition_probabilities("initial-access")
    for tactic, probability in ranked:
        assert probability == pytest.approx(fila[tactic])
    assert sum(p for _, p in ranked) <= 1.0
    assert all(p1 >= p2 for (_, p1), (_, p2) in zip(ranked, ranked[1:]))


def test_probabilities_and_end_probability_are_consistent():
    """La probabilidad de detenerse sale de la misma fila de la matriz."""
    sequences, _ = campaigns.generate_sequences(n=200, seed=3)
    model = MarkovChainModel().fit(sequences)
    history = ["exfiltration"]
    total = sum(p for _, p in model.predict_next(history, k=14))
    assert total + model.probability_of_end(history) <= 1.0 + 1e-9


def test_already_observed_tactics_are_not_predicted():
    """Proponer una fase que el incidente ya atravesó no aporta nada."""
    sequences, _ = campaigns.generate_sequences(n=200, seed=3)
    model = MarkovChainModel().fit(sequences)
    history = ["initial-access", "execution", "persistence"]
    predicted = [t for t, _ in model.predict_next(history, k=5)]
    assert not set(predicted) & set(history)


def test_conditioning_state_changes_with_the_mode():
    """`deepest` toma la fase más avanzada; `last` la última en el tiempo."""
    corpus, _ = campaigns.generate_sequences(n=200, seed=3)
    history = ["exfiltration", "credential-access"]

    deepest = MarkovChainModel(condition_on="deepest").fit(corpus)
    last = MarkovChainModel(condition_on="last").fit(corpus)

    assert deepest.predict_next(history, k=1)[0][0] == "impact"
    assert last.predict_next(history, k=1)[0][0] != "impact"


def test_monotonic_constraint_blocks_predicting_a_past_phase():
    """
    Con la fase actual ya terminal, casi toda la probabilidad se va a `<END>` y
    el resto queda repartido por el suavizado: sin la restricción monótona el
    modelo propone una fase anterior, que es el bug §4 por otra vía.
    """
    corpus, _ = campaigns.generate_sequences(n=200, seed=3)
    history = ["exfiltration"]
    frontier = mitre.tactic_index("exfiltration")

    sin_restriccion = MarkovChainModel(monotonic=False).fit(corpus)
    con_restriccion = MarkovChainModel(monotonic=True).fit(corpus)

    hacia_atras = [
        t for t, _ in sin_restriccion.predict_next(history, k=3)
        if mitre.tactic_index(t) < frontier
    ]
    assert hacia_atras, "el escenario debe reproducir la prediccion hacia atras"
    assert all(
        mitre.tactic_index(t) > frontier
        for t, _ in con_restriccion.predict_next(history, k=3)
    )


def test_model_survives_a_save_load_round_trip(tmp_path):
    sequences, _ = campaigns.generate_sequences(n=120, seed=5)
    model = MarkovChainModel().fit(sequences)
    path = model.save(tmp_path / "markov.json")

    restored = MarkovChainModel.load(path)
    assert restored.n_sequences == model.n_sequences
    assert restored.predict_next(["execution"], k=3) == model.predict_next(["execution"], k=3)


def test_unfitted_model_predicts_nothing():
    """Sin entrenar no se inventa predicciones."""
    assert MarkovChainModel().predict_next(["execution"]) == []


def test_sequences_from_incidents_reads_the_tactics():
    correlator = Correlator()
    incidents = correlator.correlate([
        _finding("execution", "T1059", 0), _finding("persistence", "T1053", 5),
    ])
    assert sequences_from_incidents(incidents) == [["execution", "persistence"]]


# ------------------------------ línea base ----------------------------------
def test_canonical_baseline_follows_the_attack_chain_order():
    predicted = [t for t, _ in CanonicalBaseline().predict_next(["credential-access"], k=2)]
    assert predicted == ["discovery", "lateral-movement"]


def test_canonical_baseline_has_nothing_after_impact():
    assert CanonicalBaseline().predict_next(["impact"], k=2) == []


# ------------------------------ evaluación ----------------------------------
def test_build_examples_creates_one_example_per_prefix():
    examples = evaluation.build_examples([["a", "b", "c", "d"]])
    assert [e.expected for e in examples] == ["b", "c", "d"]
    assert examples[1].history == ["a", "b"]


def test_precision_at_3_is_never_worse_than_at_1():
    sequences, labels = campaigns.generate_sequences(n=150, seed=11)
    train, _, test, test_labels = campaigns.train_test_split(sequences, labels, seed=11)
    examples = evaluation.build_examples(test, test_labels)
    result = evaluation.evaluate(MarkovChainModel().fit(train), examples, ks=(1, 3))
    assert result.precision_at[3] >= result.precision_at[1]
    assert 0.0 <= result.precision_at[1] <= 1.0


def test_markov_beats_the_canonical_heuristic():
    """
    La afirmación central de la Fase 3, sujeta a prueba automática.

    Si un cambio futuro la rompe, la suite lo dice: es el número que sostiene
    que el modelo entrenable aporta algo sobre la heurística.
    """
    sequences, labels = campaigns.generate_sequences(n=400, seed=7)
    train, _, test, test_labels = campaigns.train_test_split(sequences, labels, seed=7)
    examples = evaluation.build_examples(test, test_labels)

    results = evaluation.compare(
        {"baseline": CanonicalBaseline(), "markov": MarkovChainModel().fit(train)},
        examples,
    )
    assert results["markov"].precision_at[1] > results["baseline"].precision_at[1]
    assert results["markov"].precision_at[3] > results["baseline"].precision_at[3]


def test_evaluation_reports_a_square_confusion_matrix():
    sequences, labels = campaigns.generate_sequences(n=200, seed=13)
    train, _, test, test_labels = campaigns.train_test_split(sequences, labels, seed=13)
    result = evaluation.evaluate(
        MarkovChainModel().fit(train), evaluation.build_examples(test, test_labels)
    )
    size = len(result.labels)
    assert len(result.confusion) == size
    assert all(len(row) == size for row in result.confusion)
    assert sum(sum(row) for row in result.confusion) == result.n_answered


# --------------------- integración con el correlador ------------------------
def test_prediction_never_goes_backwards():
    """
    Regresión del bug detectado en la revisión: con exfiltración ya observada,
    el sistema predecía 'descubrimiento' como fase siguiente.
    """
    incident = Correlator().correlate([
        _finding("exfiltration", "T1048", 0),
        _finding("credential-access", "T1110", 5),
    ])[0]
    prediction = incident.prediction

    assert prediction.current_tactic == "exfiltration"
    deepest = mitre.tactic_index("exfiltration")
    for tactic in prediction.predicted_next:
        assert mitre.tactic_index(tactic) > deepest


def test_correlator_uses_the_injected_model():
    """El modelo es intercambiable y el incidente registra cuál se usó."""
    sequences, _ = campaigns.generate_sequences(n=200, seed=17)
    model = MarkovChainModel().fit(sequences)
    incident = Correlator(sequence_model=model).correlate([
        _finding("initial-access", "T1078", 0), _finding("execution", "T1059", 5),
    ])[0]

    assert incident.prediction.model_name == "markov-orden-1"
    assert incident.prediction.confidence_basis.startswith("probabilidad estimada")
    assert incident.prediction.probabilities
    assert incident.prediction.confidence == pytest.approx(
        incident.prediction.probabilities[0]
    )


def test_default_correlator_still_uses_the_heuristic():
    """Sin modelo entrenado, el comportamiento histórico se conserva."""
    incident = Correlator().correlate([_finding("execution", "T1059", 0)])[0]
    assert incident.prediction.model_name == "heuristica-canonica"
    assert incident.prediction.confidence_basis.startswith("heuristica")


def test_pipeline_loads_a_trained_model_from_settings(tmp_path):
    """El pipeline toma el modelo de la configuración, sin tocar código."""
    from cybersentinel.config import Settings
    from cybersentinel.pipeline import Pipeline

    sequences, _ = campaigns.generate_sequences(n=150, seed=19)
    model_path = MarkovChainModel().fit(sequences).save(tmp_path / "markov.json")

    settings = Settings()
    settings.prediction.model_path = str(model_path)
    pipeline = Pipeline(rules_dir=ROOT / "config" / "rules",
                        audit_path=tmp_path / "audit.jsonl", settings=settings)

    assert pipeline.correlator.sequence_model.name == "markov-orden-1"


def test_pipeline_falls_back_when_the_model_is_missing(tmp_path):
    """Un modelo inexistente no puede impedir un análisis."""
    from cybersentinel.config import Settings
    from cybersentinel.pipeline import Pipeline

    settings = Settings()
    settings.prediction.model_path = str(tmp_path / "no-existe.json")
    pipeline = Pipeline(rules_dir=ROOT / "config" / "rules",
                        audit_path=tmp_path / "audit.jsonl", settings=settings)

    assert pipeline.correlator.sequence_model.name == "heuristica-canonica"


# ------------------------------ generador -----------------------------------
def test_campaign_generation_is_reproducible():
    assert campaigns.generate_sequences(n=50, seed=1) == campaigns.generate_sequences(n=50, seed=1)


def test_campaigns_have_no_repeated_tactics():
    """El corpus debe tener la misma forma que `Incident.tactics`, que deduplica."""
    sequences, _ = campaigns.generate_sequences(n=200, seed=2)
    for sequence in sequences:
        assert len(sequence) == len(set(sequence))


def test_train_test_split_is_disjoint_and_complete():
    sequences, labels = campaigns.generate_sequences(n=100, seed=4)
    train, train_l, test, test_l = campaigns.train_test_split(sequences, labels, test_ratio=0.3)
    assert len(train) + len(test) == len(sequences)
    assert len(train_l) == len(train) and len(test_l) == len(test)
    assert abs(len(test) / len(sequences) - 0.3) < 0.02
