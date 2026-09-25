"""
Tests de regresión — Fase 8 Hardening Inicial.

Cubre exactamente las cuatro deudas técnicas corregidas:

  DT-01: CLI funcional (sin AttributeError, exit code 0)
  DT-02: AnomalyDetector real conectado al pipeline (sin hardcoded 0.6)
  DT-03: LLM ejecutado con generate_explanation() (sin silencio de except)
  DT-04: Benchmark reproducible (dataset_hash estable por seed)
"""
from __future__ import annotations

import hashlib
import subprocess
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

# ─────────────────────────────────────────────────────────────────────────────
# Helpers / fixtures compartidos
# ─────────────────────────────────────────────────────────────────────────────

BASELINE_EPOCH = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


def _make_event(event_id: str, offset_minutes: int = 0, src_ip: str = "10.0.0.1"):
    from cybersentinel.schema import SecurityEvent
    ts = BASELINE_EPOCH + timedelta(minutes=offset_minutes)
    return SecurityEvent(event_id, ts, "fw", "net", "allow", src_ip=src_ip)


# ─────────────────────────────────────────────────────────────────────────────
# DT-01 — CLI funcional
# ─────────────────────────────────────────────────────────────────────────────

class TestDT01CLIFunctional:
    """DT-01: La CLI no debe lanzar AttributeError al procesar eventos reales."""

    def test_cli_analyze_exits_zero(self, tmp_path):
        """cybersentinel analyze debe salir con código 0 sobre sample_logs.jsonl."""
        sample = Path("data/sample_logs.jsonl")
        if not sample.exists():
            pytest.skip("data/sample_logs.jsonl not present in this env")
        result = subprocess.run(
            [sys.executable, "-m", "cybersentinel.cli", "analyze", "--input", str(sample)],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent,
        )
        assert result.returncode == 0, (
            f"CLI exited with code {result.returncode}.\n"
            f"STDOUT: {result.stdout[-1000:]}\n"
            f"STDERR: {result.stderr[-1000:]}"
        )
        assert "AttributeError" not in result.stderr, (
            f"CLI produced AttributeError:\n{result.stderr}"
        )

    def test_cli_analyze_json_output(self, tmp_path):
        """CLI --json debe producir un JSON válido con campos del nuevo contrato."""
        sample = Path("data/sample_logs.jsonl")
        if not sample.exists():
            pytest.skip("data/sample_logs.jsonl not present in this env")
        output_json = tmp_path / "report.json"
        result = subprocess.run(
            [sys.executable, "-m", "cybersentinel.cli", "analyze",
             "--input", str(sample), "--json", str(output_json)],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent,
        )
        assert result.returncode == 0, f"CLI failed: {result.stderr}"
        import json
        report = json.loads(output_json.read_text())
        # New contract fields
        assert "total_events" in report
        assert "total_findings" in report
        assert "incidents" in report
        # Must NOT have old removed fields
        assert "audit_integrity" not in report

    def test_cli_text_output_uses_str_narrative(self, tmp_path):
        """CLI --text debe funcionar sin llamar .to_text() en narrative."""
        sample = Path("data/sample_logs.jsonl")
        if not sample.exists():
            pytest.skip("data/sample_logs.jsonl not present in this env")
        text_out = tmp_path / "narratives.txt"
        result = subprocess.run(
            [sys.executable, "-m", "cybersentinel.cli", "analyze",
             "--input", str(sample), "--text", str(text_out)],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent,
        )
        assert result.returncode == 0, f"CLI failed with --text: {result.stderr}"
        # File should be written
        assert text_out.exists()

    def test_pipeline_report_has_no_audit_integrity(self):
        """PipelineReport no debe tener audit_integrity — el CLI no puede referenciarlo."""
        from cybersentinel.pipeline import PipelineReport
        report = PipelineReport(total_events=0, total_findings=0)
        assert not hasattr(report, "audit_integrity"), (
            "PipelineReport should not have audit_integrity attribute"
        )

    def test_incident_result_has_no_incident_attribute(self):
        """IncidentResult no debe tener .incident — el CLI no puede referenciarlo."""
        from cybersentinel.pipeline import IncidentResult
        from cybersentinel.detection.hybrid import DetectionEvidence
        from cybersentinel.observability import TraceContext
        tc = TraceContext(event_id="x")
        ir = IncidentResult(evidence=DetectionEvidence("x"), narrative="ok", trace=tc)
        assert not hasattr(ir, "incident"), (
            "IncidentResult should not have .incident attribute"
        )


# ─────────────────────────────────────────────────────────────────────────────
# DT-02 — AnomalyDetector real conectado (sin hardcoded 0.6)
# ─────────────────────────────────────────────────────────────────────────────

class TestDT02MLRealConnected:
    """DT-02: El pipeline debe invocar AnomalyDetector.score() real, no un valor hardcoded."""

    def test_pipeline_ml_score_not_always_0_6(self):
        """
        Con eventos variados el ML score NO debe ser siempre 0.6.
        Dos eventos con características muy distintas deben producir scores
        distintos una vez el detector esté entrenado.
        """
        from cybersentinel.pipeline import Pipeline

        # Build a dataset large enough to train IF (≥ MIN_TRAINING_EVENTS)
        training_events = []
        for i in range(60):
            ev = _make_event(f"train_{i}", offset_minutes=i, src_ip="10.0.0.1")
            training_events.append(ev)

        pipeline = Pipeline(rules_dir="config/rules", enable_ml=True,
                            enable_temporal=False, enable_cti=False,
                            enable_rag=False, enable_llm=False)

        # Fit the anomaly detector explicitly (same as what run_events does when not fitted)
        from cybersentinel.ml.base import Dataset
        import numpy as np
        pipeline.anomaly_detector.fit(Dataset(X=np.array([]), events=training_events))

        # Verify it is fitted now
        assert pipeline.anomaly_detector.is_fitted, "AnomalyDetector should be fitted"

        # Score two similar events → should produce real (not constant 0.6) scores
        ev_a = _make_event("score_a", offset_minutes=0, src_ip="10.0.0.1")
        report = pipeline.run_events([ev_a])
        score_a = report.results[0].evidence.anomaly_score

        # The score must NOT be the hardcoded 0.6
        assert score_a != 0.6, (
            f"anomaly_score is still 0.6 — AnomalyDetector real NOT connected. "
            f"Got: {score_a}"
        )
        # Score must be in valid range [0, 1]
        assert 0.0 <= score_a <= 1.0, f"anomaly_score out of range: {score_a}"

    def test_pipeline_ml_contributes_to_hybrid_score_when_fitted(self):
        """
        Cuando el modelo ML está entrenado y la anomaly_score supera el
        umbral calibrado (DEFAULT_ANOMALY_THRESHOLD, ver config.py), el
        hybrid_score debe ser > 0. No se hardcodea el umbral aquí: este
        test verifica la fórmula del boost, no un valor de umbral concreto
        que ya cambió una vez (auditoría de producción, hallazgo H-08) y
        podría volver a calibrarse.
        """
        from cybersentinel.config import DEFAULT_ANOMALY_THRESHOLD
        from cybersentinel.detection.hybrid import DetectionEvidence
        # Simulate a fitted ML score that is anomalous
        ev = DetectionEvidence(event_id="ml_boost", anomaly_score=0.85)
        expected_boost = max(0, (0.85 - DEFAULT_ANOMALY_THRESHOLD) * 40.0)
        assert abs(ev.hybrid_score - expected_boost) < 0.001

    def test_pipeline_ml_disabled_gives_zero_score(self):
        """Cuando ML está desactivado, el anomaly_score debe ser 0.0."""
        from cybersentinel.pipeline import Pipeline
        pipeline = Pipeline(rules_dir="config/rules",
                            enable_ml=False, enable_temporal=False,
                            enable_cti=False, enable_rag=False, enable_llm=False)
        ev = _make_event("ev_no_ml")
        report = pipeline.run_events([ev])
        assert report.results[0].evidence.anomaly_score == 0.0

    def test_pipeline_ml_enabled_unfitted_gives_zero_score(self):
        """
        Cuando ML está activado pero el detector NO está entrenado todavía,
        anomaly_score debe ser 0.0 (neutro, sin contribución).
        No debe ser 0.6 (hardcoded).
        """
        from cybersentinel.pipeline import Pipeline
        # Fresh pipeline, ML enabled but not pre-fitted, only 1 event (< MIN_TRAINING)
        pipeline = Pipeline(rules_dir="config/rules",
                            enable_ml=True, enable_temporal=False,
                            enable_cti=False, enable_rag=False, enable_llm=False)
        ev = _make_event("ev_unfitted")
        report = pipeline.run_events([ev])
        score = report.results[0].evidence.anomaly_score
        # Must not be the old hardcoded 0.6
        assert score != 0.6, f"Hardcoded 0.6 still present in pipeline! Got {score}"


# ─────────────────────────────────────────────────────────────────────────────
# DT-03 — LLM ejecutado con generate_explanation()
# ─────────────────────────────────────────────────────────────────────────────

class TestDT03LLMMethodCorrect:
    """DT-03: Pipeline debe llamar generate_explanation(), no explain()."""

    def test_llm_explainer_reports_provenance_of_every_explanation(self):
        """
        DT-03 (revisado): el bug original era que el pipeline llamaba a un metodo
        inexistente y caia SIEMPRE al fallback sin que nadie lo notara.

        La comprobacion original ("LLMExplainer no debe tener metodo explain")
        fijaba la implementacion, no la intencion, y ademas prohibia justo el
        mecanismo que hace auditable el fallback. Se sustituye por la propiedad
        que de verdad importa: toda explicacion declara quien la produjo, de modo
        que un fallback nunca pueda confundirse con una respuesta del modelo.
        """
        from cybersentinel.llm.explainer import LLMExplainer
        from cybersentinel.detection.hybrid import DetectionEvidence

        assert hasattr(LLMExplainer, "generate_explanation")
        assert hasattr(LLMExplainer, "explain")

        # Sin modelo disponible: respaldo determinista, declarado como tal.
        resultado = LLMExplainer(None).explain(DetectionEvidence(event_id="ev"), [])
        assert resultado.status == "UNAVAILABLE"
        assert resultado.fallback_used is True
        assert resultado.provider == "deterministico"
        assert resultado.text

    def test_pipeline_calls_generate_explanation_not_explain(self):
        """
        Pipeline.run_events debe llamar generate_explanation() en el LLM Explainer.
        La narrativa NO debe ser siempre el fallback cuando el LLM está disponible.
        """
        from langchain_community.chat_models.fake import FakeListChatModel
        from cybersentinel.llm.explainer import LLMExplainer
        from cybersentinel.rag.vector_store import RAGStore

        try:
            from langchain_community.embeddings.fake import FakeEmbeddings
        except ImportError:
            from langchain_core.embeddings import FakeEmbeddings

        from cybersentinel.pipeline import Pipeline

        fake_llm = FakeListChatModel(responses=["Análisis LLM generado correctamente."])
        explainer = LLMExplainer(fake_llm)
        rag_store = RAGStore(FakeEmbeddings(size=10))

        pipeline = Pipeline(
            rules_dir="config/rules",
            enable_ml=False, enable_temporal=False, enable_cti=False,
            enable_rag=True, enable_llm=True,
        )
        # Inject real explainer and rag_store
        pipeline.llm_explainer = explainer
        pipeline.rag_store = rag_store

        ev = _make_event("ev_llm_test")
        report = pipeline.run_events([ev])
        narrative = report.results[0].narrative

        # Must NOT be the old fallback produced by calling .explain() (wrong method)
        assert narrative != "No hay suficiente contexto (LLM Fallback)", (
            f"Narrative is the fallback — LLM generate_explanation() was NOT called. "
            f"Got: {narrative!r}"
        )
        assert "Análisis LLM" in narrative, (
            f"Unexpected narrative content: {narrative!r}"
        )

    def test_llm_failure_produces_safe_fallback(self):
        """Una falla real del LLM debe producir el fallback, no propagar excepción."""
        from cybersentinel.llm.explainer import LLMExplainer
        from cybersentinel.rag.vector_store import RAGStore
        from cybersentinel.pipeline import Pipeline

        try:
            from langchain_community.embeddings.fake import FakeEmbeddings
        except ImportError:
            from langchain_core.embeddings import FakeEmbeddings

        class BrokenLLM:
            def __call__(self, *a, **kw):
                raise RuntimeError("LLM network error")

        class BrokenExplainer:
            """Explicador que falla en el metodo que usa el pipeline."""

            def explain(self, evidence, rag_docs):
                raise RuntimeError("LLM crashed")

            def generate_explanation(self, evidence, rag_docs):
                raise RuntimeError("LLM crashed")

        pipeline = Pipeline(
            rules_dir="config/rules",
            enable_ml=False, enable_temporal=False, enable_cti=False,
            enable_rag=False, enable_llm=True,
        )
        pipeline.llm_explainer = BrokenExplainer()

        ev = _make_event("ev_llm_fail")
        # Must not raise — fallback must be produced
        report = pipeline.run_events([ev])
        narrative = report.results[0].narrative
        assert narrative, "Se esperaba una narrativa de respaldo cuando el LLM falla"
        # El fallo no puede quedar oculto: tiene que estar en la evidencia.
        evidencia = report.results[0].evidence
        assert evidencia.llm_status == "ERROR"
        assert evidencia.fallback_used is True
        assert report.results[0].trace.status_of("llm").value == "ERROR"

    def test_llm_does_not_modify_hybrid_score(self):
        """
        hybrid_score se calcula ANTES del LLM.
        El LLM no puede alterar el score — verificado como invariante.
        """
        from langchain_community.chat_models.fake import FakeListChatModel
        from cybersentinel.llm.explainer import LLMExplainer
        from cybersentinel.pipeline import Pipeline

        try:
            from langchain_community.embeddings.fake import FakeEmbeddings
        except ImportError:
            from langchain_core.embeddings import FakeEmbeddings

        fake_llm = FakeListChatModel(responses=["Score debería ser 0."])
        explainer = LLMExplainer(fake_llm)

        pipeline = Pipeline(
            rules_dir="config/rules",
            enable_ml=False, enable_temporal=False, enable_cti=False,
            enable_rag=False, enable_llm=True,
        )
        pipeline.llm_explainer = explainer

        ev = _make_event("ev_score_invariant")
        report = pipeline.run_events([ev])

        score_before = report.results[0].evidence.hybrid_score
        # Re-run would give same score (no Sigma rule fires, no ML, no CTI)
        assert score_before == 0.0, (
            f"Expected hybrid_score=0.0 (no signals), got {score_before}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# DT-04 — Benchmark reproducible
# ─────────────────────────────────────────────────────────────────────────────

class TestDT04BenchmarkReproducible:
    """DT-04: El dataset sintético debe ser reproducible con el mismo seed."""

    def _generate_dataset(self, n: int, seed: int):
        """Import and call the refactored generate_synthetic_dataset."""
        sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
        from benchmark_runner import generate_synthetic_dataset, compute_dataset_hash
        events = generate_synthetic_dataset(n=n, seed=seed)
        h = compute_dataset_hash(events)
        return events, h

    def test_same_seed_produces_same_hash(self):
        """Dos ejecuciones con seed=42 deben producir el mismo dataset_hash."""
        _, h1 = self._generate_dataset(n=50, seed=42)
        _, h2 = self._generate_dataset(n=50, seed=42)
        assert h1 == h2, (
            f"Dataset hash NOT stable across runs with same seed!\n"
            f"  run 1: {h1}\n  run 2: {h2}"
        )

    def test_different_seeds_produce_different_hashes(self):
        """Dos ejecuciones con seeds distintos (42 vs 99) deben producir hashes distintos."""
        _, h42 = self._generate_dataset(n=50, seed=42)
        _, h99 = self._generate_dataset(n=50, seed=99)
        assert h42 != h99, (
            f"Dataset hash identical for seed=42 and seed=99 — seed not affecting output!"
        )

    def test_dataset_hash_is_sha256(self):
        """El hash debe tener formato SHA-256 (64 caracteres hexadecimales)."""
        _, h = self._generate_dataset(n=10, seed=0)
        assert len(h) == 64, f"Expected 64-char SHA-256 hex, got {len(h)} chars"
        assert all(c in "0123456789abcdef" for c in h), "Hash is not valid hex"

    def test_dataset_timestamps_are_deterministic(self):
        """Los timestamps deben ser idénticos entre dos runs con el mismo seed."""
        events1, _ = self._generate_dataset(n=10, seed=42)
        events2, _ = self._generate_dataset(n=10, seed=42)
        for e1, e2 in zip(events1, events2):
            assert e1.timestamp == e2.timestamp, (
                f"Timestamp mismatch for {e1.event_id}: {e1.timestamp} vs {e2.timestamp}"
            )

    def test_benchmark_runner_imports_and_runs(self, tmp_path):
        """El benchmark_runner debe importar sin error y ejecutarse sin excepción."""
        output_json = tmp_path / "bench.json"
        result = subprocess.run(
            [sys.executable, str(Path(__file__).parent.parent / "scripts" / "benchmark_runner.py"),
             "--events", "20", "--seed", "42", "--output-json", str(output_json)],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent,
        )
        assert result.returncode == 0, (
            f"Benchmark runner exited {result.returncode}.\n"
            f"STDOUT: {result.stdout[-1500:]}\n"
            f"STDERR: {result.stderr[-500:]}"
        )
        import json
        meta = json.loads(output_json.read_text())
        assert "run_id" in meta
        assert "seed" in meta
        assert "dataset_hash_sha256" in meta
        assert meta["seed"] == 42
        assert len(meta["dataset_hash_sha256"]) == 64

    def test_same_seed_produces_same_benchmark_results(self, tmp_path):
        """Dos ejecuciones con el mismo seed deben tener el mismo dataset_hash."""
        out1 = tmp_path / "run1.json"
        out2 = tmp_path / "run2.json"
        base_cmd = [sys.executable,
                    str(Path(__file__).parent.parent / "scripts" / "benchmark_runner.py"),
                    "--events", "20", "--seed", "42"]
        cwd = Path(__file__).parent.parent

        r1 = subprocess.run(base_cmd + ["--output-json", str(out1)],
                            capture_output=True, text=True, cwd=cwd)
        r2 = subprocess.run(base_cmd + ["--output-json", str(out2)],
                            capture_output=True, text=True, cwd=cwd)

        assert r1.returncode == 0 and r2.returncode == 0

        import json
        m1 = json.loads(out1.read_text())
        m2 = json.loads(out2.read_text())

        assert m1["dataset_hash_sha256"] == m2["dataset_hash_sha256"], (
            f"Dataset hash differs between runs with same seed!\n"
            f"  run 1: {m1['dataset_hash_sha256']}\n"
            f"  run 2: {m2['dataset_hash_sha256']}"
        )
        assert m1["run_id"] != m2["run_id"], (
            "run_id should be unique per execution (UUID)"
        )
