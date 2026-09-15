# CYBERSENTINEL — AUDITORÍA FINAL DE CIERRE — FASE 7
## Benchmark Científico + Observabilidad
**Fecha de auditoría:** 2026-09-15 (UTC-5)  
**Ejecutada por:** Auditor autónomo — evidencia verificada desde código fuente y ejecución real  
**Entorno:** Python 3.13.15 · macOS · pytest-9.0.3 · scikit-learn · langchain-core

---

## VEREDICTO EJECUTIVO

# 🟡 CONDITIONAL GO

La arquitectura principal está preparada para avanzar a Fase 8. No existen fallas que invaliden los resultados de seguridad ni que oculten una afirmación científica crítica. Sin embargo, existen **cuatro deudas técnicas** concretas, verificables desde el código fuente, que deben quedar documentadas antes de iniciar el deployment.

---

## CRITERIOS AUDITADOS

### F7-01 — INTEGRACIÓN ARQUITECTÓNICA

**Estado: ⚠️ PASS CON OBSERVACIONES**

El flujo puede reconstruirse desde código. El pipeline orquesta correctamente:
```
EVENT → NORMALIZATION → SIGMA → ML(*) → TEMPORAL → CTI → DetectionEvidence → RAG → LLM(*) → DatasetManager
```

**Evidencia verificable (ejecución real):**
```json
{
  "total_events": 1, "total_findings": 0, "num_incidents": 1,
  "evidence": { "event_id": "test_e2e_001", "hybrid_score": 4.0 },
  "trace": { "latencies_ms": { "sigma": 0.033, "cti": 0.0136, "total": 0.0573 } }
}
```

> [!CAUTION]
> **DEUDA TÉCNICA #1 — CLI ROTA:** La CLI oficial (`cli.py`) referencia tres atributos **eliminados** del nuevo `PipelineReport/IncidentResult`:
> - L86: `r.incident for r in report.results` → `IncidentResult` ya no tiene `.incident`
> - L95: `r.narrative.to_text()` → `narrative` ahora es `str`, no un objeto
> - L109: `report.audit_integrity` → eliminado del dataclass
>
> Ejecutar `cybersentinel analyze --input logs.jsonl` falla con `AttributeError`. La interfaz oficial está rota.

---

### F7-02 — DEFINICIÓN DE DETECCIÓN

**Estado: ⚠️ PASS CON OBSERVACIONES**

Existe una definición técnicamente coherente: `hybrid_score > 50.0` como umbral de alertamiento.

**Fórmula documentada en código (`hybrid.py`):**

| Señal | Contribución |
|---|---|
| Sigma RuleHit | +50.0 |
| ML anomaly_score > 0.5 | +(score - 0.5) × 40.0 |
| Contexto temporal | +30.0 |
| CTI: nation-state / C2 / APT28 | +50.0 |
| CTI: malicious / malware | +30.0 |
| CTI: anomalous-activity | +15.0 |
| CTI: spam | +5.0 |
| Techo | min(100.0) |

**Limitación documentada:** No existe un conjunto de evaluación con ground-truth que permita calcular TP, TN, FP, FN formalmente. El umbral `> 50.0` es heurístico no validado contra datos reales. Esto es conocido y declarado (`ready_for_training = False`).

> [!CAUTION]
> **DEUDA TÉCNICA #2 — ML SCORE HARDCODED:** El pipeline L140 contiene:
> `anomaly_score = 0.6  # Simplified mock for ablation speed.`
> El `AnomalyDetector` real existe y funciona en tests, pero no se invoca en `run_events()`. Todo evento con ML habilitado produce `ml_boost = 4.0` constante, independientemente del evento real. El componente ML no aporta diferenciación.

---

### F7-03 — BENCHMARK ABLATION

**Estado: ⚠️ PASS PARCIAL**

Ejecución real verificada (A–E):

| Configuración  | Detecciones | p95 Core (ms) | p95 Total (ms) |
|----------------|-------------|---------------|----------------|
| A. Sigma Only  | 0           | 0.0008        | 0.0008         |
| B. + ML        | 0           | 0.0009        | 0.0009         |
| C. + Temporal  | 0           | 0.0015        | 0.0015         |
| D. + CTI       | 0           | 0.0056        | 0.0056         |
| E. Full System | 0           | 0.0084        | 0.0152         |

**Limitaciones documentadas:**
- Configuraciones **F y G ausentes** del runner (aunque E ya incluye RAG+LLM).
- **Cero detecciones** en todas las configuraciones: StixIngestor vacío, reglas Sigma no disparan sobre datos sintéticos triviales, ML score es constante.
- Las latencias son reales. Las detecciones son artefactos del dataset trivial.

---

### F7-04 — DATASET READINESS

**Estado: 🔴 NO DEMOSTRADO**

El benchmark usa `datetime.now(timezone.utc)` sin seed ni hash. Una segunda ejecución produce timestamps distintos. No existe dataset persistente ni mecanismo de identificación.

**Evidencia verificada:**
```python
# benchmark_runner.py L19 — sin seed, sin hashlib, sin persistencia
now = datetime.now(timezone.utc)
```
> [!CAUTION]
> **DEUDA TÉCNICA #4 — DATASET SIN HASH/SEED:** El benchmark no puede reproducirse exactamente. Los timestamps varían entre ejecuciones.

---

### F7-05 — LEAKAGE AUDIT

**Estado: ✅ NO OBSERVADO**

- `TimeBasedSplitter`: ordena por timestamp, divide (60/20/20) sin contaminar train con futuro.
- `DatasetManager`: usa `timestamp` del evento original (no `created_at`), explícito en L101.
- `StructuredDecision`: inmutable (`frozen=True`). El feedback humano no puede mutar.
- Features: observacionales (hora, entropía, rareza de IP) — sin acceso a la etiqueta.

---

### F7-06 — MÉTRICAS DE DETECCIÓN

**Estado: ⚠️ PARCIALMENTE SOPORTADO**

`AnomalyDetector.evaluate()` implementa roc_auc y accuracy, pero requiere dataset con etiquetas `y` que en la práctica no existe. El pipeline no invoca `evaluate()`. No existe archivo de resultados persistidos.

---

### F7-07 — LATENCIA

**Estado: ✅ PASS**

`TraceContext` instrumenta con `time.perf_counter()`. Ejecución real con 200 eventos:

| Percentil | Total (ms) |
|---|---|
| p50 | 0.0143 |
| p95 | 0.0185 |
| p99 | 0.0673 |
| mean | 0.0320 |
| max | 3.2861 |

> [!NOTE]
> Latencias corresponden a `FakeEmbeddings` y `FakeListChatModel`. En producción con LLM real las latencias serán órdenes de magnitud mayores (500–2000ms por evento).

---

### F7-08 — THROUGHPUT

**Estado: ⚠️ DEMOSTRADO CON LIMITACIONES**

```
Events: 1000 · Elapsed: 3.854s · Throughput: 259 events/sec (con FakeLLM/FakeEmbeddings)
```

Con LLM real el throughput sería ~1 evento/seg sin concurrencia.

---

### F7-09 — OBSERVABILIDAD

**Estado: ✅ PASS**

`TraceContext` produce por evento: `event_id`, latencias fraccionadas, y `DetectionEvidence` completa vía `.to_dict()`.

**Limitación:** No existe `run_id` de sesión. Re-ejecuciones no son diferenciables sin identificador externo.

---

### F7-10 — GRACEFUL DEGRADATION

**Estado: ✅ PASS**

Verificado empíricamente:

| Config | Resultado | Score |
|---|---|---|
| Sigma Only | OK | 0.0 |
| ML desactivado | OK | 0.0 |
| CTI desactivado | OK | 4.0 |
| RAG desactivado | OK | 4.0 |
| LLM desactivado | OK | 4.0 |

RAG y LLM **no pueden alterar `hybrid_score`**: el score se calcula antes de llamarlos.

---

### F7-11 — RAG

**Estado: ⚠️ PASS ARQUITECTURAL / INERTE EN PRODUCCIÓN**

Arquitectura correcta (retrieve con provenance, prompt injection resistance verificada). Sin embargo, `RAGStore` se inicializa sin documentos indexados → `retrieve()` siempre retorna `[]` en el pipeline actual.

---

### F7-12 — LLM

**Estado: ⚠️ PASS ARQUITECTURAL / BUG ACTIVO**

> [!CAUTION]
> **DEUDA TÉCNICA #3 — MISMATCH DE MÉTODO LLM:** El pipeline llama `self.llm_explainer.explain()` (L182), pero el método real es `generate_explanation()`. La llamada falla silenciosamente dentro del `try/except` → `narrative = "No hay suficiente contexto (LLM Fallback)"` siempre. El LLM **nunca ejecuta** en el pipeline actual.

**Positivo verificado:** El `SYSTEM_PROMPT` impide que el LLM modifique la clasificación.

---

### F7-13 — HUMAN-IN-THE-LOOP

**Estado: ✅ PASS**

`StructuredDecision` captura `detection_id`, `event_id`, `timestamp` original, `analyst_id`, `model_version`, `rule_version`, `fingerprint` (SHA-256).  
`DatasetManager` implementa resolución de conflictos y `ready_for_training = False` (threshold: >1000 TP + >1000 FP).

---

### F7-14 — REPRODUCIBILIDAD

**Estado: 🔴 PARCIALMENTE SOPORTADO**

Sin seed fijo, sin `run_id`, sin hash del dataset. `AnomalyDetector` tiene `random_state=42` y `TimeBasedSplitter` es determinista, pero el benchmark no puede reproducirse exactamente.

---

### F7-15 — TESTS

**Estado: ✅ PASS**

```
247 passed, 13 warnings in 14.97s  (Python 3.13.15 · pytest-9.0.3 · 2026-09-15)
```

> [!IMPORTANT]
> 247/247 tests demuestra estabilidad funcional modular. No demuestra efectividad de detección sobre tráfico real, ausencia de falsos negativos, ni rendimiento bajo carga concurrente.

---

### F7-16 — CLAIMS AUDIT

| Afirmación | Estado |
|---|---|
| "Sigma asegura detección determinista" | ✅ SUPPORTED |
| "ML modula el riesgo por rareza" | 🔴 UNSUPPORTED EN PIPELINE (hardcoded 0.6) |
| "CTI confirma compromiso" | ⚠️ PARTIALLY SUPPORTED (StixIngestor vacío en benchmark) |
| "RAG enriquece el contexto" | 🔴 UNSUPPORTED EN PIPELINE (corpus vacío) |
| "LLM genera narrativa contextual" | 🔴 UNSUPPORTED EN PIPELINE (método incorrecto → fallback) |
| "LLM no modifica clasificación" | ✅ SUPPORTED (hybrid_score calculado antes) |
| "Graceful Degradation verificada" | ✅ SUPPORTED (5 configs probadas) |
| "247 tests = efectividad" | ⚠️ PARTIALLY SUPPORTED (= estabilidad funcional, no efectividad) |
| "Leakage prevenido" | ✅ SUPPORTED |
| "ready_for_training = False" | ✅ SUPPORTED |

---

### F7-17 — SEGURIDAD Y ALCANCE

**Estado: ✅ PASS**

Uso estrictamente defensivo. Sin malware, exploits ni acciones ofensivas. SYSTEM_PROMPT LLM: "ERES STRICTAMENTE READ-ONLY". Alcance de laboratorio declarado.

---

## MATRIZ FINAL DE EVIDENCIAS

| ID    | Criterio             | Estado     |
|-------|----------------------|------------|
| F7-01 | Integración pipeline | ⚠️ PASS* (CLI rota) |
| F7-02 | Definición detección | ⚠️ PASS* (ML no real) |
| F7-03 | Ablation A–G         | ⚠️ PASS* (0 detecciones, F–G ausentes) |
| F7-04 | Dataset persistente  | 🔴 FAIL |
| F7-05 | Leakage audit        | ✅ PASS (NO OBSERVADO) |
| F7-06 | Métricas TP/FP/FN    | ⚠️ PARCIAL |
| F7-07 | Latencia p50/p95/p99 | ✅ PASS (FakeLLM) |
| F7-08 | Throughput           | ⚠️ PASS* (259 ev/s, sin LLM real) |
| F7-09 | Observabilidad       | ✅ PASS |
| F7-10 | Graceful degradation | ✅ PASS |
| F7-11 | RAG Recall@K         | ⚠️ PARCIAL (corpus vacío) |
| F7-12 | LLM groundedness     | ⚠️ PARCIAL (bug activo) |
| F7-13 | HITL trazabilidad    | ✅ PASS |
| F7-14 | Reproducibilidad     | 🔴 PARCIAL |
| F7-15 | Tests                | ✅ PASS (247/247) |
| F7-16 | Claims audit         | ⚠️ MIXTO (3 UNSUPPORTED) |
| F7-17 | Seguridad            | ✅ PASS |

---

## DEUDAS TÉCNICAS REGISTRADAS

| ID | Severidad | Descripción | Archivo | Impacto |
|---|---|---|---|---|
| DT-01 | 🔴 Alta | CLI rota — 3 atributos eliminados | `cli.py` L86, L95, L109 | Interfaz oficial inutilizable |
| DT-02 | 🔴 Alta | ML score hardcoded 0.6 | `pipeline.py` L140 | ML no aporta diferenciación real |
| DT-03 | 🔴 Alta | LLM método incorrecto → fallback silencioso | `pipeline.py` L182 | LLM nunca genera narrativas |
| DT-04 | 🟡 Media | Dataset sin seed/hash | `benchmark_runner.py` L19 | Benchmark no reproducible exactamente |

---

## ESTADO FINAL

```
FASE 7: CERRADA CON DEUDA TÉCNICA DOCUMENTADA
NIVEL:  🟡 CONDITIONAL GO
ACCIÓN: INICIAR FASE 8 — RESOLVER DT-01 a DT-03 COMO PRIMER PASO
```

## GATE FINAL

> **¿Existe evidencia técnica y científica suficiente para afirmar que CyberSentinel puede pasar de experimentación a Deployment sin ocultar limitaciones conocidas?**

**SÍ — con las limitaciones explícitamente registradas arriba.**

# 🟡 CONDITIONAL GO — FASE 8 AUTORIZADA
