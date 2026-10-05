# FASE 1.5B — VALIDATION REPORT

**Fecha:** 2026-10-05
**Commit evaluado:** `0826952` (solo documentación sobre `ad622c2`; ningún archivo de código cambió entre ambos)
**Rama:** `fix/orphaned-collectors-sysmon-firewall`
**Alcance:** evidencia ejecutada. No se modificó código, tests, datos ni artefactos versionados.

### Cómo se obtuvo la evidencia

- La suite de tests se ejecutó en el repositorio.
- Los scripts de ML, Sigma y Markov **escriben en archivos versionados** (`results/`, `reports/`, `models/`, `docs/navigator_*.json`). Por eso se ejecutaron en una **copia aislada** del repositorio, con el dataset UNSW-NB15 enlazado en solo lectura, y sus salidas se compararon byte a byte con las versionadas.
- Al terminar, `git status` del repositorio está limpio.

### Convención de estados

| Estado | Significado |
|---|---|
| IMPLEMENTADO | El código existe. |
| CONECTADO | Otro módulo de `src/` lo invoca en un flujo real (CLI, API o pipeline). |
| TESTEADO | Tiene tests que pasan en la suite estándar. |
| VALIDADO EXPERIMENTALMENTE | Hay métricas con verdad-terreno, reejecutadas en esta fase y coincidentes. |
| PRODUCCIÓN | Desplegado y operado con tráfico real. **Ningún componente alcanza este estado.** |

---

## 1. Execution baseline

| Elemento | Valor |
|---|---|
| Commit | `0826952e17cc8bc0b3ac8fe1b21ceb4e0159afbe` |
| Python | 3.11.15 (`.venv/` del repositorio) |
| pytest | 9.1.1 |
| Plataforma | macOS (Darwin 24.5.0) |
| scikit-learn / numpy / pandas / pysigma | 1.9.1 / 2.4.6 / 3.0.5 / 1.5.0 |
| Plugins relevantes | `anyio` 4.15.1. **No** están instalados `pytest-asyncio` ni `nats-py`. |

Comando (equivale a la configuración del proyecto: `pyproject.toml` no define `addopts`):

```bash
PYTHONPATH=src .venv/bin/python -m pytest -q -p no:cacheprovider -rs
```

## 2. Test suite real

```
677 passed, 1 skipped, 4 warnings in 124.12s (0:02:04)
```

| passed | failed | errors | skipped | warnings | duración |
|---|---|---|---|---|---|
| 677 | 0 | 0 | 1 | 4 | 124.12 s |

- El resultado coincide con la ejecución anterior sobre `ad622c2` (677/1/4 en 133.65 s). La diferencia de duración se debe a la carga de la máquina.
- **Warnings:**
  - `langchain-community` en retirada (`rag/vector_store.py:16`).
  - Dos avisos de `HTTP_422_UNPROCESSABLE_ENTITY` deprecado (`api/app.py:435, 473, 648`; aparecen en 2 tests de `test_soc_panel.py`).
  - El alias `anyio.abc.BlockingPortal` (dentro de Starlette).

**Hallazgo: la suite no es hermética.** Durante la ejecución se modificaron archivos fuera de `tmp_path`:
- `data/feedback/decisions.jsonl`
- `audit_log.jsonl`
- `response_actions.db`

Los tres están ignorados por git, por lo que no aparecen en `git status`. Los escriben, entre otros, `tests/test_soc_panel.py`, `tests/test_e2e_agent.py` y `tests/test_high_availability.py`, que referencian los almacenes por defecto.

Subconjunto del pipeline (sección 4): 17 archivos, `275 passed in 15.95s`.

## 3. NATS skip

| Campo | Valor |
|---|---|
| Archivo / test | `tests/test_streaming.py:59`, `test_integracion_con_nats_real` |
| Mecanismo | `@pytest.mark.skipif(True, …)`: **incondicional** |
| Razón declarada | "requiere un servidor NATS real (docker-compose up nats)" |
| Dependencias | servidor NATS con JetStream, `nats-py` (extra `streaming`, no instalado) y `pytest-asyncio` (**no declarado en ningún extra ni instalado**) |
| ¿Requiere NATS real? | Sí: publica y suscribe contra `nats://127.0.0.1:4222` |
| ¿Hay alternativa local o mock? | Parcial. La lógica pura (`process_raw_message`) ya se prueba sin red en 3 tests. `EventBus` no tiene doble en memoria. |
| ¿Mantener el skip en CI? | Sí en la suite estándar. Debería pasar a un job de integración separado. |

**Contradicción con la documentación del propio archivo.** El docstring de `test_streaming.py` dice que el test "se salta explícitamente si no hay servidor —o si `nats-py` no está instalado—". El código no comprueba ninguna de las dos condiciones: se salta siempre. Aunque se quitara el `skipif`, tampoco correría sin `pytest-asyncio`.

**Contexto decisivo:** ningún módulo de `src/` fuera de `src/cybersentinel/streaming/` importa `streaming`. Ni el pipeline, ni la API, ni la CLI publican ni consumen del bus.

**Clasificación: C**, un test de integración para una etapa posterior. Además, el módulo que prueba no está conectado. No es una limitación de infraestructura que oculte un fallo del flujo principal (A), y un mock no añadiría evidencia sobre un componente que nada usa (B).

## 4. Pipeline E2E

`tests/test_pipeline.py::test_full_pipeline_end_to_end` **pasa**, tanto en la suite como en solitario. Además se ejecutó el pipeline real sobre `data/generate_sample.py` (`num_benign=60`), igual que el test, en dos configuraciones:

- **Como el test E2E:** sin `sigma_rules_dir`, solo las 7 reglas propias.
- **Como la CLI y la API:** con `config/sigma_rules/selected`, 7 reglas propias + 38 Sigma.

| Métrica | Como el test | Como la CLI |
|---|---|---|
| Líneas crudas → `SecurityEvent` | 77 → 77 | 77 → 77 |
| Reglas cargadas | 7 | 45 |
| Hallazgos (`hybrid_score ≥ ALERT_THRESHOLD`) | 17 | 17 |
| `detection_status` | NO_DETECTION 53, BEHAVIORAL_ANOMALY 13, ANOMALY_ONLY 4, RULE_MATCH 4, RULE_AND_ANOMALY 3 | NO_DETECTION 47, BEHAVIORAL_ANOMALY 13, RULE_MATCH 10, RULE_AND_ANOMALY 6, ANOMALY_ONLY 1 |
| Técnicas ATT&CK observadas | 7 | 11 |
| Incidentes temporales / predicciones kill-chain | 5 / 1 | 6 / 1 |
| Decisiones de gobernanza | allowed 231, requires_approval 11 | allowed 231, requires_approval 36 |
| Entradas de auditoría / `verify()` | 101 / `(True, None)` | 130 / `(True, None)` |

**Implicación:** el test E2E no ejercita Sigma. Que pase demuestra que la cadena está conectada, no que las 38 reglas Sigma funcionen dentro del pipeline (eso lo cubre `test_sigma_integration.py`).

### Flujo verificado etapa por etapa

| Etapa | Módulo | Clase / función | Entrada | Salida | Evidencia de ejecución | Tests |
|---|---|---|---|---|---|---|
| INPUT | `ingestion/normalizer.py`; `api/app.py` (`POST /api/v1/events`) | `Normalizer.from_jsonl`; `IngestService.ingest` | JSONL o `RawEvent` JSON | `list[dict]` | 77 líneas leídas | `test_ingestion`, `test_api_ingestion` |
| NORMALIZATION → SECURITY EVENT | `ingestion/normalizer.py:78-220`, `collectors/*`, `schema.py` | `Normalizer.normalize_record`; 5 colectores | dict crudo | `SecurityEvent` | 77/77 instancias `SecurityEvent` | `test_collectors`, `test_ocsf`, `test_pipeline::test_normalizer_auth_event` |
| DETECTION | `detection/rules_engine.py`, `detection/anomaly.py`, `analytics/deviation.py`, `cti/enrichment.py` | `RulesEngine.evaluate`; `AnomalyDetector.fit/score`; `DeviationDetector.evaluate`; `CTIEnricher.enrich_event` | `list[SecurityEvent]` | `RuleHit`, score 0..1, desviaciones, coincidencias CTI | `sigma=OK` 7 eventos, `ml=OK` 77, `behavior=OK` 16, `cti=OK` 13 | `test_sigma_integration`, `test_detection_quality`, `test_ml_features`, `test_behavioral_analytics`, `test_cti_enrichment` |
| EVIDENCE | `detection/hybrid.py` | `DetectionEvidence` (`hybrid_score`, `detection_status`) | señales anteriores | evidencia por evento | 77 evidencias; `hybrid_score` máx. 100.0 | `test_pipeline::test_full_pipeline_end_to_end`, `test_anomaly_threshold_calibration` |
| CORRELATION | `detection/temporal.py`, `correlation/correlator.py`, `correlation/sequence_model.py` | `TemporalCorrelator.correlate`; `Correlator.build_findings/correlate` (Markov orden 1) | hits + anomalías | incidentes y predicción | 5–6 incidentes; 1 predicción | `test_temporal_correlation`, `test_sequence_model`, `test_phase4d_prediction_and_risk` |
| MITRE | `pipeline.py:605-615`, `correlation/mitre.py` | `mitre.tactics_of` sobre `rule.mitre_technique` | reglas activadas | técnicas y tácticas | 7 / 11 técnicas observadas | `test_mitre_attack`, `test_pipeline::test_mitre_next_tactics` |
| GOVERNANCE | `governance/policy.py`, `response/actions.py` | `ResponsePlanner.plan` → `GovernancePolicy` | evidencia | veredictos ALLOWED / REQUIRES_APPROVAL / PROHIBITED | 242 / 267 veredictos (0 PROHIBITED en esta muestra) | `test_pipeline::test_policy_*`, `test_response_defense` |
| RESPONSE DECISION | `response/executor.py` | `ResponseExecutor.request_action` (`dry_run=True`) | veredictos no prohibidos de hallazgos | `ResponseAction` | Configuración CLI: 36 `action_requested`, 38 `action_completed` (Nivel 1 en dry-run) | `test_response_defense`, `test_e2e_incident_flow` |
| AUDIT | `governance/audit.py` | `AuditLog.record` / `verify` | eventos del pipeline | JSONL encadenado por hash | `verify()` → `(True, None)` | `test_audit_integrity`, `test_pipeline::test_audit_*` |

**Observación de diseño (relevante para ML, ver §6):** en `pipeline.py:548-549`, si el detector no está entrenado, se entrena con **el mismo lote que después puntúa**. En la API ese primer lote fija la línea base de forma permanente. `api/worker.py` lo declara en su docstring.

## 5. ML reproducibility

### Inventario

| Componente | Existe | Ruta | ¿Ejecutable hoy? | Evidencia |
|---|---|---|---|---|
| Dataset real | Sí, **fuera de git** (`.gitignore`, ~720 MB) | `data/unsw_nb15/UNSW-NB15_{1..4}.csv` | Sí, en esta máquina | SHA-256 de los archivos 1 a 4 iguales a los registrados en `results/*metadata.json` y `docs/UNSW-NB15-EVALUATION.md` |
| Datasets sintéticos | Sí | `data/synthetic_sysmon_eval.json` (11 ataques), `data/sample_logs.jsonl`, `data/synthetic_flows_unsw_format.csv` (ignorado; se genera con `data/generate_flow_sample.py`), `data/generate_campaigns.py` | Sí | Ejecutados |
| Preprocesamiento | Sí | `data/unsw_nb15_adapter.py` (`UNSWNB15Adapter`, `FIELD_MAPPING`) | Sí | 300 000 registros cargados |
| Feature engineering | Sí | `ml/features.py` (`FeatureExtractor`, 19 features) | Sí | 10 de 19 con varianza en UNSW (las 9 de host son constantes) |
| Entrenamiento | Sí | `detection/anomaly.py` (`AnomalyDetector`, `IsolationForest`) | Sí | 9.2 s sobre 154 873 benignos |
| Validación | Sí | `evaluate_unsw_nb15.py::pick_threshold` (barrido de percentiles, máximo F1) | Sí | umbral 0.642614 |
| Test | Sí | split temporal 60/20/20 | Sí | n = 60 000 |
| Métricas | Sí | `results/`, `reports/`, `models/prediction_report.json` | Sí | ver §7 |
| Modelo guardado | **No** para Isolation Forest: no hay `.pkl`/`.joblib`, se reentrena en cada ejecución. **Sí** para Markov. | `models/markov_tactics.json` | Sí | regenerado idéntico |
| Script reproducible | Sí | `scripts/evaluate_unsw_nb15.py`, `run_unsw_nb15_1.py`, `calibrate_anomaly_threshold.py`, `train_eval_iforest.py`, `audit_iforest.py`, `evaluate_sigma_phase1.py`, `cli.py train-prediction` | Sí, con matices | ver tabla siguiente |
| Notebooks | No | — | — | — |

### Ejecuciones de esta fase

| Script / comando | Datos | Duración | Resultado frente a lo versionado |
|---|---|---|---|
| `evaluate_unsw_nb15.py --limit 300000 --seed 42` **solo con los archivos 2, 3 y 4** | 300 000 flujos, 16.22 % ataques | 2 min 01 s | **Idéntico byte a byte**: métricas, umbral, `predictions.csv`, `curves.csv`, `confusion_matrix.csv`, `ablation.csv` |
| El mismo comando **tal como está documentado** (toma los archivos 1 a 4) | 300 000 flujos, 11.97 % ataques | 2 min 32 s | **Distinto**: P 0.5006, R 0.8970, F1 0.6426, ROC-AUC 0.9078, PR-AUC 0.6469, umbral 0.646882 |
| `run_unsw_nb15_1.py --stage full` | `UNSW-NB15_1.csv`, 186 812 en la ventana evaluable | 1 min 01 s | Idéntico (métricas y predicciones) |
| `calibrate_anomaly_threshold.py` (2 veces) | 1 020 sintéticos, 46 sospechosos | ~5 s | Idéntico: umbral 0.602; FPR/recall validation 2.06 % / 100 %; **test 2.87 % / 66.67 %** |
| `train_eval_iforest.py` | 2 000 benignos + 11 ataques sintéticos | 4.5 s | Idéntico: análisis FP/TP, `threshold_analysis.csv`, `experiment_reproducibility.json` (salvo timestamp) |
| `audit_iforest.py` | el mismo | 3.9 s | **Distinto** (ver §6, hallazgo L2) |
| `cli train-prediction` (seed 7, 400 campañas) | sintético | <5 s | Idéntico: `models/markov_tactics.json` y `models/prediction_report.json` |

### Registro de la evaluación principal (archivos 2 a 4)

| Campo | Valor |
|---|---|
| Dataset | UNSW-NB15 crudo (`UNSW-NB15_2.csv`, `_3`, `_4`), muestreo sistemático 1 de cada k |
| Registros | 300 000 (251 335 benignos, 48 665 ataques) |
| Features | 19 definidas, 10 informativas |
| Target | `label` (0/1); `attack_cat` solo para el desglose |
| Algoritmo | IsolationForest, `contamination="auto"`, `n_estimators=200`, `random_state=42` |
| Split | temporal 60/20/20: train 180 000 (entrena solo con sus 154 873 benignos), validation 60 000, test 60 000 |
| Umbral | 0.642614, elegido en validation |
| Test | TP 12 949, FP 12 375, TN 34 493, FN 183 |
| Métricas de test | precision 0.5113, recall 0.9861, F1 0.6734, **FPR 0.264**, ROC-AUC 0.8855, PR-AUC 0.566 |
| Artefactos | `results/unsw_nb15_{metrics,run_metadata,predictions,confusion_matrix,ablation,curves}` |
| Errores | ninguno |

### Clasificación: **PARCIALMENTE REPRODUCIBLE**

Qué falta para que otra persona lo reproduzca solo con repositorio, dependencias, datos, configuración y comando:

1. **El comando documentado no fija el conjunto de archivos.** `docs/UNSW-NB15-EVALUATION.md:333` publica `python scripts/evaluate_unsw_nb15.py --limit 300000 --seed 42`, pero el script toma `UNSW-NB15_[0-9].csv`. Con los cuatro archivos presentes, las métricas cambian. El documento sí explica que `_1` se excluyó, pero el script no tiene forma de excluirlo.
2. **El dataset no está en el repositorio.** Hay que descargarlo de UNSW manualmente; los SHA-256 publicados permiten verificarlo.
3. **No hay versiones fijadas.** `requirements.txt` usa rangos (`>=`) y no hay lockfile. Los metadatos de ejecución registran Python, pero no la versión de scikit-learn ni de numpy. Hoy reproduce con sklearn 1.9.1, pero nada lo garantiza para otras versiones.
4. **Los scripts sobrescriben artefactos versionados.** Ejecutarlos en el repositorio modifica `results/`, `reports/` y `docs/navigator_*.json`. `train_eval_iforest.py` y `audit_iforest.py` escriben los mismos nombres de archivo.
5. **Ningún test regenera métricas.** `test_anomaly_threshold_calibration.py` solo lee el JSON guardado.

## 6. ML leakage audit

Análisis ejecutado sobre la misma partición de la evaluación principal (archivos 2 a 4), reutilizando sus funciones.

| # | Hallazgo | Dónde | Evidencia | Clasificación |
|---|---|---|---|---|
| L1 | El pipeline entrena el detector con el mismo lote que puntúa, ataques incluidos | `pipeline.py:548-549`; `api/worker.py` (primer lote fija la línea base) | Lectura de código; documentado por el propio worker | **ALTO**: las puntuaciones del pipeline, la CLI y la API son in-sample y no siguen el protocolo con el que se midió el detector (train benigno → test separado). Las métricas de UNSW no describen el comportamiento del pipeline. |
| L2 | `audit_iforest.py` no desplaza los ataques a la ventana de test: los 11 ataques caen en TRAIN y TEST se queda sin positivos | `scripts/audit_iforest.py` frente a `train_eval_iforest.py:81-82` | Reejecución: `class_distribution` train = 11 ataques, test = 0; matriz TP 0, FP 267, TN 136 | **ALTO**: evaluación inválida. Los artefactos que produce (`iforest_confusion_matrix.json`, `class_distribution.json`, `iforest_sample_tn_fn.json`) no son regenerables. Ningún documento los cita. |
| L3 | Ground truth sintético definido por atributos que las features ven directamente (puerto 4444 → `is_rare_port`, `source=auth`, comandos fijos) | `calibrate_anomaly_threshold.py:71-86`; `train_eval_iforest.py` (5 comandos benignos fijos) | Lectura de código | **MEDIO**: validez de constructo. El umbral 0.602, usado por defecto en producción, se calibró con 46 positivos (12 en test) fácilmente separables. |
| L4 | Partición aleatoria estratificada sobre una serie temporal | `calibrate_anomaly_threshold.py:125-143` | Lectura de código | **MEDIO**: no es fuga de etiqueta, pero mezcla pasado y futuro en las features de ventana (`events_in_window`, `time_since_prev_log`). |
| L5 | Métrica global Sigma sumada entre reglas (cada ataque cuenta una vez por regla) | `evaluate_sigma_phase1.py` | FN 2 459 = 5 reglas × ~500 ataques | **MEDIO**: definición de métrica, no fuga. |
| L6 | La etiqueta viaja dentro del evento (`tags: attack:<cat>`; `raw.label`, `raw.attack_cat`) | `unsw_nb15_adapter.py:281-299`; `rules_engine.py:172` y `sigma_adapter.py:179` consultan `event.raw` como respaldo | Comprobado en ejecución. Ninguna regla actual referencia esos campos. | **BAJO** (latente). |
| L7 | Empates de timestamp en las fronteras de partición | `evaluate_unsw_nb15.py::temporal_split` | Train y validation comparten el segundo 06:26:11; validation y test, el 09:26:37 | **BAJO** |
| L8 | Duplicados entre train y test | — | 0.00 % de vectores de features idénticos; 0.28 % de filas con campos crudos idénticos | **BAJO** |
| L9 | Normalización antes del split | `anomaly.py:125-130` (media y desviación solo en `fit`) | `fit` recibe solo benignos de train | SIN HALLAZGO |
| L10 | Umbral elegido sobre test | `pick_threshold` usa validation | Verificado | SIN HALLAZGO |
| L11 | Selección de features con todo el dataset | `feature_eligibility(train)` | Solo train | SIN HALLAZGO |
| L12 | Atajo por IP de origen (`src_ip_rarity`) | — | Las 4 IPs atacantes también emiten tráfico benigno; el 100 % de los ataques de test vienen de IPs vistas en train. Sin esa feature: ROC-AUC 0.8864 (frente a 0.8855). | SIN HALLAZGO |
| L13 | Features derivadas del target (`sttl`, `ct_state_ttl`, conocidas por filtrar la etiqueta en UNSW-NB15) | `FEATURE_NAMES` | No se usan | SIN HALLAZGO |
| L14 | Inconsistencia de hiperparámetros declarados | `train_eval_iforest.py:197` (ablación con `IsolationForest` por defecto, 100 árboles) frente a los metadatos (200) | Lectura de código | **BAJO** |

No se encontraron hallazgos **CRÍTICOS**: ninguna métrica publicada está inflada por fuga de etiqueta.

## 7. ML metrics provenance

| Artefacto | Dataset | Generado | Código | Config | ¿Regenerable? | Clasificación |
|---|---|---|---|---|---|---|
| `results/unsw_nb15_{metrics,run_metadata,predictions,confusion_matrix,ablation,curves}` | UNSW-NB15 archivos 2 a 4 (SHA registrado) | 2026-09-15T11:28 UTC (`efa62e2`) | `evaluate_unsw_nb15.py` | seed 42, 300k, n_est 200 | Sí, byte a byte, **solo excluyendo `_1`** | **VALIDADA ACTUALMENTE** (con esa salvedad) |
| `results/unsw_nb15_1_*` | `UNSW-NB15_1.csv` | 2026-09-15T17:00 UTC (`cd84181`) | `run_unsw_nb15_1.py --stage full` | seed 42 | Sí, idéntico | **VALIDADA ACTUALMENTE** (evaluación declarada **exploratoria**) |
| `reports/anomaly_threshold_calibration.json` (umbral 0.602) | 1 020 sintéticos, 46 positivos | `bf416a0` (2026-09-24) | `calibrate_anomaly_threshold.py` | seeds 42 y 123 | Sí, idéntico | **VALIDADA ACTUALMENTE** (sintético; ver L3 y L4) |
| `reports/iforest_{false,true}_positive_analysis.json`, `iforest_threshold_analysis.csv`, `experiment_reproducibility.json` | sintético Sysmon | `cfd07db` | `train_eval_iforest.py` | seed 42 | Sí, idéntico | **VALIDADA ACTUALMENTE** (sintético) |
| `reports/iforest_confusion_matrix.json` (TP 11, FP 391, TN 1) | sintético | `cfd07db` | supuestamente `audit_iforest.py` | — | **No**: hoy produce TP 0, FP 267, TN 136. Además contradice el CSV de umbrales versionado (umbral 0.5: FP 343, TN 49). | **NO TRAZABLE** |
| `reports/class_distribution.json`, `reports/iforest_sample_tn_fn.json` | sintético | `cfd07db` | `audit_iforest.py` | — | No | **NO TRAZABLE** |
| `reports/sigma_phase1_{summary,metrics,by_rule,false_positives}` | `synthetic_flows_unsw_format.csv` (5 000 flujos sintéticos, **no** UNSW real) | 2026-09-14, commit `fbfcef9`, en otra máquina (`/home/user/...`) | `evaluate_sigma_phase1.py` | seed 42 | Las métricas globales se reproducen (TP 41, FP 0, FN 2 459, TN 22 500), pero el reporte versionado cubre **22 reglas** y hoy hay **45** (7 propias + 38 Sigma) | **HISTÓRICA** |
| `docs/navigator_before.json`, `docs/navigator_after.json` | — | `cfd07db` | `evaluate_sigma_phase1.py` (sobrescribe `docs/`) | lista `TECHNIQUES_FROM_SIGMA` **escrita a mano** | Se regeneran, pero difieren de lo versionado | **HISTÓRICA** |
| `docs/navigator_phase3.json`, `docs/navigator_phase4a_{before,after}.json` | — | `cfd07db`, `fad97de` | sin script que escriba esos nombres; probablemente `cli analyze --navigator` o `coverage` | — | No se intentó (no se recalcula cobertura en esta fase) | **NO TRAZABLE** (sin comando registrado) |
| `models/markov_tactics.json`, `models/prediction_report.json` | campañas sintéticas (`generate_campaigns.py`) | `5b90197` | `cli train-prediction` | seed 7, 400 campañas, alpha 0.5 | Sí, idéntico | **VALIDADA ACTUALMENTE** (sintético) |
| `results/unsw_nb15_validation.json` | UNSW | — | `validate_unsw_nb15.py` | ruta `/home/user/...` | No ejecutado | **REPRODUCIBLE PERO NO EJECUTADA** |
| `results/load_*`, `results/benchmark_*`, `security_benchmark.json`, `wal_benchmark.json`, `api_metrics_final.json` | carga sintética | 2026-09-16 | `benchmark_*.py`, `telemetry_generator.py` | seed 42 | Depende de la máquina; no ejecutado (fuera de alcance: sin pruebas de carga) | **REPRODUCIBLE PERO NO EJECUTADA** |

**Uso en la documentación.**
- `docs/ENTERPRISE_READINESS.md:33, 109, 273` cita "ROC-AUC 0.9462" como resultado sobre "UNSW-NB15 real". Es la cifra de la **evaluación exploratoria de un solo archivo** (`run_unsw_nb15_1.py`), no la de la evaluación principal (0.8855), y omite que esa misma evaluación tiene PR-AUC 0.4561.
- `docs/UNSW-NB15-EVALUATION.md` usa las cifras de la evaluación principal, que son correctas para los archivos 2 a 4.

## 8. MITRE evidence status

| Elemento | Existe | Respaldado por ejecución en esta fase |
|---|---|---|
| Base de conocimiento | `data/knowledge/attack/` (222 documentos); el RAG la indexa: "222 documentos, embeddings local-lsa-128d" | Sí: se cargó en el pipeline |
| Matriz ATT&CK | `data/attack/attack_cache.json` (83 KB, versionado) y `enterprise-attack.json` (54 MB, ignorado) | Cargada indirectamente (`mitre.tactics_of`) |
| Mapeos | `mitre_technique` en las 7 reglas propias y en las 38 Sigma (`attack.tXXXX`) | Sí |
| Secuencias | `config/sequences.yaml` (5 secuencias) | Sí: 5–6 incidentes temporales en la muestra sintética |
| Markov kill-chain | `models/markov_tactics.json` | Sí: regenerado idéntico; 1 predicción en el pipeline |
| Navigator | 5 capas en `docs/` | Ver §7: 2 HISTÓRICAS y 3 NO TRAZABLES |
| Tests | `test_mitre_attack.py` (22 funciones), `test_sequence_model.py`, `test_phase4d_*` | Pasan |

**Cobertura estructural frente a experimental:**
- **Estructural.** Las reglas etiquetan alrededor de 39 técnicas distintas (contando subtécnicas). Los documentos publican cifras que no concuerdan entre sí: 18/222 en `sigma_phase1_summary.json` y `navigator_after.json`, a partir de una lista escrita a mano, frente a 41/222 (18.5 %) en `docs/AGENT-CAPABILITIES.md` y `navigator_phase4a_after.json`. **No se recalcula aquí.**
- **Experimental (observada en esta fase).** 7 técnicas con las reglas propias y 11 con Sigma, sobre `generate_sample.py`, **datos sintéticos diseñados para activar esas reglas**. Sobre UNSW-NB15 real, la cobertura experimental de ATT&CK es **no evaluable**: el propio script de evaluación lo declara así.

No se publica ningún porcentaje nuevo.

## 9. Sigma evidence status

| Pregunta | Respuesta medida |
|---|---|
| Reglas actuales | 38 Sigma (`config/sigma_rules/selected/*.yml`) + 7 propias (`config/rules/*.yaml`) |
| Reglas cargadas | 45/45 en el pipeline cuando se pasa `sigma_rules_dir` (CLI y API lo pasan; el test E2E no) |
| Reglas compatibles y evaluables sobre flujos de red | 5 (3 Sigma + 2 propias), según `evaluate_sigma_phase1.py` |
| Reglas no evaluables sobre ese dataset | 40 (35 Sigma + 5 propias): requieren telemetría de host o de autenticación |
| Reglas ejecutadas contra eventos sintéticos de host | En el pipeline con `generate_sample.py` se activaron 8 reglas Sigma distintas y las 7 propias |
| TP/TN/FP/FN | Solo en `evaluate_sigma_phase1.py`, sobre flujos **sintéticos** con formato UNSW: C2 ports TP 41, FP 0, FN 459, TN 4 500. Las otras 4 reglas evaluables tienen **0 activaciones**. |
| Métricas globales | precision 1.0, recall 0.0164, F1 0.0323 (sumadas entre reglas, ver L5) |
| Métricas sobre telemetría de host real | **No existen** |

**Qué significa realmente que pase `test_sigma_integration.py` (34 funciones):**
- las reglas se parsean con pySigma;
- se mapean a `SecurityEvent`;
- disparan sobre eventos construidos para casar y no disparan sobre contraejemplos;
- no se evalúan contra un dataset etiquetado.

Es **evidencia de corrección funcional, no de capacidad de detección**.

## 10. API integration status

| Paso | Implementación | Evidencia |
|---|---|---|
| Petición HTTP | FastAPI (`api/app.py`) | Tests con `TestClient` |
| Transporte | middleware `_exigir_tls` (`app.py:751`): HTTP solo desde loopback; si no, 403 | `test_api_security` |
| Autenticación | `security/guard.py` (`issue_token`), JWT HS256 (`security/tokens.py`), revocación en `identity.py` | `test_api_security` |
| RBAC | `Depends(requires(Permission.X))` en cada endpoint; matriz en `security/roles.py` | `test_api_security` |
| Límite de caudal | `charge_events` / `ratelimit.py` antes de normalizar | `test_api_security` |
| Validación + normalización | `IngestService.ingest` → `Normalizer.normalize_record` (la **misma clase** que usa la CLI) | `test_api_ingestion` |
| Durabilidad | WAL (`api/wal.py`): se escribe antes de aceptar | `test_high_availability` (15+ tests) |
| Cola | `IngestQueue` con contrapresión (429) | `test_api_ingestion` |
| Procesamiento | `api/worker.py::_procesar` → **`Pipeline.run_events`** (el mismo método que la CLI) | `test_e2e_agent`, `test_soc_panel` |
| Persistencia | `ResultStore.save_batch` (`api/store.py`, SQLite) y checkpoint del WAL | `test_soc_panel` |
| Respuesta | 202 / 207 / 422 / 429 | `test_api_ingestion` |
| HITL | `POST /api/v1/incidents/{id}/triage` → `DatasetManager.submit_decision` + auditoría | `test_soc_panel`, `test_production_readiness_panel_triage_gap`, `test_e2e_incident_flow` |

**¿Pipeline único o lógica duplicada?** Único. El worker no reimplementa la detección: llama a `Pipeline.run_events`. La API solo añade validación, cola, WAL y persistencia.

**Hallazgos:**
- **Permisos definidos pero no aplicados.** `Permission.RESPONSE_APPROVE` y `Permission.AUDIT_READ` están en la matriz, pero **ningún endpoint los exige**. No hay endpoint para leer la auditoría ni para aprobar acciones.
- **La aprobación humana de respuestas no está expuesta.** `ResponseExecutor.approve_action` solo lo llaman los tests (`test_response_defense.py`); ni la API ni la CLI lo exponen. Las acciones `requires_approval` quedan en estado `requested` sin canal para aprobarlas. El HITL que sí existe es el **triage** de incidentes.
- **La línea base ML depende del primer lote** que llegue al worker (L1).

**Estado: CONECTADO y TESTEADO. No PRODUCCIÓN:** sin TLS real, sin pruebas de carga en esta fase y sin NATS.

## 11. CISA KEV integration status

| Pregunta | Respuesta |
|---|---|
| Implementación | `src/cybersentinel/cti/cisa_kev.py` (`CisaKevFeed`): descarga, caché en disco y consulta local por CVE |
| Tests | 4 en `tests/test_cti_live_feeds.py:150-195` (refresco, no refrescar dos veces, error de red, persistencia) |
| Mock | `httpx.MockTransport`; los tests no hacen llamadas de red |
| ¿Quién lo importa? | Solo el test. En `src/` únicamente aparece mencionado en el docstring de `cti/feeds.py:6`. |
| ¿Participa en `Pipeline`? | **No.** `LiveCTIEnricher` usa AbuseIPDB y OTX, no KEV. |
| Evidencia histórica | `docs/evidence_phase4c_cisa_kev_real.json` y `data/runtime/cisa_kev_cache.json` (2026-09-17): hubo una descarga real en el pasado; no se repitió aquí (sin red externa) |

**Respuesta:** **módulo aislado**, no una capacidad integrada. La limitación está documentada en su propio docstring: ningún colector normaliza CVEs ni versiones de software, así que no hay campo de entrada con el que correlacionar.

## 12. Documentation consistency

Hallazgos sobre los dos documentos de línea base. **No se han modificado**; se proponen correcciones.

### `docs/BASELINE-EXECUTION-REPORT.md`

| Afirmación | Estado frente a esta fase | Corrección propuesta |
|---|---|---|
| 677 passed, 1 skipped, 4 warnings | Correcta | — |
| "La única prueba que necesita un broker real se omite de forma explícita, con un motivo" | Incompleta | Añadir que el skip es incondicional (`skipif(True)`), que falta `pytest-asyncio` y que `streaming/` no está conectado a nada |
| §6: la ejecución "demuestra la API (JWT + RBAC, ingesta, panel SOC con HITL)" | Parcial | Precisar que el HITL es de triage; la aprobación de respuestas no está expuesta |
| §6: "No demuestra … llamadas reales a … CISA KEV" | Correcta para esta ejecución | Mencionar la evidencia histórica de una descarga real |
| Ausencia de comentarios sobre ML | Omisión | Referenciar este informe |

### `AUDIT-BASELINE.md`

| Afirmación | Estado | Corrección propuesta |
|---|---|---|
| §13.1: `analyst` tiene `response:approve` ("triage + HITL") | Engañosa | El permiso existe, pero ningún endpoint lo exige |
| §13.1: "`viewer` tiene `audit:read` y `analyst` no. Puede ser intencional" | La pregunta queda sin objeto | `audit:read` no lo usa ningún endpoint |
| §11 ML: "la documentación menciona calibración … sobre datos sintéticos" | Correcta, pero ahora hay evidencia | Sustituir por las clasificaciones de §7 |
| §11 ML: "aún hay que demostrar que … el threshold no produce demasiados falsos positivos" | Respondida | FPR de test 0.264 en UNSW (archivos 2 a 4) y 0.0583 en UNSW_1 (exploratoria) con el umbral elegido en validation |
| §4.5 / §13: streaming no integrado | Correcta | Reforzar con la evidencia de §3 |
| §12.1: KEV aislado | Correcta | — |
| §9 Sigma | Correcta en lo cualitativo | Añadir las cifras de §9 |

### Otros documentos (fuera de alcance; solo se señalan)

- `docs/ENTERPRISE_READINESS.md:33, 109, 273`: presenta "ROC-AUC 0.9462" (exploratoria, un archivo) como resultado principal.
- `docs/UNSW-NB15-EVALUATION.md:333`: el comando publicado no reproduce las métricas del propio documento si `UNSW-NB15_1.csv` está presente.
- `scripts/calibrate_anomaly_threshold.py:30` habla de "~51 eventos sospechosos"; son 46.
- Docstring de `tests/test_streaming.py`: describe un skip condicional que no existe.
- Cobertura ATT&CK: 18/222 frente a 41/222 entre documentos.

## 13. Critical findings

Ordenados por impacto sobre la validez de lo que el proyecto afirma.

1. **[ALTO] El ML del pipeline se entrena con el lote que puntúa** (L1). Las métricas de UNSW describen el detector con un protocolo limpio, no el comportamiento del pipeline, la CLI o la API.
2. **[ALTO] Evaluación ML no reproducible con el comando documentado.** Sin excluir `UNSW-NB15_1.csv`, F1 pasa de 0.6734 a 0.6426 y recall de 0.986 a 0.897.
3. **[ALTO] La aprobación humana de acciones de respuesta no tiene canal.** `approve_action` solo se llama desde tests, y `response:approve` y `audit:read` no se aplican en la API.
4. **[ALTO] `audit_iforest.py` produce una evaluación inválida** (L2), y tres artefactos versionados son NO TRAZABLES.
5. **[MEDIO] El umbral por defecto (0.602) se calibró con 46 positivos sintéticos fácilmente separables** (L3, L4). En test, el recall es del 66.7 %.
6. **[MEDIO] El test E2E no carga Sigma**, así que la integración de Sigma en el pipeline solo la cubren tests unitarios.
7. **[MEDIO] Los informes de Sigma versionados están desfasados** (22 frente a 45 reglas) y la cobertura sale de una lista escrita a mano.
8. **[MEDIO] Suite no hermética:** escribe en `data/feedback/`, `audit_log.jsonl` y `response_actions.db`.
9. **[MEDIO] Los scripts de evaluación sobrescriben artefactos versionados** en `results/`, `reports/` y `docs/`.
10. **[MEDIO] Sin lockfile ni versión de sklearn en los metadatos.**
11. **[BAJO] NATS y streaming:** skip incondicional, `pytest-asyncio` ausente y módulo desconectado.
12. **[BAJO] Etiqueta presente en `event.tags` y `event.raw`** de los eventos UNSW (L6).

**Positivos confirmados:**
- La evaluación principal UNSW y la exploratoria UNSW_1, la calibración, `train_eval_iforest` y el modelo de Markov se reproducen **byte a byte**.
- El protocolo de `evaluate_unsw_nb15.py` es correcto: split temporal, entrenamiento solo con benignos, normalización y umbral sin tocar test, y sin atajo por IP ni features del TTL.
- La API y la CLI comparten un único pipeline.

## 14. Recommended Phase 2 changes

Cambios mínimos y sin nuevas funcionalidades. Ordenados por prioridad.

| # | Cambio | Tipo | Archivos |
|---|---|---|---|
| 1 | Añadir `--files` (o `--exclude`) a `evaluate_unsw_nb15.py` y actualizar el comando de `UNSW-NB15-EVALUATION.md` para fijar los archivos 2 a 4 | reproducibilidad | `scripts/evaluate_unsw_nb15.py`, `docs/UNSW-NB15-EVALUATION.md` |
| 2 | Añadir `--output-dir` (por defecto `results/`) a los scripts de evaluación, para regenerar sin sobrescribir lo versionado | reproducibilidad | `scripts/*.py` |
| 3 | Registrar las versiones de sklearn, numpy y pysigma en los metadatos de cada ejecución; añadir un lockfile o `requirements-lock.txt` | reproducibilidad | scripts, raíz |
| 4 | Corregir `audit_iforest.py` para que use la misma colocación temporal de ataques que `train_eval_iforest.py`, o retirarlo y marcar sus tres artefactos como no trazables | corrección | `scripts/audit_iforest.py`, `reports/` |
| 5 | Documentar explícitamente, en ML-MODEL-CARD y README, que el pipeline entrena en el primer lote (L1). Decidir en Fase 2 si se carga una línea base pre-entrenada (cambio de comportamiento: requiere aprobación) | honestidad / diseño | docs; `pipeline.py` solo si se aprueba |
| 6 | Pasar `sigma_rules_dir` en `test_full_pipeline_end_to_end`, o añadir un caso paralelo con Sigma | cobertura de test | `tests/test_pipeline.py` |
| 7 | Aislar los almacenes por defecto en los tests (`tmp_path` / `monkeypatch` de `FEEDBACK_STORE`, `audit_path`) | higiene de tests | tests indicados en §2 |
| 8 | Reemplazar `skipif(True)` por una condición real (import de `nats` y conexión), declarar `pytest-asyncio` en el extra `streaming` y corregir el docstring | higiene de tests | `tests/test_streaming.py`, `pyproject.toml` |
| 9 | Decidir el destino de `response:approve` / `audit:read`: exponer el endpoint existente de `approve_action` o eliminar los permisos de la matriz y de la documentación | coherencia (decisión del equipo) | `api/app.py` o `security/roles.py` |
| 10 | Calcular la cobertura de `evaluate_sigma_phase1.py` desde las reglas cargadas, en lugar de `TECHNIQUES_FROM_SIGMA`, y regenerar los informes Sigma con las 45 reglas | trazabilidad | `scripts/evaluate_sigma_phase1.py`, `reports/sigma_phase1_*` |
| 11 | Corregir `ENTERPRISE_READINESS.md` (0.9462 → cifra principal con contexto), el "~51" de la calibración y la discrepancia 18/222 frente a 41/222 | documentación | docs |
| 12 | Migrar `HTTP_422_UNPROCESSABLE_ENTITY` y planificar la salida de `langchain-community` | mantenimiento | `api/app.py`, `rag/vector_store.py` |

---

## Tabla final

Leyenda: ✅ sí · ⚠️ parcial · ❌ no · — no aplica

| Área | Implementado | Conectado | Testeado | Validado experimentalmente | Reproducible | Estado |
|---|---|---|---|---|---|---|
| Pipeline | ✅ | ✅ CLI y API (mismo `run_events`) | ✅ E2E pasa (sin Sigma) | ⚠️ solo con datos sintéticos de demostración | ✅ | Funcional; ML entrenado in-sample (L1) |
| Detection (reglas + híbrido) | ✅ | ✅ | ✅ | ⚠️ reglas propias solo sobre datos sintéticos | ✅ | Funcional bajo test |
| Sigma | ✅ 38 reglas | ✅ CLI y API; ❌ en el test E2E | ✅ funcional | ⚠️ 5 de 45 evaluables sobre flujos sintéticos; recall 0.016 | ⚠️ métricas sí; informe desfasado | Corrección funcional demostrada; detección no |
| ML (Isolation Forest) | ✅ | ✅ (entrenamiento en el lote) | ✅ | ✅ UNSW-NB15 real: F1 0.673, FPR 0.264 (archivos 2 a 4) | ⚠️ byte a byte solo excluyendo `_1` | Validado offline; no es el protocolo del pipeline |
| MITRE | ✅ | ✅ | ✅ | ❌ sobre datos reales; ⚠️ 7–11 técnicas observadas en sintético | ✅ Markov idéntico | Cobertura estructural; la experimental no está demostrada |
| CTI (STIX local) | ✅ | ✅ | ✅ | ❌ (indicadores de laboratorio) | ✅ | Funcional con datos de laboratorio |
| CTI live (AbuseIPDB / OTX) | ✅ | ⚠️ desactivado por defecto | ✅ con mocks | ❌ | — | Experimental |
| CISA KEV | ✅ | ❌ | ✅ con mocks | ❌ (descarga real histórica) | — | Módulo aislado |
| RAG | ✅ | ✅ | ✅ | ❌ no medido contra verdad-terreno | ✅ embeddings locales deterministas | Funcional; calidad sin medir |
| LLM | ✅ | ✅ | ✅ con fallback | ❌ (sin credenciales: `UNAVAILABLE`, determinista) | ✅ fallback | Solo el fallback determinista está ejercitado |
| Governance | ✅ | ✅ | ✅ | — (lógica de política) | ✅ | Funcional; auditoría verificada |
| Response | ✅ | ⚠️ ejecución Nivel 1 en dry-run; aprobación Nivel 2 sin canal | ✅ | ❌ | ✅ | Parcial |
| API | ✅ | ✅ mismo pipeline | ✅ `TestClient` | ❌ | ✅ | Conectada y testeada; **no producción** |
| NATS / streaming | ✅ | ❌ ningún módulo lo importa | ⚠️ lógica pura sí; integración omitida | ❌ | ❌ falta `nats-py` y `pytest-asyncio` | No integrado |

**Ningún área está en PRODUCCIÓN.**

---

## Apéndice: comandos de reproducción

```bash
# Suite
PYTHONPATH=src .venv/bin/python -m pytest -q -p no:cacheprovider -rs

# Evaluación ML principal. Ejecutar en una copia del repo: escribe en results/.
# Para reproducir las métricas versionadas, data/unsw_nb15/ debe contener SOLO
# UNSW-NB15_2.csv, _3 y _4.
python scripts/evaluate_unsw_nb15.py --limit 300000 --seed 42

# Exploratoria UNSW_1, calibración, iforest sintético, Sigma y Markov
# (todas escriben en archivos versionados)
python scripts/run_unsw_nb15_1.py --stage full
python scripts/calibrate_anomaly_threshold.py
python scripts/train_eval_iforest.py
python scripts/evaluate_sigma_phase1.py
PYTHONPATH=src python -m cybersentinel.cli train-prediction --save-model <ruta> --json <ruta>
```
