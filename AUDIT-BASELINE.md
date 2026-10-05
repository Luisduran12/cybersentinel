# AUDIT-BASELINE.md

## 1) Alcance y metodología

Esta es una auditoría técnica del estado actual del repositorio de CyberSentinel, realizada sin modificar código ni cambiar la lógica del proyecto. La revisión se basa en:

- el árbol de archivos del repositorio,
- la estructura del pipeline principal,
- la configuración y módulos del código,
- los tests existentes,
- la documentación y los scripts de reproducibilidad,
- la conectividad real de la arquitectura.

Importante: esta fase es una auditoría de línea base. No debe interpretarse como una validación productiva ni como la afirmación de que un componente funciona correctamente simplemente porque existe su archivo o clase.

## 2) Estado real del proyecto: resumen corto

CyberSentinel tiene una arquitectura muy ambiciosa y bien estructurada, con un diseño claramente pensado para un flujo defensivo completo:

INPUT
→ NORMALIZATION
→ SECURITY EVENT
→ DETECTION
→ EVIDENCE
→ GOVERNANCE
→ RESPONSE DECISION
→ AUDIT

El proyecto está claramente más allá de un prototipo mínimo: incluye:

- normalización de eventos,
- motor de reglas + Sigma,
- ML no supervisado,
- correlación temporal,
- ATT&CK y kill-chain,
- CTI y live CTI,
- RAG local,
- explicabilidad/LMM optional,
- gobernanza y auditoría,
- respuesta planeada,
- API y panel SOC.

Sin embargo, la realidad es la siguiente:

- mucho está IMPLEMENTADO,
- menos está VALIDADO de manera reproducible,
- varios componentes están CONECTADOS solo parcialmente,
- otros están EXPERIMENTALES o PLACEHOLDERS,
- la documentación a veces describe el proyecto como si estuviera más cerca de producción que lo que realmente está validado.

La diferencia clave es:

IMPLEMENTADO ≠ VALIDADO
CONECTADO ≠ CORRECTO
EXPERIMENTAL ≠ PRODUCCIÓN

## 3) Tests disponibles: inventario y situación

El repositorio incluye una amplia batería de tests en `tests/`.

Lista observada (por nombre):

- `test_anomaly_threshold_calibration.py`
- `test_api_ingestion.py`
- `test_api_security.py`
- `test_audit_cti_fp.py`
- `test_audit_grounding.py`
- `test_audit_integrity.py`
- `test_audit_prompt_injection.py`
- `test_behavioral_analytics.py`
- `test_benchmark.py`
- `test_collectors.py`
- `test_cti_enrichment.py`
- `test_cti_ingestor.py`
- `test_cti_lifecycle.py`
- `test_cti_live_feeds.py`
- `test_datasets.py`
- `test_detection_evaluation.py`
- `test_detection_quality.py`
- `test_e2e_agent.py`
- `test_e2e_incident_flow.py`
- `test_explainer_safety.py`
- `test_high_availability.py`
- `test_human_feedback.py`
- `test_ingestion.py`
- `test_llm_explainer.py`
- `test_mitre_attack.py`
- `test_ml_features.py`
- `test_ocsf.py`
- `test_phase4d_prediction_and_risk.py`
- `test_phase8_hardening.py`
- `test_pipeline.py`
- `test_production_readiness_normalizer_gap.py`
- `test_production_readiness_panel_triage_gap.py`
- `test_rag_evaluation.py`
- `test_rag_pipeline.py`
- `test_response_defense.py`
- `test_sequence_model.py`
- `test_sigma_expansion.py`
- `test_sigma_integration.py`
- `test_sigma_phase1_evaluation.py`
- `test_soc_panel.py`
- `test_streaming.py`
- `test_sysmon_detection.py`
- `test_sysmon_properties.py`
- `test_temporal_correlation.py`
- `test_unsw_nb15_adapter.py`

Conclusión: el repositorio tiene una suite amplia y ambiciosa, con cobertura de varios subsistemas. Sin embargo, la cantidad de tests no equivale a validación real del sistema completo ni a una base de producción objetiva.

### 3.1 Estado de ejecución real

No fue posible ejecutar una suite `pytest` en esta sesión desde los medios disponibles del entorno de auditoría. Esto debe indicarse explícitamente: no existe una verificación ejecutada real del proyecto en esta sesión.

Por lo tanto, la línea base a continuación se basa en:

- inventario de archivos,
- inspección directa de módulos,
- documentación del proyecto,
- contenido de tests,
- arquitectura y contratos de integración.

Esto es una línea base válida para un primer diagnóstico, pero no sustituye a una ejecución real.

## 4) Matriz de estado por módulo

### 4.1 IMPLEMENTADO

Estos módulos están presentes y claramente conectados o pensados para conectarse al flujo principal:

- `src/cybersentinel/schema.py` — SecurityEvent y timestamps normalizados
- `src/cybersentinel/config.py` — configuración central
- `src/cybersentinel/observability.py` — trazabilidad por etapa
- `src/cybersentinel/detection/rules_engine.py` — motor de reglas
- `src/cybersentinel/detection/anomaly.py` — Isolation Forest
- `src/cybersentinel/detection/hybrid.py` — evidencia híbrida
- `src/cybersentinel/detection/temporal.py` — correlación temporal
- `src/cybersentinel/correlation/mitre.py` — ATT&CK mapeo
- `src/cybersentinel/correlation/correlator.py` — correlación y predicción
- `src/cybersentinel/correlation/sequence_model.py` — secuencias / Markov / baseline
- `src/cybersentinel/cti/stix_ingestor.py` — ingesta STIX
- `src/cybersentinel/cti/enrichment.py` — enriquecimiento CTI
- `src/cybersentinel/cti/cache.py` — caché de CTI
- `src/cybersentinel/rag/embeddings.py`
- `src/cybersentinel/rag/vector_store.py`
- `src/cybersentinel/llm/explainer.py`
- `src/cybersentinel/llm/providers.py`
- `src/cybersentinel/governance/policy.py`
- `src/cybersentinel/governance/audit.py`
- `src/cybersentinel/response/*.py`
- `src/cybersentinel/cli.py`
- `src/cybersentinel/pipeline.py`

### 4.2 PARCIAL

Estos módulos están implementados, pero no están del todo integrados o están acotados a un subconjunto de funcionamiento:

- `src/cybersentinel/api/*` — hay API, pero no es el eje central del pipeline observado en `pipeline.py`
- `src/cybersentinel/collectors/*` — existe soporte para múltiples colectores, pero no queda claro que todos estén validados en producción real
- `src/cybersentinel/cti/abuseipdb.py` / `cti/otx.py` — implementados, pero están sujetos a API real y a configuración externa
- `src/cybersentinel/response/executor.py` — existen decisiones y acciones, pero la ejecución real final debe revisarse contra la política y el modo dry-run
- `src/cybersentinel/governance/dataset_manager.py` — parece un sumidero / infraestructura para HITL, pero no es un flujo principal claro

### 4.3 EXPERIMENTAL

Estos módulos se entienden como exploratorios o de laboratorio, no como componentes de producción estables:

- CTI live feeds sobre APIs reales (AbuseIPDB, OTX)
- RAG con embeddings locales y recuperación semántica
- uso opcional de LLM externo
- predicción de kill-chain basada en secuencias generadas sintéticamente
- modelos de aprendizaje no supervisado sobre telemetría sintética / semi-sintética

### 4.4 PLACEHOLDER

Módulos que existen, pero no se observa una integración funcional completa o reaprovechable:

- `src/cybersentinel/governance/dataset_manager.py`
- varios módulos de `api/` cuya conexión real al pipeline no queda clara
- varios módulos de integración de response / monitorización / panel que están documentados pero no verificados como parte del flujo principal

### 4.5 NO INTEGRADO

Módulos o componentes que parecen estar construidos como capacidades, pero no forman parte del flujo observable actual del pipeline principal:

- muchas partes de `api/` y `streaming/` parecen estar previstas para producción o desacoplo, pero la integración principal del pipeline no depende de ellas
- algunos módulos de `correlation/navigator.py`, `prediction_context.py`, etc., están documentados, pero no necesariamente conectados de forma determinista al `pipeline.py` principal
- algunos scripts y documentación anticipan arquitectura de producción que no está integrada ni validada en flujo real

## 5) Conexiones reales del pipeline

El pipeline principal `src/cybersentinel/pipeline.py` muestra una integración real de varios componentes. La conexión observada es la siguiente:

- `Normalizer()`
- `RulesEngine.from_directory()`
- `AnomalyDetector()`
- `TemporalCorrelator.from_yaml()`
- `StixIngestor()` y `CTIEnricher()`
- `EntityProfiler()` + `DeviationDetector()`
- `LiveCTIEnricher()` si `enable_live_cti`
- `RAGStore()` con embeddings locales
- `LLMExplainer()` con `build_chat_model()`
- `ResponsePlanner(self.policy)`
- `ResponseExecutor()`
- `AuditLog()`
- `RiskScoreTracker()`
- `Correlator()` para kill-chain y predicción

Esto significa que el flujo central está realmente montado, aunque no necesariamente validado para producción.

## 6) Conexiones faltantes o no consolidadas

Se observa que faltan o no están consolidadas las siguientes capas:

- integración real y reproducible de API/streaming con pipeline completo,
- validación de `nats-py` / streaming en producción,
- validación de `SOC panel` con flujo real de incidentes persistentes en ejecución real,
- validación de CTI live feeds contra telemetría real,
- validación consistente de reglas Sigma sobre eventos sintéticos realmente compatibles,
- validación experimental de datasets reales con métricas representativas,
- trazabilidad de `Navigator` layer automática desde evidencia real del pipeline.

## 7) Configuración, dependencias y scripts

### 7.1 Configuración

El proyecto define `config/config.yaml` y `src/cybersentinel/config.py` como capa real de configuración.

Puntos positivos:

- la configuración centraliza defaults,
- la precedencia CLI > config.yaml > defaults está declarada,
- se separan detección, correlación, predicción y explicación.

Puntos de atención:

- los defaults y los settings son útiles, pero se debe verificar que todas las capas realmente los consuman de forma uniforme,
- no todo el código del proyecto parece seguir exactamente el mismo contrato de configuración.

### 7.2 Dependencias

`requirements.txt` y `pyproject.toml` incluyen las dependencias esperadas:

- scikit-learn
- numpy
- pandas
- PyYAML
- rich
- pysigma
- stix2
- fastapi / uvicorn
- httpx
- psutil
- langchain-core / community / text-splitters / faiss-cpu

Conclusión:

- la dependencia principal del proyecto es razonable y encaja con la arquitectura planteada,
- pero hay dependencias que no son claramente necesarias para todas las ejecuciones,
- varios componentes (LLM, attack, streaming, NATS) aparecen como opcionales pero con fuerte impacto documental.

### 7.3 Scripts

El repositorio incluye varios scripts de generación, evaluación y demostración, por ejemplo:

- `data/generate_sample.py`
- `data/generate_flow_sample.py`
- `data/generate_campaigns.py`

Esto es positivo para reproducibilidad, pero no reemplaza la validación experimental real sobre data pública etiquetada.

## 8) Cobertura MITRE ATT&CK

La documentación menciona que hay:

- `data/attack/attack_cache.json`
- matriz ATT&CK soportada por STIX
- soporte de capa Navigator
- `navigator_before.json`, `navigator_after.json`, etc.

El proyecto está claramente orientado a mapear técnicas y secuencias ATT&CK. Sin embargo, hay un punto clave:

- la cobertura estructural del código no implica cobertura validada.

En otras palabras:

- la existencia de un mapeo MITRE no significa que cada técnica esté validada por laboratorio o dataset.
- el proyecto tiene intención de trazabilidad evento → evidencia → técnica, pero la validación experimental real aún debe demostrarse.

## 9) Reglas Sigma realmente evaluables

El repositorio incluye:

- reglas propias en `config/rules/`
- reglas Sigma en `config/sigma_rules/selected/`
- `manifest.yaml` para catálogo

La idea es buena: integrar Sigma público y reglas propias. Pero hay un punto importante:

- no todas las reglas Sigma son automáticamente evaluables sobre cualquier fuente de telemetría.
- muchas reglas requieren campos de evento específicos que no siempre existen en `SecurityEvent` o en la normalización.
- la condición de parseo es necesaria, pero no suficiente para afirmar que son validas.

Clasificación honesta:

### 9.1 EVALUABLES

Reglas que dependen de campos típicos de evento y de normalización común:

- autenticación fallida / brute force,
- detección de proceso / ejecución,
- cambios de servicio,
- actividades de red / port scan,
- creación de cuentas,
- descubrimiento de red / systeminfo / lsass,
- RDP / lateral movement, etc.

### 9.2 PARCIALMENTE EVALUABLES

Reglas que requieren:

- nombres de proceso más específicos,
- campos de Windows Event Logs o Sysmon muy concretos,
- metadata de eventos no cubierta por el esquema común,
- condiciones complejas que dependen del origen exacto del log.

### 9.3 NO EVALUABLES EN LA ACTUALIDAD

Reglas que no pueden evaluarse de forma fiable sin un conjunto de telemetría exacto y compatible con la normalización del proyecto, por ejemplo:

- reglas muy dependientes de fuentes de logs no normalizadas,
- reglas que exigen `process.command_line` / `parent_process` / `file.path` / `registry` en formatos no observados,
- reglas de `Linux` o Windows particulares que no tienen representación equivalente en `SecurityEvent`.

### 9.4 INCOMPATIBLES

Reglas que no pueden evaluarse correctamente por incompatibilidad de esquema, ausencia de campo, o reglas Sigma demasiado específicas para el modelo de datos actual.

## 10) Datasets disponibles

El repositorio incluye y menciona datasets y muestras:

- `data/sample_logs.jsonl`
- `data/synthetic_sysmon_eval.json`
- `data/cti/lab_indicators.json`
- `data/knowledge/*` (documentos de ATT&CK)
- `data/attack/attack_cache.json`

Además, la documentación referencia datasets públicos que se usan para evaluación, por ejemplo:

- UNSW-NB15,
- CICIDS2017,
- Security-Datasets / OTRF,
- Atomic Red Team style synthetic telemetry.

Puntos importantes:

- la disponibilidad de datasets no significa que el proyecto haya ejecutado validación real sobre todos ellos,
- el proyecto usa mucho telemetry sintética o generada localmente,
- hay documentación de metodología, pero la validación experimental final requiere un protocolo transparente y reproducible.

## 11) ML y datos de entrenamiento

El motor de anomalías usa `IsolationForest` a través de `src/cybersentinel/detection/anomaly.py` y `src/cybersentinel/ml/*`.

Observaciones:

- el entrenamiento no supervisado se basa en eventos normales del lote / dataset,
- la calibración de threshold de anomalía (`DEFAULT_ANOMALY_THRESHOLD`) es un punto específico y requiere validación,
- la documentación menciona calibración y que el umbral se ajustó sobre datos sintéticos,
- esto es útil, pero no sustituye validación con datos reales y no contaminados.

La estructura de ML está presente y debe considerarse como una base sólida, pero aún hay que demostrar que:

- el modelo generaliza a tráfico validado,
- el threshold no produce demasiados falsos positivos,
- la representación de features es suficientemente estable.

## 12) CTI, RAG, LLM, governance y response

### 12.1 CTI

- STIX ingestor está implementado y se usa en `pipeline.py`.
- Live CTI existe, pero con conectividad real a feeds externos.
- Esto es un componente EXPERIMENTAL / no necesariamente apropiado para una ejecución automática sin configuración y sin control.

### 12.2 RAG

- Hay base de embeddings locales y vector store.
- `Pipeline` utiliza RAG en el flujo.
- El sistema probablemente puede recuperar contexto relevante de documentos ATT&CK / conocimiento.
- La parte importante es validar que la recuperación realmente mejora la evidencia y la explicación, no solo que no falla en la ejecución.

### 12.3 LLM

- La capa de explicación tiene fallback determinista.
- Si no hay credenciales, usa un mecanismo determinista y registra `llm_status`.
- Esto es una buena práctica de seguridad y honestidad, pero requiere validación de calidad de explicaciones y separación entre evidencia y generación del texto.

### 12.4 Governance

- `governance/policy.py` es una buena base para una política de acciones defensivas.
- La acción se clasifica en `ALLOWED`, `REQUIRES_APPROVAL`, `PROHIBITED`.
- Esto es un punto fuerte del proyecto, y una buena línea de defensa.

### 12.5 Response

- La capa de respuesta está implementada para clasificar y planificar acciones.
- La ejecución real debe ser tratada con cuidado y no asumirse como operativa sin validación.

## 13) API y streaming

El repositorio tiene un diseño de API y streaming muy orientado a producción futura. Esto incluye:

- API FastAPI,
- autenticación,
- RBAC,
- WAL / colas,
- panel SOC,
- streaming / NATS,
- OCSF adapter.

Sin embargo:

- la integración real con `pipeline.py` no parece ser el flujo principal del conjunto de actualización documentado,
- hay mucha infraestructura incluidas, pero no todas aparecen conectadas y validadas en ejecución real.

Conclusión:

- el proyecto tiene una base de arquitectura avanzada,
- pero aún no está demostrado que todo ese nivel de producción esté realmente integrado y estabilizado.

## 14) Documentación y reproducibilidad

El repositorio tiene mucha documentación, lo que es un punto muy positivo:

- `README.md`
- `docs/ARCHITECTURE.md`
- `docs/PRODUCTION-ARCHITECTURE.md`
- `docs/SECURITY.md`
- `docs/DATASETS.md`
- `docs/BENCHMARK.md`
- documentación de ATT&CK, ML, SOC Panel, etc.

Esto es un activo enorme para la reproducibilidad y la trazabilidad.

No obstante:

- la documentación es muy extensa y a veces describe capacidades que no están demostradas como operativas,
- la línea entre “arquitectura prevista” y “capacidad validada” se debe mantener bien clara.

## 15) Problemas priorizados

### P1 — Sobrepromesa de validación

El proyecto documenta muchas capacidades y parece cercano a producción, pero la validación completa no está demostrada de forma ejecutada y reproducible en esta fase de auditoría.

### P2 — Distinción insuficiente entre implementado y validado

Hay módulos implementados y claramente conectados, pero no se demuestra su correcto comportamiento bajo datasets reales y escenarios de producción.

### P3 — Regla Sigma y telemetría

La integración Sigma está muy bien planteada, pero la evaluabilidad real depende del esquema de eventos y del origen del log. No todas las reglas son automáticamente válidas.

### P4 — Deep architecture vs real execution

API, streaming, panel, OCSF, NATS y capas de producción están diseñados con buena intención, pero la integración concreta y la validación real todavía requieren trabajo.

### P5 — CTI live y LLM con red/credenciales

Son áreas de alto valor, pero pueden introducir riesgos reales de disponibilidad, coste y dependencia externa si se activan sin control.

### P6 — Detectar “trabajo de laboratorio” como si fueran capacidades de producción

El repositorio está claramente orientado a demostración y laboratorio, pero en algunos puntos la documentación se lee como si ya estuviera estabilizado para despliegue real.

## 16) Estado final de la auditoría base

Conclusión honesta:

CyberSentinel es un proyecto muy bien estructurado, con arquitectura clara, modularidad razonable, variedad de componentes, amplia documentación y una suite de tests abundante. Tiene una base sólida para continuar el desarrollo y la investigación.

Pero no se puede afirmar que el sistema está validado ni que todo el flujo es robusto en producción.

El proyecto se encuentra mejor descrito como:

- una plataforma defensiva modular con arquitectura muy completa,
- con muchas piezas implementadas y conectadas al pipeline principal,
- con componentes avanzados de ML, CTI, MITRE, RAG y gobernanza,
- pero todavía con una validación experimental y operativa incompleta en varios puntos.

Esto no es un fallo. Es una evaluación de línea base honesta: el proyecto está en una etapa avanzada, pero aún requiere estabilización, validación experimental y enfoques de producción más estrictos.

## 17) Criterio de decisión para la siguiente fase

La siguiente etapa de mejora debe centrarse en:

1. estabilizar el core del pipeline,
2. corregir contratos entre módulos,
3. validar schemas y configuración,
4. eliminar silencios de error y falsos positivos de serialización,
5. reducir sobrepromesa de producción,
6. convertir la suite de tests en evidencia ejecutada y reproducible,
7. reforzar Sigma validada sobre telemetría real compatible.

## 18) Declaración final de la auditoría

No se ha modificado código ni se ha alterado el repositorio durante esta fase de auditoría.

Se ha hecho una revisión de arquitectura, configuración, módulos, documentación y estado de integraciones, con una distinción explícita entre lo que existe, lo que está conectado, lo que está validado y lo que sigue siendo experimental.

Este documento es el punto de partida para la siguiente fase de estabilización.

---

Fin de AUDIT-BASELINE.md
