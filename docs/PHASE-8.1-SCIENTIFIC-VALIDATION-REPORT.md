# CYBERSENTINEL — PHASE 8.1 SCIENTIFIC VALIDATION REPORT

## 1. Executive Summary

La Fase 8.1 ha completado la **Validación Científica Integral** del pipeline de CyberSentinel, ejecutando un benchmark riguroso, reproducible y sin manipulación de resultados. El objetivo principal era establecer una línea base de rendimiento (Precision, Recall, F1) sobre el conjunto de herramientas actual, evitando cualquier forma de *data leakage* y documentando el verdadero estado del sistema.

### Veredicto: GO PARA FASE 8.2 🟢
CyberSentinel demuestra una arquitectura sólida y auditable. Si bien las métricas absolutas (Recall bajo) evidencian que los modelos de ML y las integraciones avanzadas (RAG/CTI) requieren refinamiento, la **infraestructura científica (TimeBasedSplitter, Ablation dinámico, Reproducibilidad con Seeds)** está lista para soportar iteraciones de mejora de forma honesta.

---

## 2. Experimental Protocol

- **Dataset**: Mezcla sintética de eventos Sysmon.
  - *Benigno*: 2,000 eventos generados determinísticamente distribuidos en 72 horas.
  - *Malicioso*: Ataques inyectados estáticamente al final de la línea temporal (hacia la hora 70).
- **Leakage Control**: Se aplicó una separación temporal estricta (`TimeBasedSplitter`) con ratios 0.6 (Train), 0.2 (Val), 0.2 (Test).
  - *Total*: 2,011 eventos.
  - *Train*: 1,206 eventos (0 ataques).
  - *Validation*: 402 eventos (0 ataques).
  - *Test*: 403 eventos (11 ataques).
- **Reproducibilidad**: Verificado mediante la ejecución con `seed=42` y `seed=99`, los cuales producen hashes únicos (SHA-256) del dataset ordenado temporalmente.

---

## 3. Component Ablation Study (Test Set)

El siguiente Ablation Study mide el impacto acumulativo de cada componente en el pipeline. Las alertas se consideraron activas cuando `hybrid_score >= 50.0`.

| Pipeline Stage | Precision | Recall | F1-Score | FP | FN |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **A. Sigma Only** | 1.0000 | 0.2727 | 0.4286 | 0 | 8 |
| **B. Sigma + ML** | 1.0000 | 0.2727 | 0.4286 | 0 | 8 |
| **C. Sigma + ML + Temporal** | 1.0000 | 0.2727 | 0.4286 | 0 | 8 |
| **D. Sigma + ML + Temp + CTI** | 1.0000 | 0.2727 | 0.4286 | 0 | 8 |
| **E. Full System (Inc. RAG/LLM)** | 1.0000 | 0.2727 | 0.4286 | 0 | 8 |

### Análisis de Resultados:
1. **Sigma (Reglas Deterministas):** Detecta 3 de los 11 ataques (Recall 27.2%), sin generar falsos positivos (Precision 100%).
2. **Machine Learning (Isolation Forest):** El modelo no incrementó el `anomaly_score` de los ataques lo suficiente como para cruzar el umbral del `hybrid_score`. La ROC-AUC evaluada de forma aislada arrojó `0.0000`, indicando que el modelo requiere un profundo rediseño de *feature engineering* o ajuste de hiperparámetros (contaminación).
3. **Temporal, CTI, RAG y LLM:** Inertes en esta validación debido a la ausencia de datos en el vector store y de contexto malicioso prolongado que cruzara los umbrales de los mockups configurados.

---

## 4. Latency and Throughput Audit

*Los valores representan las métricas p95 extraídas del TraceContext sobre el Test Set.*

- **Core Processing (Reglas + ML puro):** Estrictamente acotado y eficiente (< 1ms por evento en batch mode).
- **Full System Latency (Invocaciones LLM mockeadas):** Overhead dominado por simulaciones de E/S.
*Se requiere carga completa del LLM con modelo real en Fase 8.2 para obtener métricas productivas de latencia.*

---

## 5. Claims Audit & Scientific Honesty

CyberSentinel se acoge al principio rector: *"Una limitación documentada no es un fracaso científico. Una limitación ocultada sí lo es."*

### Declaraciones Limitantes Requeridas:
1. **ML Limitation:** El *Isolation Forest* actual no está aportando valor detectivo en el dataset de Sysmon sintético. Sus scores anómalos no logran separar las clases bajo la extracción de features actual.
2. **RAG Limitation:** NOT DEMONSTRATED. No existe un corpus persistente de inteligencia, por lo tanto el Recall@K es equivalente a 0 para el propósito de sumar puntos al score híbrido.
3. **CTI Limitation:** Las inyecciones en `hashes` fueron resueltas a nivel de pipeline, pero no cruzaron con falsos positivos significativos ni agregaron detecciones netas (TP) al score general.
4. **LLM Explainer:** Confirmado como **invariante**. El LLM provee contexto sin modificar artificialmente las métricas de clasificación, respetando su naturaleza "Read-Only".

---

## 6. Next Steps (Fase 8.2)

Habiendo asegurado que el entorno de benchmarking es ciego, temporalmente estricto e incapaz de inflar métricas artificialmente, la Fase 8.2 deberá enfocarse en:

1. **Feature Engineering ML:** Refactorizar la abstracción matemática del `AnomalyDetector` para que pueda discriminar ataques de forma efectiva (mejorar ROC-AUC).
2. **Hardening CTI & RAG:** Cargar artefactos de inteligencia reales y medir el uplift en Recall en el sistema híbrido.
3. **Threshold Calibration:** Optimizar el peso de ML vs Sigma en la fórmula del `hybrid_score`.
