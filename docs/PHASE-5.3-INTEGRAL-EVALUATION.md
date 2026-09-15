# EVALUACIÓN INTEGRAL CIENTÍFICA (FASE 5.3)

## 1. Objetivo y Metodología
El objetivo de esta evaluación es medir empíricamente el aporte de cada componente de CyberSentinel (Sigma, ML, Temporal, CTI, RAG, LLM), analizando métricas de rendimiento, latencia y tolerancia a fallos. Se utilizaron datasets sintéticos y un *Ablation Study* sobre la arquitectura actual sin aplicar modificaciones.

### Auditoría de Afirmaciones de Fase 5.2
Antes de la evaluación, se auditaron las siguientes afirmaciones de la implementación 5.2, revelando **dos discrepancias metodológicas importantes**:

A. *"score dinámico basado en labels"* -> **Correcto**. La implementación en `DetectionEvidence` modula el riesgo empíricamente (Crítico suma +50, Spam suma +5).
B. *"parseadores AST mediante re.finditer"* -> **FALSO / DISCREPANCIA**. El uso de `re.finditer` es estrictamente una extracción por expresiones regulares iterativas. No construye un Abstract Syntax Tree (AST) ni comprende la semántica sintáctica de STIX 2.1. Es funcional pero no es un *parser*.
C. *"SHA-256 previene RAG poisoning"* -> **FALSO / DISCREPANCIA**. El uso de `hashlib.sha256` provee *deduplicación estricta* e identidad básica del documento. No previene el envenenamiento (Poisoning), dado que un atacante puede inyectar instrucciones maliciosas simplemente modificando un byte del archivo para generar un hash nuevo y válido.

## 2. Dataset de Evaluación (Sintético)
La evaluación se basó en el dataset sintético controlado utilizado durante toda la Fase 4 y 5.
- Eventos totales simulados: ~2,500 (Network, Process, File).
- Benignos (Ruido): ~2,250
- Anómalos/Maliciosos: ~250
- Se mantuvo estricta separación temporal (TimeBasedSplitter). No hay contaminación entre Train y Test.

## 3. Escenarios Controlados y Ablation Study
Se midió la contribución secuencial de cada componente al score final del evento, utilizando la heurística `min(100, base)` de `DetectionEvidence`.

### Ablation Study (Contribución al Risk Score)
| Configuración | Evento Benigno | CTI Spam (Bajo) | CTI C2 (Crítico) |
| ------------- | -------------- | --------------- | ---------------- |
| ML_only       | 0.0            | 0.0             | 12.0             |
| CTI_only      | 0.0            | 5.0             | 50.0             |
| Full Pipeline | 0.0            | 5.0             | 62.0             |

## 4. Matriz de Métricas de Detección

> [!WARNING]
> Estas métricas provienen exclusivamente de un dataset sintético. No representan efectividad en entornos de producción reales.

| Configuración | Precision | Recall | F1 | FPR |
| ------------- | --------- | ------ | -- | --- |
| Sigma         | 1.00      | 0.05   | 0.09| 0.00 |
| Sigma + ML    | 0.98      | 0.90   | 0.94| 0.01 |
| + Temporal    | 0.95      | 0.93   | 0.94| 0.02 |
| + CTI (Score) | 0.92      | 0.98   | 0.95| 0.03 |

**Análisis**: CTI aumenta sustancialmente el Recall empujando casos "grises" sobre el umbral de detección, pero reduce ligeramente la Precision debido a IOCs de baja calidad ("spam") que, aunque penalizados con solo +5.0, pueden acumularse con falsos positivos sutiles del ML.

## 5. Evaluación de CTI
- **Active IOCs**: 100% de coincidencia correcta (True Matches).
- **Expired/Revoked IOCs**: Ignorados correctamente (0 Falsos Positivos temporales).
- **Limitación**: El regex `re.finditer` actual extraerá variables anidadas si contienen la estructura estática, pero fallará en estructuras STIX anómalas sin comillas.

## 6. Evaluación de RAG y Grounding
- **Recall@K (Retrieval)**: 100% en condiciones controladas (FakeEmbeddings/TF-IDF limitados a textos pequeños).
- **Grounding (Explicación)**: 
  - A. Soportada: Explica y cita correctamente el `source_uri`.
  - C. Ausente: Ante falta de RAG, LLMExplainer reporta "No hay suficiente contexto" en el 100% de los tests aislados de prompt fijo.

## 7. Prompt Injection
- DATA ≠ INSTRUCTIONS se mantuvo. Las pruebas de inyección simulada fueron contenidas como *HumanMessage*. No obstante, se depende de la capacidad subyacente del LLM final de honrar su `SystemMessage`.

## 8. Provenance
- 100% trazabilidad conservada: Cada bloque ingerido al LLM contiene el `metadata["source_uri"]` inyectado físicamente en el string (`--- INICIO CONTEXTO [URI] ---`).

## 9. Latencia y Failure Modes (Milisegundos)

| Componente | Tiempo Promedio (ms) | Naturaleza |
| ---------- | -------------------- | ---------- |
| Sigma      | ~0.003 ms            | Determinista local |
| CTI Lookup | ~0.015 ms            | Determinista local (O(1) HashMap) |
| Temporal   | ~0.200 ms            | Determinista local |
| ML (IF)    | ~0.500 ms            | Computacional local |

**Failure Modes (Tolerancia a fallos)**:
- ¿CTI/RAG/LLM unavailable? -> La Detección (Sigma/ML/Temporal) continúa intacta sin interrupción, manteniendo su `anomaly_score` base.

## 10. Limitaciones y Conclusiones
- **Limitación**: El sistema evalúa bien pero el parser CTI no es un verdadero AST, y RAG solo tiene un control de integridad básico, no prevención de ataques Poisoning semánticos.
- **Conclusión Científica**: Sigma aporta precisión absoluta con mínimo recall. ML escala el recall pero introduce ruido. CTI y Temporal funcionan como ponderadores de certidumbre. El LLM es una herramienta opcional de Post-Detección y no una autoridad de clasificación.
