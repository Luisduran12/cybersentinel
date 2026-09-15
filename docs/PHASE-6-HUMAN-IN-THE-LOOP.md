# FASE 6: HUMAN-IN-THE-LOOP Y DATASET DE FEEDBACK

## 1. El Problema
Los sistemas automatizados de detección de anomalías y reglas deterministas (Fases 1-5) generan alertas, pero sin supervisión humana es imposible diferenciar con certeza absoluta los Falsos Positivos de los comportamientos benignos pero anómalos, o de las amenazas reales.
Para poder entrenar modelos de aprendizaje supervisado (como Random Forest o LSTMs) en futuras fases, **es fundamental contar primero con un dataset de alta calidad, etiquetado por analistas**. No podemos permitir que una etiqueta humana contamine retrospectivamente la evidencia original, ni que la evidencia disponible en un momento futuro modifique el entendimiento del evento pasado (*Data Leakage*).

## 2. Arquitectura de Human-in-the-Loop
CyberSentinel ha incorporado un mecanismo estructurado de retroalimentación humana destinado a construir progresivamente un dataset supervisado confiable para futuras iteraciones de aprendizaje. **Aún no entrena modelos automáticamente.**

El flujo es unidireccional y preserva la inmutabilidad:
`RAW EVENT` -> `DETECTION EVIDENCE` -> `ANALYST DECISION` -> `LABELED SAMPLE`

### Estructura de Decisión (`StructuredDecision`)
Implementado como un `frozen dataclass`, encapsula:
- Identidad del evento y la detección (`event_id`, `detection_id`).
- Identidad de la regla/modelo (`model_version`, `rule_version`).
- Decisión (`HumanDecision` enum: `TRUE_POSITIVE`, `FALSE_POSITIVE`, `BENIGN`, `UNCERTAIN`).
- Evidencia observada congelada (`selected_evidence`).
- Firma SHA-256 única para prevenir mutaciones.

## 3. Gestor de Feedback (`DatasetManager`)
El módulo actúa como un guardián de calidad de datos, implementando las siguientes lógicas críticas:

### Controles de Calidad y Resolución de Conflictos
Si múltiples analistas auditan el mismo evento:
- Si todos están de acuerdo (ej. `TP`), se asigna ese label unánime.
- Si hay divergencia (ej. uno etiqueta `TP` y otro `FP`), el sistema asigna el estado `CONFLICT` y excluye la muestra del dataset final.
- Las decisiones marcadas como `UNCERTAIN` se descartan para el entrenamiento, pero se contabilizan como métrica de ambigüedad del sistema.

### Prevención de Data Leakage (Temporal Split)
Para separar el dataset en `TRAIN`, `VALIDATION` y `TEST`, el sistema evalúa exclusivamente el `timestamp` original de ocurrencia del evento frente a un `cutoff_date`. 
*Razón*: Si un evento ocurrió hace un mes, pero fue etiquetado hoy (tras conocer nueva Inteligencia de Amenazas), usar su fecha de etiquetado introduciría conocimiento del futuro en el pasado, arruinando la evaluación científica.

## 4. Métricas Disponibles
El Gestor proporciona las siguientes métricas HITL:
- Total de decisiones enviadas (`total_decisions_submitted`).
- Total de eventos únicos revisados (`unique_events_reviewed`).
- Distribución final consensuada (`TRUE_POSITIVE`, `FALSE_POSITIVE`, `BENIGN`, `UNCERTAIN`, `CONFLICT`).
- Cobertura mínima umbral (`ready_for_training`), indicando empíricamente si hay suficientes datos balanceados para iniciar un entrenamiento supervisado en Fase 7/8.

## 5. Limitaciones y Criterios de Fase Futura
**Limitación**: Actualmente, el dataset está vacío porque el entorno de pruebas es sintético y no está conectado a una consola de operaciones reales (SOC). 
**Criterio para Habilitar Aprendizaje Supervisado**: No debe iniciarse la implementación de Random Forest / LTSM hasta que las métricas del `DatasetManager` reporten un umbral mínimo estadísticamente significativo (ej. > 1000 muestras de `TRUE_POSITIVE` y > 1000 de `FALSE_POSITIVE`). Entrenar antes de ese hito resultará en un modelo sobreajustado (*overfitting*) a ruido sintético.
