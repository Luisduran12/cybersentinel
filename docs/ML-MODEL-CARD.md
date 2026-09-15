# Model Card: CyberSentinel Isolation Forest

## Identificación del Modelo
* **Nombre:** Isolation Forest Anomaly Detector
* **Versión:** 1.0.0 (Fase 4)
* **Algoritmo Base:** `sklearn.ensemble.IsolationForest`
* **Licencia:** MIT (As part of CyberSentinel academic project)

## Intended Use (Uso Previsto)
* **Propósito:** Detección de comportamiento atípico en flujos de telemetría de red y eventos de Sysmon, mediante el aprendizaje de una línea base de comportamiento benigno/rutinario.
* **Intended Use Cases:** Investigación de ciberseguridad defensiva, triaje de alertas de seguridad, descubrimiento de actividades Living-off-the-Land (LotL) que carecen de firmas Sigma conocidas.
* **Out-of-Scope:** Uso ofensivo (generación de payloads). No debe usarse como *sistema automatizado de bloqueo* (IPS), ya que las anomalías no son obligatoriamente maliciosas.

## Datos de Entrenamiento y Evaluación
* **Training Data:** El modelo se ajusta utilizando la telemetría recolectada en una ventana de tiempo inicial (ej. primeros 60% de los datos cronológicos de un despliegue). Asume que la inmensa mayoría de este tráfico es benigno (`contamination="auto"`).
* **Evaluation Data:** Datos separados de manera estrictamente cronológica (validación y test) del mismo entorno, inyectados con un dataset de evaluación de Sysmon (`data/synthetic_sysmon_eval.json`).
* **Prevención de Leakage:** Está garantizado mediante `TimeBasedSplitter` que la evaluación no interactúa con los contadores de frecuencia generados durante el entrenamiento.

## Características (Features)
El vector de características está diseñado de forma interpretable:
1. **Atributos de Proceso:** Entropía de Shannon en comandos, conteo de caracteres especiales, frecuencias relativas de IPs/Usuarios.
2. **Atributos de Red:** Ratio in/out, exclusividad de puertos.
3. **Contexto Temporal:** Conteo de eventos agrupados por host en una ventana móvil de 5 minutos (`events_in_window`), tiempo inactivo previo y variables armónicas de hora del día.

*El modelo no codifica hashes crudos ni nombres de host como embeddings numéricos arbitrarios.*

## Hiperparámetros Clave
* `contamination`: "auto" (Permite que el límite de decisión sea orgánico y no fuerce un porcentaje de falsos positivos fijos en lotes benignos).
* `n_estimators`: 200 (Compromiso entre estabilidad y tiempo de inferencia).
* `random_state`: 42 (Para reproducibilidad de línea base).

## Threshold de Alerta (Punto de Operación)
El umbral no es estático ni derivado en inferencia. Se determina extrayendo el **percentil 99 de los scores observados durante el entrenamiento** (o validación) de la línea base, limitado inferiormente en `0.5`. Todo lo que exceda este límite es clasificado como anomalía.

## Métricas Estimadas (Evaluación Sintética de Laboratorio)
* **ROC-AUC:** ~0.94
* **Recall (Ataques):** 1.0000 (Detecta todos los escenarios del `synthetic_sysmon_eval`)
* **Precision:** Muy baja en crudo (~0.02) debido a la altísima disparidad de clases de los conjuntos no supervisados, justificando por qué el Isolation Forest funciona como **modulador** (Score Híbrido) y no como oráculo.

## Limitaciones y Known Biases
1. **Bias de la Línea Base:** Si el sistema de entrenamiento inicial ya contenía compromisos (Backdoors latentes), el Isolation Forest lo aprenderá como comportamiento "normal".
2. **Incapacidad de discernir intención:** Un administrador realizando tareas legítimas poco frecuentes (ej. respaldos masivos anómalos o instalación de software nuevo de madrugada) disparará el detector de igual forma que un intruso.
3. **Incapacidad Supervisada:** Al ser no-supervisado, el modelo no comprende explícitamente "qué es un ataque" (ej. no sabe que Mimikatz es inherentemente malo si nunca vio las reglas deterministas). Depende intrínsecamente del motor híbrido con Sigma.
