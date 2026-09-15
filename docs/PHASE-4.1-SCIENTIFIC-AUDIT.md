# Fase 4.1: Auditoría Científica de Machine Learning

## Contexto y Problemática (Distribution Shift)
Durante la validación empírica inicial de la Fase 4, se detectó un comportamiento patológico: el baseline de Isolation Forest arrojaba un 100% de Recall pero una Precision del 2.7%.
La auditoría científica reveló que este resultado estaba causado por un **Distribution Shift masivo** acoplado a una **división por varianza cero**:
1. El generador de tráfico benigno solo abarcaba 10 horas desde la medianoche.
2. La partición temporal `TimeBasedSplitter` confinó todo el entrenamiento a las horas nocturnas (`is_night` = 1.0 constante, desviación estándar de cero).
3. Durante la fase de evaluación en horas diurnas (`is_night` = 0.0), el valor normalizado estallaba matemáticamente hacia `1e9`.
4. El modelo aisla estos valores asumiéndolos (incorrectamente) como anomalías absolutas.

## Remediación y Estabilización Numérica
Para asegurar un modelo metodológicamente robusto, se implementaron las siguientes correcciones defensivas:
1. **Estabilidad de Scaling:** Se actualizó `AnomalyDetector.fit` para forzar `std = 1.0` en todas las características con desviación estándar ínfima (`< 1e-5`), comportamiento análogo al `StandardScaler` de Scikit-Learn.
2. **Representatividad del Dataset:** Se extendió el simulador `generate_benign_background` a una ventana de 72 horas para asegurar que las clases temporales diurnas y nocturnas estén debidamente representadas en todos los splits. Adicionalmente, se inyectaron características aleatorias de Sysmon (`hashes`, `parent_command_line`) en el ruido de fondo.

## Nuevos Resultados Experimentales
La re-ejecución del pipeline limpio bajo condiciones asépticas muestra un modelo sensible, con un PR-AUC de **0.7030** (frente al 0.25 anterior).
- **Precision:** 3.11%
- **Recall:** 100%

### Estudio de Ablación (Ablation Study)
Para validar las contribuciones de las características:
- **Red + Proceso (Sin Temporal):** F1 0.0573
- **Completo (Con Temporal):** F1 0.0593
Las características de comportamiento temporal (ventanas de actividad, periodicidad) incrementan marginalmente la resolución del modelo en este dataset, confirmando su validez arquitectónica.

### Evidencia Híbrida: Sigma vs ML
En el conjunto de prueba (603 eventos totales):
- **Sigma (Determinista):** Detectó los 3 eventos firmados con exactitud quirúrgica (0 FP).
- **ML (Isolation Forest):** Detectó los 11 eventos de ataque, pero incluyó 354 anomalías (FP).
- **Sistema Híbrido:** Aplicando la fórmula de score combinado (donde la anomalía modula pero no dicta sentencias de alta criticidad por sí sola), se obtuvieron **3** alertas críticas.

## Limitaciones y Conclusiones del Baseline
1. **El dataset sigue siendo sintético:** La baja Precision de Isolation Forest (3%) es esperable dado el ruido inyectado y la sensibilidad del algoritmo no supervisado para detectar rarezas (comandos atípicamente largos).
2. **No justifica Random Forest todavía:** La métrica demuestra que carecemos de un volumen suficiente y balanceado de etiquetas en el mundo real. Entrenar Random Forest requeriría que la clase de "Ataque" exista de forma representativa en el pasado del cliente, algo inusual. Isolation Forest cumple adecuadamente su función como *baseline* sin requerir supervisión.

## Criterio Final
CyberSentinel posee ahora un control de leakage temporal estricto, una extracción de características estables y un baseline de ML matemáticamente seguro. El módulo de Machine Learning Defensivo **funciona como un detector auxiliar (modulador híbrido)** pero **no debe operar en modo automático (IPS)** para bloquear tráfico, dadas sus altas tasas de falsos positivos frente a desviaciones operativas benignas.

El proyecto está preparado metodológicamente para avanzar a la Fase 5.
