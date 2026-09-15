# CyberSentinel Fase 4: Machine Learning Defensivo Científico

## El Problema: ¿Qué aprende CyberSentinel?
En la Fase 4, el objetivo principal ha sido introducir Machine Learning para detectar **comportamiento anómalo** que escapa a las reglas de detección deterministas (Sigma). CyberSentinel aprende la **línea base de comportamiento normal** de la red y los procesos. No aprende a detectar ataques per se, sino que aprende qué es habitual en el entorno para levantar banderas cuando ocurre un evento extremadamente atípico.

## 1. Datos y Separación Estricta
Se implementó `TimeBasedSplitter` para garantizar una evaluación científica con cero data leakage:
- **Entrenamiento (Train):** Datos 100% pasados, idealmente benignos.
- **Validación (Val):** Para ajustar el umbral de anomalía (`anomaly_threshold`) dinámicamente usando el percentil 99.
- **Prueba (Test):** Datos futuros. Aquí es donde se miden métricas de precisión.

*Cualquier intento de entrenar e inferir sobre el mismo lote de datos fue purgado de la arquitectura (`Pipeline.run_events`).*

## 2. Ingeniería de Características (Feature Extraction)
El `FeatureExtractor` fue rediseñado (en `ml/features.py`) para soportar contexto temporal sin violar la causalidad. Extrae:
- **Red:** Ratio de asimetría in/out, puertos raros, entropía.
- **Proceso:** Longitud de comandos, caracteres especiales, frecuencia de hashes.
- **Temporal:** Volumen de eventos en los últimos 5 minutos (`events_in_window`), tiempo transcurrido desde la última acción, y variables trigonométricas cíclicas (hora).

*Los léxicos de frecuencias (`user_rarity`, `ip_rarity`) solo se ajustan en TRAIN.*

## 3. Modelo Base: Isolation Forest
Se optó por Isolation Forest ya que, en ciberseguridad defensiva real, el tráfico maligno representa menos del 0.1% de los datos. No tenemos suficientes etiquetas para entrenar algoritmos supervisados robustos.

### ¿Por qué no Random Forest?
Un algoritmo supervisado requiere que la clase positiva (ataques) esté debidamente representada en el conjunto de entrenamiento. Dado que en un despliegue real no dispondremos de cientos de ataques perfectamente etiquetados para entrenar, Random Forest no está justificado para esta etapa. Solo sería viable en implementaciones extremadamente maduras que recopilan alertas confirmadas (Feedback) durante meses.

## 4. Detección Híbrida (Sigma + ML)
Hemos introducido `DetectionEvidence` que combina:
- Macheos de reglas deterministas (Alta Confianza).
- Score de Anomalías del ML (Confianza de Desviación).
- Contexto temporal (Secuencias previas).

Esto significa que una anomalía aislada nunca disparará un incidente CRÍTICO a menos que Sigma o el modelo de cadenas de Markov dicten que forma parte de una cadena de ataque estructurada.

## 5. Explicabilidad y Gobernanza
Cada evaluación del modelo no solo emite un veredicto binario sino un `AnomalyResult` con un score real en [0,1] y las `top_features` que contribuyeron al aislamiento (ej. "el comando tiene una entropía extremadamente alta para la línea base").
Se preparó `AnalystFeedback` para un loop de aprendizaje futuro (True Positive / False Positive).

## 6. Reproducibilidad
Para repetir la evaluación científica de forma aséptica:
```bash
python scripts/train_eval_iforest.py
```
Este script demostrará empíricamente la efectividad del ML frente a un dataset donde los atacantes actúan de manera desviada a la norma.
