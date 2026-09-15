# CYBERSENTINEL — AUDITORÍA ARQUITECTÓNICA PROFESIONAL

**Estado del proyecto:** Prototipo académico maduro
**Fecha de auditoría:** 2026-09-14
**Objetivo:** Evaluación integral de arquitectura, deuda técnica y viabilidad para escalado hacia entornos empresariales, enfocada estrictamente en la defensa (Blue Team).

---

## A. Fortalezas

1. **Modularidad Estricta:** La separación del pipeline (Ingesta → Detección → Correlación → Explicación → Gobernanza → Auditoría) es ejemplar. Permite probar y sustituir componentes aisladamente.
2. **Normalización Agnóstica:** `SecurityEvent` centraliza la semántica. Reglas, ML y correlador no necesitan conocer si el dato vino de Sysmon o Netflow.
3. **Integración Nativa de pySigma:** La conversión del AST de Sigma a un árbol de evaluación directo sobre `SecurityEvent` es muy superior (en rendimiento y seguridad) a usar backends que generen strings (Splunk/Lucene) o usar la función insegura `eval()`.
4. **Auditoría WORM-like Inmutable:** El registro `AuditLog` con anclaje externo (anchor file) y firmas HMAC asegura la trazabilidad criptográfica de las decisiones, crucial para gobernanza SOC.
5. **Human-in-the-Loop y Fail-Safe:** Las contramedidas (`ResponsePlanner`) operan en dry-run y por defecto bloquean (requires_approval) cualquier acción desconocida, principio básico del Blue Teaming defensivo.
6. **Explicabilidad Segura (XAI):** La sanitización de telemetría inyectada al LLM (`<telemetria_no_fiable>`) y la decisión arquitectónica de que el LLM *solo redacta* (y no decide la severidad o técnicas) previene vulnerabilidades de prompt injection desde los datos del atacante.

## B. Deuda técnica

1. **Manejo de Errores en Parsers:** Las líneas ilegibles en archivos JSONL (ingesta) se registran en el log (`logger.warning`) y se omiten. No existe un mecanismo de "Dead Letter Queue" (DLQ) para recuperar telemetría fallida.
2. **Evaluación de Tiempo Fijo (Time Formats):** La extracción de marcas de tiempo en `CICIDS2017Loader` y `SecurityEvent.try_parse_timestamp` prueba una lista de formatos iterativamente. Esto escala mal computacionalmente en grandes volúmenes.
3. **Hardcoding de Traducciones MITRE:** Las equivalencias de tácticas retiradas (`defense-evasion` -> `stealth`) están escritas en código, lo cual obliga a actualizar el código cada vez que MITRE publica un nuevo framework.
4. **Duplicación Parsers/Loaders:** La lógica de normalización de Sysmon se repite conceptualmente entre `parse_sysmon` (en `normalizer.py`) y `SecurityDatasetsLoader` (en `datasets.py`).

## C. Riesgos arquitectónicos

1. **Evaluación en Memoria (Batch Processing):** `RulesEngine.evaluate` y `Correlator` iteran sobre una lista `events` que asumen cargada completamente en memoria RAM. Para llevarlo a un piloto empresarial, el pipeline deberá migrar a un modelo de *streaming* (ej. procesamiento continuo desde Kafka/RabbitMQ) y mantener el estado de agregación en una base de datos o caché (Redis).
2. **Auto-Contaminación en ML:** El componente `AnomalyDetector` entrena (`fit`) y evalúa (`predict`) sobre el **mismo lote de datos** durante la ejecución del `Pipeline`. Si un atacante inyecta eventos paulatinamente (boiling frog), el modelo asumirá la actividad maliciosa como la "nueva normalidad".
3. **Bloqueo del Hilo Principal:** Los componentes LLM (`anthropic`) son síncronos. En un flujo intenso de incidentes, la generación de narrativas congelaría el pipeline de ingesta/detección.

## D. Cuellos de botella

1. **Ceguera de Telemetría (El mayor problema):** El cuello de botella principal no es de código, sino de datos. Al tener solo UNSW-NB15 (Netflow), 12 de las 15 reglas Sigma (80%) están inutilizadas por depender de telemetría de proceso o autenticación.
2. **Falta de Agregación Sigma (`count()`):** `SigmaBackedRule` no soporta condiciones de agregación de Sigma (timeframe, count() by field). Limita severamente la detección de ataques de fuerza bruta o escaneos.

## E. Componentes duplicados

1. **Reglas Nativas vs Sigma:** Actualmente coexisten 7 reglas en YAML nativo (ej. `cs-large-outbound`, `cs-rdp-lateral`) y 15 reglas en formato Sigma. Ya que se integró pySigma, la capa de YAML nativo es redundante y esas reglas deberían migrar al estándar Sigma.
2. **Caché vs Fallback de MITRE:** Se mantienen tácticas MITRE en duro en `mitre.py` y, simultáneamente, en un archivo JSON cacheado. Si bien garantiza el arranque en frío, puede generar desincronización y comportamientos erráticos.

## F. Funcionalidades incompletas

1. **Soporte de Agregación Temporal:** `Aggregation` (para reglas nativas) está programado, pero está desconectado de `SigmaBackedRule`.
2. **Soporte de Red IPv6:** No hay garantías explícitas para manejo de IPv6 en los parsers de redes ni en los constructores de características numéricas (`FeatureExtractor`).
3. **Contramedidas Simuladas:** `ResponsePlanner` está limitado a retornar "DRY-RUN", sin hooks para integración con EDR, SOAR o Firewalls (ej. webhooks genéricos).

## G. Suposiciones peligrosas

1. **Etiquetado "Security-Datasets":** Asumir que todo el archivo PCAP/JSON de Mordor/OTRF es malicioso introduce un sesgo gigantesco. Gran parte de los eventos (procesos de fondo de Windows) generados son benignos. Medir Precision usando esto clasificará falsos positivos verdaderos como verdaderos positivos, invalidando cualquier investigación científica.
2. **Sincronización de Relojes:** Se asume que todos los eventos llegan con timestamps perfectos. En entornos reales, los logs de diferentes equipos (firewall vs Windows) tienen drifts de segundos o minutos, rompiendo la lógica del modelo de secuencias (Markov) que asume un orden estrictamente causal temporal.
3. **Escala Absoluta IF:** Considerar que `0.5` siempre es el umbral de anomalía universal ignora el drift de concepto y volumen entre entornos de producción distintos.

## H. Problemas de reproducibilidad

1. **Falta de Semilla Global en Pipeline:** Aunque `AnomalyDetector` usa `random_state=42`, el pipeline global no forza la semilla aleatoria, lo que impide asegurar determinismo estricto 100% en todos los cruces.
2. **Métricas Empíricas Disimuladas:** El último reporte de Sigma indicó F1=0.03, provocado porque 4 reglas no dispararon (dataset limitado). Las reglas inevaluables diluyen las métricas globales. Falta estratificación.

## I. Problemas de evaluación científica

1. **Fuga de Datos (Data Leakage):** Como se mencionó en riesgos, el detector de anomalías (Isolation Forest) no separa los datos de entrenamiento (comportamiento normal validado) de los de prueba (análisis actual).
2. **Métricas Limitadas:** El proyecto usa principalmente Precision/Recall. Para Isolation Forest y predictores (Markov), hace falta reportar matrices de confusión, ROC-AUC y métricas específicas por umbral. Un F1 macro y micro evitaría que la clase "Benigna" distorsione métricas de ataque (clase desbalanceada).

## J. Problemas que impedirían llevar el prototipo a un piloto empresarial

1. **Estructura de Datos `SecurityEvent` en Expansión Infinita:** A medida que ingresen logs de Cloud (AWS CloudTrail), Web y DNS, la clase `SecurityEvent` tenderá a llenarse de decenas de campos `Optional`, convirtiéndose en un "God Object". Debe migrar o mapearse a OCSF (Open Cybersecurity Schema Framework).
2. **Procesamiento de Archivos Locales vs Stream (Kafka/Syslog):** El SOC real no sube un CSV para analizarlo. El sistema requiere interfaces de subscripción continua (ej. Redis Pub/Sub, Kafka Consumer).
3. **Gestión de Memoria en Correlador (`Correlator`):** Actualmente el correlador carga todos los eventos de la ventana de incidentes en una lista Python en memoria. Con picos de miles de EPS (Eventos Por Segundo), el Worker colapsaría por OutOfMemory. Necesita estado distribuido (windowing de streams).
4. **Aislamiento Multi-Tenant / Multi-Sensor:** El prototipo asume un único entorno. Un piloto empresarial requiere etiquetar cada evento con el `Tenant_ID` o `Sensor_ID` para que el aprendizaje automático de línea base no cruce dominios diferentes.
