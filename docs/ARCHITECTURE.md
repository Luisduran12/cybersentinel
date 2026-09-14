# Arquitectura de CyberSentinel

Documento de apoyo para la defensa del proyecto de grado. Explica cada capa, las
decisiones de diseño y — muy importante para el jurado — **los alcances y límites
honestos** del sistema.

## 1. Visión general

CyberSentinel es un **agente defensivo** que transforma telemetría cruda en
incidentes explicados, priorizados y con predicción de evolución, bajo control
humano y con trazabilidad total.

El diseño sigue tres principios:

- **Desacople**: cada capa expone objetos de datos claros (`SecurityEvent`,
  `Finding`, `Incident`, `PolicyVerdict`). Se puede reemplazar una capa sin tocar
  las demás.
- **Fail-safe ético**: ante la duda, el sistema es conservador (una acción
  desconocida requiere aprobación humana; un fallo del LLM cae a la narrativa
  local).
- **Verificabilidad**: toda decisión queda auditada de forma que la manipulación
  posterior es detectable.

## 2. Las capas

### 2.1 Ingesta (`ingestion/`)
Normaliza fuentes heterogéneas a un **esquema común** inspirado en ECS/OCSF.
Cada fuente tiene un parser; añadir una fuente = añadir un parser. Soporta lectura
completa y *streaming* para archivos grandes.

### 2.2 Detección (`detection/`)
Enfoque **híbrido**:
- **Reglas (estilo Sigma)** en YAML, con técnica ATT&CK asociada. Capturan
  patrones *conocidos* con alta precisión. Soportan **agregación temporal**
  (`count` coincidencias en `timeframe_minutes` agrupadas por entidad), que es lo
  que distingue "un login fallido" de "fuerza bruta" y lo que evita emitir ocho
  alertas donde hay un solo ataque.
- **Anomalías (Isolation Forest)**. Aprenden una línea base de comportamiento y
  marcan lo que se desvía. Capturan lo *desconocido*. Cada anomalía es explicable
  a nivel de característica (qué features empujaron el score).

Tres decisiones de esta capa condicionan la validez de los números y conviene
poder defenderlas:

1. **La puntuación de anomalía es absoluta**, no relativa al lote. Se usa
   directamente `-score_samples` de Isolation Forest, acotada en (0, 1) y con 0.5
   como frontera de decisión del algoritmo. Una normalización min-max dentro del
   lote haría que el evento más raro de *cualquier* lote recibiera 1.0 —aunque el
   lote fuera inofensivo— y que los scores de dos ejecuciones no fueran
   comparables.
2. **`contamination="auto"`**. Fijar una contaminación (p. ej. 0.08) obliga al
   modelo a marcar esa proporción de eventos como anómalos *por construcción*,
   haya ataques o no.
3. **Una anomalía sola no puede ser CRITICAL.** Sin corroboración de ninguna
   regla es una *pista*, no un veredicto; su severidad tiene techo en MEDIUM. El
   riesgo sí sube por la vía correcta cuando la correlación la agrupa con
   hallazgos de reglas y progresión en la cadena de ataque.

Las características son interpretables por diseño (rareza de la entidad frente a
la línea base, entropía del comando, hora cíclica). Codificar el usuario o la IP
como un entero —un hash— mete un orden numérico sin significado en el modelo y
produce explicaciones vacías del tipo "la característica user_hash se desvió".

### 2.3 Correlación y predicción (`correlation/`)
- Agrupa hallazgos por **entidad** (host/usuario/IP) y **ventana temporal** en
  `Incident`.
- Mapea a **MITRE ATT&CK** (tácticas y técnicas).
- **Predice la fase siguiente** combinando el orden canónico de la cadena de
  ataque con la coherencia de la progresión observada. La confianza sube cuando
  las fases observadas son monótonas y numerosas.
- Calcula un **riesgo agregado** (severidad + profundidad en la cadena + volumen).

### 2.4 Explicación (`explanation/`)
Genera una narrativa: resumen, razonamiento, evidencia citada, predicción y
confianza. Modo **local determinista** por defecto; modo **LLM (Claude)** opcional
para un resumen ejecutivo más fluido, con *fallback* automático.

### 2.5 Gobernanza (`governance/`)
- **Política**: clasifica cada contramedida en *permitida / requiere aprobación /
  prohibida*. Las acciones destructivas u ofensivas están **prohibidas por
  diseño**.
- **Auditoría verificable**: cadena de entradas encadenadas por hash, con dos
  defensas sobre la cadena desnuda:
  - **Firma HMAC-SHA256** con clave fuera del archivo (`CYBERSENTINEL_AUDIT_KEY`).
    Sin clave, quien edite el log puede recalcular la cadena entera y la
    verificación pasa; con clave, falsificarla exige el secreto.
  - **Ancla externa** (`<log>.anchor`) con el número de entradas y el último
    hash. La cadena por sí sola no detecta el **truncado**: si se borran las
    últimas entradas, lo que queda sigue siendo una cadena válida.

  Límite declarado: el ancla vive en el mismo disco. Un atacante con escritura
  sobre ambos archivos *y* la clave puede reescribirlo todo. La defensa completa
  exige publicar el ancla en un medio independiente (otro host, almacenamiento
  WORM o un servicio de sellado de tiempo). Por eso el término correcto es
  *auditoría verificable con detección de manipulación*, no *inmutable*.

### 2.6 Respuesta (`response/`)
Propone contramedidas priorizadas según tácticas y riesgo. En este entregable
**nada se ejecuta de verdad**: las acciones permitidas se simulan (*dry-run*) y las
sensibles esperan aprobación humana.

## 3. Flujo de datos

```
JSONL ─► Normalizer ─► [SecurityEvent] ─► RulesEngine ─┐
                                     └─► AnomalyDetector ┴─► [Finding]
      ─► Correlator ─► [Incident + KillChainPrediction]
      ─► Explainer ─► IncidentNarrative
      ─► ResponsePlanner + GovernancePolicy ─► [Recommendation]
      ─► AuditLog (encadenado por hash)
```

## 4. Alcances y límites (honestidad para el jurado)

**Lo que SÍ hace hoy, de forma funcional y verificable:**
- Ingesta multi-fuente, detección híbrida, correlación, mapeo ATT&CK, predicción
  de fase siguiente, narrativa explicable, política ética y auditoría íntegra.
- Corre de punta a punta sobre datos sintéticos y es adaptable a datasets reales.

**Lo que NO es (y no debe venderse como tal):**
- La confianza de una regla **no es una probabilidad calibrada**: se deriva de la
  severidad que le puso su autor, es decir, de cuánto "pesa" la regla, no de
  cuántas veces acierta. Calibrarla exige medir contra un dataset etiquetado.
- El detector de anomalías entrena y puntúa sobre el mismo lote. Es aceptable
  para una demo no supervisada, pero **no para medir**: la evaluación
  cuantitativa exige entrenar sobre una línea base y puntuar sobre un conjunto
  separado.
- No es un IDS/EDR de producción ni sustituye a un SOC. Es un **prototipo de
  investigación** de laboratorio.
- La predicción es **probabilística y heurística**, no una garantía. Un atacante
  real puede saltarse fases o encadenarlas en otro orden.
- El subconjunto ATT&CK embebido es **parcial**; la matriz completa se integra
  como trabajo futuro.
- La ejecución de respuestas es **simulada**; conectar ejecutores reales exige
  validaciones adicionales y mantener siempre el *human-in-the-loop*.

Reconocer estos límites **fortalece** la tesis: demuestra criterio y entendimiento
del problema real.

## 5. Hoja de ruta (trabajo futuro)

1. Matriz ATT&CK completa desde el STIX oficial de MITRE.
2. Parser Sigma completo (para reutilizar miles de reglas de la comunidad).
3. Modelo de secuencia entrenable (p. ej. cadenas de Markov / LSTM) para la
   predicción, evaluado con métricas (precisión@k de la fase siguiente).
4. Evaluación cuantitativa sobre CICIDS2017 / UNSW-NB15 con matriz de confusión y
   curvas ROC.
5. Panel web (FastAPI + frontend) para el flujo de aprobación humana.
6. Conectores de respuesta reales (firewall/EDR) con doble confirmación.

## 6. Cómo defenderlo

- **Demo en vivo**: corre `analyze` sobre `sample_logs.jsonl`; muestra cómo la
  cadena completa se detecta, se explica y se predice "Impacto" como fase
  siguiente.
- **Integridad**: tres demos, en orden creciente de sofisticación del atacante.
  1. Edita una línea del `audit_log.jsonl` -> `verify-audit` detecta la alteración.
  2. Borra las últimas líneas -> el ancla detecta el truncado.
  3. Recalcula toda la cadena con SHA-256 -> con `CYBERSENTINEL_AUDIT_KEY`
     definida, la firma HMAC no cuadra y también se detecta.
- **Ética**: enseña la política y muestra que una acción como `hack_back` queda
  *prohibida* automáticamente.
