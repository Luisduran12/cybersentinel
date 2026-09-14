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
  patrones *conocidos* con alta precisión.
- **Anomalías (Isolation Forest)**. Aprenden una línea base de comportamiento y
  marcan lo que se desvía. Capturan lo *desconocido*. Cada anomalía es explicable
  a nivel de característica (qué features empujaron el score).

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
- **Auditoría inmutable**: cadena de entradas encadenadas por hash SHA-256. Si se
  altera una entrada pasada, `verify()` lo detecta.

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
- **Integridad**: manipula una línea del `audit_log.jsonl` y corre `verify-audit`
  para mostrar que el sistema detecta la alteración.
- **Ética**: enseña la política y muestra que una acción como `hack_back` queda
  *prohibida* automáticamente.
