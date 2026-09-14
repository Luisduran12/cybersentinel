# CyberSentinel

**Agente defensivo de ciberseguridad (blue team)** que **analiza**, **predice** y ayuda a **contrarrestar** amenazas, con **explicabilidad (XAI)** y una **capa de gobernanza ética** con *human-in-the-loop*.

> Proyecto de grado — Especialización en Ciberseguridad.
> Ámbito: **estrictamente defensivo y de laboratorio**. Sin exploits, sin malware, sin capacidades ofensivas.

---

## ¿Qué hace? (en una frase)

Ingiere telemetría de seguridad, detecta lo conocido (reglas) y lo desconocido (ML de anomalías), **correlaciona** los hallazgos en incidentes, los **mapea a MITRE ATT&CK**, **predice la fase siguiente** de la cadena de ataque, **explica** cada decisión en lenguaje natural y **recomienda** contramedidas que pasan por una política ética antes de poder ejecutarse — dejando todo registrado en un **log de auditoría inmutable**.

## El diferenciador

La mayoría de las herramientas son *reactivas* (regla → alerta → dashboard). CyberSentinel combina tres cosas que casi no se ven juntas:

1. **Predicción de kill-chain** — no solo "detecté algo", sino "esto es la fase N de un ataque y lo más probable es que siga Z".
2. **Explicabilidad** — narrativa legible: qué vio, por qué es sospechoso, confianza y evidencia citada.
3. **Gobernanza ética integrada** — cada contramedida se clasifica en *permitida / requiere aprobación / prohibida*, con auditoría verificable.

## Arquitectura (modular y desacoplada)

```
 Ingesta ─► Detección ─► Correlación + Predicción ─► Explicación ─► Gobernanza ─► (Auditoría)
 (normaliza  (reglas Sigma   (incidentes, MITRE      (narrativa    (permitida/
  a esquema   + ML anomalías)  ATT&CK, kill-chain)     XAI + LLM     aprobación/
  común ECS)                                           opcional)     prohibida)
```

Cada capa es independiente: añadir una fuente de logs, una regla o una acción no obliga a tocar el resto. Ver `docs/ARCHITECTURE.md`.

## Instalación

Requiere **Python 3.10–3.12** (el ecosistema de seguridad que se integra en las
fases siguientes —pySigma, mitreattack-python— aún no cubre 3.13+).

```bash
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Uso rápido

```bash
# 1) Generar telemetría sintética de laboratorio (incluye una cadena de ataque)
python data/generate_sample.py

# 2) Analizar
PYTHONPATH=src python -m cybersentinel.cli analyze --input data/sample_logs.jsonl

# 3) Exportar el reporte a JSON
PYTHONPATH=src python -m cybersentinel.cli analyze -i data/sample_logs.jsonl --json report.json

# 4) Verificar la integridad del log de auditoría
PYTHONPATH=src python -m cybersentinel.cli verify-audit --audit audit_log.jsonl
```

### Firmar el log de auditoría (recomendado)

Sin clave, la cadena de hashes detecta una edición ingenua, pero **no** una
reescritura completa: quien edite el archivo puede recalcular todos los hashes.
Con clave, la firma es un HMAC-SHA256 que exige un secreto que no está en el
archivo:

```bash
export CYBERSENTINEL_AUDIT_KEY='una-clave-larga-y-secreta'
```

Junto al log se escribe un **ancla** (`audit_log.jsonl.anchor`) con el número de
entradas y el último hash: es lo que permite detectar que se borraron entradas
del final. Límite honesto: el ancla vive en el mismo disco. La defensa completa
exige publicarla en un medio independiente (otro host, almacenamiento WORM o un
servicio de sellado de tiempo).

### Predicción de kill-chain (entrenable y medida)

La fase siguiente la propone un **modelo de secuencia intercambiable**. Por
defecto es la heurística del orden canónico de ATT&CK; con una **cadena de Markov
de primer orden** entrenada, la predicción pasa a ser probabilística y, sobre
todo, **medible**:

```bash
# Entrena sobre campanas sinteticas etiquetadas, compara contra la linea base
# y reporta precision@k, matriz de confusion y F1 por tactica.
PYTHONPATH=src python -m cybersentinel.cli train-prediction \
    --save-model models/markov_tactics.json --json models/prediction_report.json

# Usar el modelo en un analisis (o fijarlo en config.yaml)
PYTHONPATH=src python -m cybersentinel.cli analyze -i data/sample_logs.jsonl \
    --model models/markov_tactics.json
```

Resultado con la configuración por defecto (400 campañas, semilla 7, 30% para
evaluación, 450 prefijos):

| Modelo | precisión@1 | precisión@3 | F1 macro | Cobertura |
|---|---:|---:|---:|---:|
| Heurística canónica (línea base) | 0.422 | 0.796 | 0.353 | 0.998 |
| **Cadena de Markov (orden 1)** | **0.576** | **0.893** | **0.372** | 0.998 |

La cadena de Markov gana **15.3 puntos de precisión@1** y **9.8 de precisión@3**
sobre la heurística.

**Lo que estos números significan y lo que no.** Las campañas de entrenamiento
las genera `data/generate_campaigns.py`: el modelo aprende *esa* distribución, no
el comportamiento de atacantes reales. Miden que el modelo es capaz de aprender
la estructura de una campaña a partir de ejemplos, no su eficacia frente a un
adversario real — eso llega con datos observados en la Fase 4. La **comparación**
sí es justa: ambos modelos se evalúan sobre las mismas campañas retenidas y
ninguno conoce el generador.

Dos tácticas tienen **F1 = 0** (comando y control, impacto): el modelo nunca las
propone como primera opción porque en el corpus rara vez son la continuación más
frecuente de su fase previa. Es una limitación real del modelo de orden 1 y
conviene discutirla, no esconderla.

Sustituir la Markov por un LSTM no obliga a tocar el correlador: basta con
heredar de `SequenceModel` e implementar `fit`, `predict_next` y `to_dict`.

### Configuración

`config/config.yaml` es la fuente de verdad de los parámetros (umbrales de
anomalía, ventana de correlación, modelo del LLM). Precedencia:

```
argumento de CLI  >  config.yaml  >  default embebido
```

### Enriquecer las narrativas con Claude (opcional)

```bash
export ANTHROPIC_API_KEY=tu_clave
pip install anthropic
PYTHONPATH=src python -m cybersentinel.cli analyze -i data/sample_logs.jsonl --use-llm
```

Sin API key el sistema funciona igual con narrativas generadas localmente (deterministas y reproducibles).

## Pruebas

```bash
PYTHONPATH=src python -m pytest -q
```

La suite cubre tres cosas distintas:

| Archivo | Qué comprueba |
|---|---|
| `tests/test_pipeline.py` | Que el flujo completo funciona de punta a punta. |
| `tests/test_detection_quality.py` | Que se detecta lo que se dice detectar y, sobre todo, que el tráfico benigno **no** genera incidentes graves. |
| `tests/test_audit_integrity.py` | Que la manipulación del log (edición, truncado, reescritura completa) se detecta. |
| `tests/test_sequence_model.py` | Que la cadena de Markov aprende, que las métricas miden lo que dicen, y que la predicción nunca retrocede en la cadena. |

## Datasets reales para tu tesis

El generador sintético sirve para demostrar el flujo. Para evaluación rigurosa, adapta un parser en `ingestion/normalizer.py` a datasets públicos:

- **CICIDS2017**, **UNSW-NB15** (flows de red etiquetados).
- Logs de laboratorio con **Sysmon** + **Atomic Red Team** (ejecutas técnicas ATT&CK controladas en tu propia VM).

## Ética y alcance

- Todo el trabajo es sobre **tu propio laboratorio o datasets públicos**. Nunca contra sistemas de terceros sin autorización escrita.
- **Sin capacidades ofensivas** en el entregable. Las contramedidas sensibles **nunca** se ejecutan solas: requieren aprobación humana.
- **Trazabilidad total**: cada decisión del agente queda en el log de auditoría encadenado por hash.

## Estructura

```
cybersentinel/
├── src/cybersentinel/
│   ├── schema.py            # esquema común de eventos (ECS/OCSF)
│   ├── ingestion/           # normalización de telemetría
│   ├── detection/           # reglas (Sigma) + anomalías (Isolation Forest)
│   ├── correlation/         # incidentes, MITRE ATT&CK, predicción kill-chain
│   │   ├── sequence_model.py   # Markov / línea base / interfaz para LSTM
│   │   └── evaluation.py       # precisión@k, matriz de confusión, F1
│   ├── explanation/         # narrativa XAI (+ LLM opcional)
│   ├── governance/          # política ética + auditoría inmutable
│   ├── response/            # recomendación de contramedidas (human-in-the-loop)
│   ├── pipeline.py          # orquestador
│   └── cli.py               # interfaz de línea de comandos
├── config/                  # reglas YAML + política + config
├── data/                    # generadores de telemetría y de campañas sintéticas
├── models/                  # modelos entrenados + reporte de métricas
├── tests/                   # pruebas unitarias
└── docs/                    # arquitectura y hoja de ruta
```

## Licencia

Uso académico. Autor: Luis Emir.
