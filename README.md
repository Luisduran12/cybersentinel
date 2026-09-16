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
evaluación) sobre la matriz ATT&CK oficial:

| Modelo | precisión@1 | precisión@3 | F1 macro | Cobertura |
|---|---:|---:|---:|---:|
| Heurística canónica (línea base) | 0.479 | 0.818 | 0.401 | 1.000 |
| **Cadena de Markov (orden 1)** | **0.584** | **0.893** | 0.397 | 1.000 |

La cadena de Markov gana **10.5 puntos de precisión@1** y **7.5 de precisión@3**.

Dos matices que conviene no ocultar:

- La ventaja **se redujo** al pasar del subconjunto ATT&CK escrito a mano (14
  tácticas) a la matriz oficial (15): la heurística subió de 0.422 a 0.479. El
  orden oficial de tácticas es, por sí solo, una línea base mejor de lo que
  parecía.
- En **F1 macro** la heurística queda marginalmente por delante (0.401 frente a
  0.397). El F1 macro pesa todas las tácticas por igual, así que penaliza que la
  Markov nunca proponga las fases raras. La Markov gana donde importa
  operativamente —acertar la fase siguiente— y empata en el promedio por clase.

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

### MITRE ATT&CK oficial y capas de Navigator

La matriz ATT&CK sale del **STIX oficial de MITRE**, no de un subconjunto escrito
a mano. Se resume en una caché de 81 KB que se versiona con el proyecto, de modo
que el sistema funciona sin descargar los 51 MB del bundle ni instalar
`mitreattack-python`:

```bash
# Descargar el STIX oficial (solo si quieres regenerar la cache)
curl -sSL -o data/attack/enterprise-attack.json \
  https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json

pip install 'mitreattack-python>=3.0'
PYTHONPATH=src python -m cybersentinel.cli attack-sync --coverage
```

**Lo que cambió al usar la matriz real** (y que un subconjunto manual ocultaba):

- La táctica `defense-evasion` **ya no existe**: MITRE la dividió en `stealth` y
  `defense-impairment`, y la matriz pasó de 14 a 15 fases. Los nombres retirados
  se siguen resolviendo mediante alias.
- **Una técnica puede pertenecer a varias tácticas**: `T1053` está en ejecución,
  persistencia y escalada de privilegios; `T1078`, en cuatro. El modelo anterior
  asumía una sola.
- Hay técnicas **revocadas** (como `T1562`) que un subconjunto manual mantendría
  vivas indefinidamente.

#### Capas de ATT&CK Navigator

```bash
# Que se detecto en este analisis, coloreado por riesgo
PYTHONPATH=src python -m cybersentinel.cli analyze -i data/sample_logs.jsonl \
    --navigator docs/figuras/capa_incidentes.json
```

Se abren en <https://mitre-attack.github.io/attack-navigator/> → *Open Existing
Layer* → *Upload from local*.

`attack-sync --coverage` responde además a la pregunta incómoda: **qué parte de
ATT&CK cubre el sistema**. Hoy son 7 de 222 técnicas (**3.1%**), concentradas en
seis tácticas de quince. No es un defecto que esconder, sino la medida honesta
del alcance de un prototipo de laboratorio — y el argumento numérico que
justifica integrar las reglas Sigma de la comunidad.

### Configuración

`config/config.yaml` es la fuente de verdad de los parámetros (umbrales de
anomalía, ventana de correlación, modelo del LLM). Precedencia:

```
argumento de CLI  >  config.yaml  >  default embebido
```

### Exportar las narrativas a texto plano

```bash
PYTHONPATH=src python -m cybersentinel.cli analyze -i data/sample_logs.jsonl --text narrativas.txt
```

### Enriquecer las narrativas con Claude (opcional)

```bash
export ANTHROPIC_API_KEY=tu_clave
pip install anthropic
PYTHONPATH=src python -m cybersentinel.cli analyze -i data/sample_logs.jsonl --use-llm
```

Sin API key el sistema funciona igual con narrativas generadas localmente (deterministas y reproducibles).

**Seguridad de este modo.** La evidencia de un incidente contiene texto que
escribió el atacante (líneas de comando, URLs). Pasarlo a un modelo sin más es una
vía de inyección de prompt. Tres defensas:

1. **El modelo no decide nada.** Solo reescribe el texto del resumen. La
   severidad, el riesgo, las técnicas, la predicción y las contramedidas se
   calculan antes y no se le consultan: una narrativa manipulada no puede cambiar
   una decisión de gobernanza.
2. **La telemetría va delimitada y escapada** dentro de una etiqueta que el
   prompt de sistema declara como datos no fiables, y un intento de cerrar esa
   etiqueta desde el propio dato se neutraliza.
3. **Queda auditado**: el log registra si la narrativa salió del modo local o del
   LLM, y con qué modelo.

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
| `tests/test_ingestion.py` | Que ningún registro se pierde ni se falsea en silencio (fuente desconocida, timestamp ilegible, línea corrupta). |
| `tests/test_explainer_safety.py` | Que la telemetría del atacante llega al LLM como datos delimitados y que la narrativa no puede alterar ninguna decisión. |
| `tests/test_datasets.py` | Que los cargadores digieren los formatos reales (CSV sin cabecera, cp1252, columnas con espacios). |
| `tests/test_detection_evaluation.py` | Que el protocolo de medición es correcto: ningún ataque en el entrenamiento, nada medido sobre datos vistos. |
| `tests/test_mitre_attack.py` | Que la matriz oficial se integra sin romper la interfaz, y que el sistema sigue funcionando sin ella. |

## Evaluación con datasets reales

El detector de anomalías se mide contra datasets públicos etiquetados. Hay
cargadores para los cuatro formatos y un comando que entrena, mide y dibuja:

```bash
# UNSW-NB15 (acepta los CSV crudos sin cabecera y la particion con cabecera)
PYTHONPATH=src python -m cybersentinel.cli evaluate-detection \
    --dataset unsw-nb15 -i UNSW-NB15_1.csv --curves docs/figuras/roc.png --json eval.json

# CICIDS2017
PYTHONPATH=src python -m cybersentinel.cli evaluate-detection \
    --dataset cicids2017 -i "TrafficLabelling/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"

# Telemetria Windows por tecnica ATT&CK (Security-Datasets / OTRF)
PYTHONPATH=src python -m cybersentinel.cli evaluate-detection \
    --dataset security-datasets -i psh_cmd.json --technique T1059.001
```

**Sin haber descargado nada todavía**, puedes validar toda la tubería con flujos
sintéticos en formato UNSW-NB15:

```bash
python data/generate_flow_sample.py
PYTHONPATH=src python -m cybersentinel.cli evaluate-detection \
    --dataset unsw-nb15 -i data/synthetic_flows_unsw_format.csv
```

El comando avisa solo de que esos números no valen para la memoria.

**Protocolo**: el detector es no supervisado, así que se entrena **solo con
tráfico benigno** y se mide sobre eventos que no vio, con **todos** los ataques en
el conjunto de evaluación. Se reportan precisión, exhaustividad, F1, tasa de
falsos positivos, matriz de confusión, AUC-ROC, **AUC-PR**, exhaustividad por
familia de ataque y una tabla de puntos de operación.

Las instrucciones de descarga de cada dataset, las trampas de formato de cada uno
y el flujo de laboratorio con **Atomic Red Team** están en
[`docs/DATASETS.md`](docs/DATASETS.md).

## Ingesta y collectors

Cuatro collectors traducen telemetría real —Sysmon (JSON y XML), Linux
(journald/syslog/auditd), firewall genérico y Suricata EVE— a `SecurityEvent`.
Ese es todo el contrato: añadir una fuente **no** obliga a tocar Sigma, el
modelo, Markov ni la correlación, y hay una prueba que lo verifica inspeccionando
los imports. Formatos soportados y **limitaciones conocidas de cada collector**
en [`docs/COLLECTORS.md`](docs/COLLECTORS.md).

## Rendimiento y falsos positivos medidos

```bash
python scripts/benchmark_enterprise.py --seconds 10 --benign 2000
```

Cinco intensidades de carga (100 → 10.000 ev/s) y las siete configuraciones de
ablación sobre el mismo conjunto etiquetado. Todo sale de la ejecución; lo que no
se puede medir dice `NOT EVALUABLE`. Los artefactos quedan en
`results/benchmark_<run_id>/`.

De la ejecución de referencia:

| | |
|---|---|
| Caudal sostenido | **~3.400 ev/s** en un proceso, CPU al 99 % |
| Objetivos cumplidos | 100, 500 y 1.000 ev/s; 5.000 y 10.000 saturan |
| Coste del cómputo | el Isolation Forest consume el **64–98 %** |
| Falsos positivos | **0** sobre 2.130 benignos, incluidos 130 casos difíciles |
| Aporte de ML y correlación | **ninguna decisión cambia**: A, D, E y G son idénticas |

Ese último punto es el hallazgo importante y no es cómodo: la puntuación híbrida
concede como máximo 20 puntos al modelo y 30 a la correlación frente a los 50 de
una regla, de modo que **sin Sigma ninguna configuración puede emitir una alerta**,
por buena que sea la señal. Es la misma causa que deja UNSW-NB15 con ROC-AUC
0,9462 y cero hallazgos. El análisis completo, con la tabla de ablación, el
desglose de latencia y las limitaciones, está en
[`docs/BENCHMARK.md`](docs/BENCHMARK.md).

## Ética y alcance

- Todo el trabajo es sobre **tu propio laboratorio o datasets públicos**. Nunca contra sistemas de terceros sin autorización escrita.
- **Sin capacidades ofensivas** en el entregable. Las contramedidas sensibles **nunca** se ejecutan solas: requieren aprobación humana.
- **Trazabilidad total**: cada decisión del agente queda en el log de auditoría encadenado por hash.

## Estructura

```
cybersentinel/
├── src/cybersentinel/
│   ├── schema.py            # esquema común de eventos (ECS/OCSF)
│   ├── ingestion/           # normalización (sysmon, auth, firewall, netflow, web)
│   │   └── datasets.py         # UNSW-NB15, CICIDS2017, Security-Datasets, Atomic
│   ├── detection/           # reglas (Sigma) + anomalías (Isolation Forest)
│   │   └── evaluation.py       # precision/recall/F1, ROC y precisión-exhaustividad
│   ├── correlation/         # incidentes, MITRE ATT&CK, predicción kill-chain
│   │   ├── attack_data.py      # matriz ATT&CK oficial (STIX) + caché
│   │   ├── navigator.py        # capas para ATT&CK Navigator
│   │   ├── sequence_model.py   # Markov / línea base / interfaz para LSTM
│   │   └── evaluation.py       # precisión@k, matriz de confusión, F1
│   ├── explanation/         # narrativa XAI (+ LLM opcional)
│   ├── governance/          # política ética + auditoría inmutable
│   ├── response/            # recomendación de contramedidas (human-in-the-loop)
│   ├── pipeline.py          # orquestador
│   └── cli.py               # interfaz de línea de comandos
├── config/                  # reglas YAML + política + config
├── data/attack/             # caché de la matriz ATT&CK oficial
├── data/                    # generadores de telemetría, campañas y flujos sintéticos
├── models/                  # modelos entrenados + reporte de métricas
├── tests/                   # pruebas unitarias
└── docs/                    # arquitectura y hoja de ruta
```

## Licencia

Uso académico. Autor: Luis Emir.
