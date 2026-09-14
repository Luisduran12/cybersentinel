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

```bash
python -m venv .venv && source .venv/bin/activate   # opcional
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
│   ├── explanation/         # narrativa XAI (+ LLM opcional)
│   ├── governance/          # política ética + auditoría inmutable
│   ├── response/            # recomendación de contramedidas (human-in-the-loop)
│   ├── pipeline.py          # orquestador
│   └── cli.py               # interfaz de línea de comandos
├── config/                  # reglas YAML + política + config
├── data/                    # generador de telemetría sintética
├── tests/                   # pruebas unitarias
└── docs/                    # arquitectura y hoja de ruta
```

## Licencia

Uso académico. Autor: Luis Emir.
