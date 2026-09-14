# Datasets de evaluación

Guía para medir CyberSentinel con datos reales. El generador sintético demuestra
el flujo; **los números de la memoria salen de aquí**.

> **Ética y alcance.** Todo lo de este documento es sobre datasets públicos o
> sobre tu propio laboratorio. Nunca contra sistemas de terceros.

---

## Resumen

| Dataset | Tipo | Tamaño | Sirve para | Etiquetas |
|---|---|---|---|---|
| **UNSW-NB15** | Flujos de red | ~100 MB (partición) / ~2 GB (crudo) | Métricas del detector de anomalías | Por flujo, con categoría de ataque |
| **CICIDS2017** | Flujos de red | ~1 GB | Métricas del detector, más familias de ataque | Por flujo |
| **Security-Datasets** (OTRF) | Telemetría Windows (JSON) | MB por técnica | Cobertura de las reglas ATT&CK | Por archivo (una técnica) |
| **Atomic Red Team** | Tu laboratorio | El que generes | Cobertura sobre telemetría propia | Por ventana temporal |

Los dos primeros miden **el detector de anomalías** (¿distingue ataque de tráfico
normal?). Los dos últimos miden **el motor de reglas** (¿se dispara la regla
correcta ante la técnica X?). Son preguntas distintas y conviene reportarlas por
separado.

---

## 1. UNSW-NB15

Flujos de red etiquetados generados por el Cyber Range de UNSW Canberra.

**Descarga**: [research.unsw.edu.au → UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset)

Hay dos formatos y el cargador acepta ambos:

| Archivo | Cabecera | IPs | Notas |
|---|---|---|---|
| `UNSW-NB15_1.csv` … `_4.csv` | **No** | Sí | 49 columnas; los nombres están en `NUSW-NB15_features.csv` |
| `UNSW_NB15_training-set.csv` | Sí | No | 45 columnas, ya particionado |

Empieza por los CSV crudos: conservan IPs y puertos, que es lo que alimenta las
características de rareza del detector.

```bash
PYTHONPATH=src python -m cybersentinel.cli evaluate-detection \
    --dataset unsw-nb15 \
    --input UNSW-NB15_1.csv UNSW-NB15_2.csv \
    --curves docs/figuras/roc_unsw.png \
    --json models/eval_unsw.json
```

Categorías de ataque: `Fuzzers`, `Analysis`, `Backdoors`, `DoS`, `Exploits`,
`Generic`, `Reconnaissance`, `Shellcode`, `Worms`.

---

## 2. CICIDS2017

Cinco días de tráfico con ataques inyectados, de la Universidad de New Brunswick.

**Descarga**: [unb.ca/cic/datasets/ids-2017.html](https://www.unb.ca/cic/datasets/ids-2017.html)

| Carpeta | Contenido |
|---|---|
| `MachineLearningCVE/` | 79 columnas, **sin IPs**: solo características de flujo |
| `GeneratedLabelledFlows/TrafficLabelling/` | 85 columnas, con IPs y marca de tiempo |

Usa `GeneratedLabelledFlows/`: sin IPs ni horas, la mitad de las características
del detector quedan vacías.

```bash
PYTHONPATH=src python -m cybersentinel.cli evaluate-detection \
    --dataset cicids2017 \
    --input "TrafficLabelling/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv" \
    --curves docs/figuras/roc_cicids.png \
    --json models/eval_cicids.json
```

**Trampas del formato, ya resueltas en el cargador** — merece la pena mencionarlas
en la memoria porque son parte del trabajo real de ingeniería de datos:

- Los nombres de columna llevan un espacio delante (`' Destination Port'`), y los
  valores también (`' 192.168.10.5'`). Una IP con espacio no agrupa con la misma
  IP de otra fuente.
- El archivo no es UTF-8: la etiqueta `Web Attack – Brute Force` usa un guion
  cp1252 (byte `0x96`) que rompe la lectura estricta a mitad del archivo.
- Las columnas de tasa contienen `Infinity` y `NaN`.
- La marca de tiempo cambia de formato entre archivos (`5/7/2017 8:55` frente a
  `7/7/2017 3:30:00 PM`).

Los archivos son grandes: usa `--limit` para una primera pasada.

---

## 3. Security-Datasets (OTRF) — telemetría Windows por técnica

Conjuntos de telemetría Windows en JSON, cada uno correspondiente a la ejecución
de una técnica ATT&CK concreta.

**Repositorios**: [OTRF/Security-Datasets](https://github.com/OTRF/Security-Datasets)
y [sbousseaden/EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES).

```bash
git clone https://github.com/OTRF/Security-Datasets.git

PYTHONPATH=src python -m cybersentinel.cli evaluate-detection \
    --dataset security-datasets \
    --input Security-Datasets/datasets/atomic/windows/execution/host/psh_cmd.json \
    --technique T1059.001
```

**Límite metodológico que hay que declarar.** Aquí la etiqueta es del *archivo*,
no del evento: dentro de la captura de una técnica hay mucha telemetría benigna
de fondo. Medir "precisión" contra esa etiqueta cuenta como falsos negativos
eventos que nunca fueron maliciosos. Estos datasets sirven para responder
**"¿se dispara la regla correcta ante esta técnica?"** (cobertura), no para una
tasa de acierto.

### Muestras EVTX

Los archivos de `EVTX-ATTACK-SAMPLES` son `.evtx` binarios. Conviértelos a JSON
Lines antes de ingerirlos:

```bash
# Opcion A: evtx_dump (Rust, rapido)
cargo install evtx
evtx_dump -o jsonl muestra.evtx > muestra.json

# Opcion B: python-evtx
pip install python-evtx
```

---

## 4. Atomic Red Team — tu propio laboratorio

La fuente más cercana a un caso real: tú ejecutas técnicas controladas en **tu
máquina virtual** y recoges la telemetría que producen.

> Ejecuta esto **solo en tu laboratorio aislado**, con instantánea previa y sin
> conectividad a redes de terceros. Las técnicas de Atomic Red Team modifican el
> sistema.

1. **Prepara la VM**: Windows con Sysmon instalado (configuración de
   [SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config) o de Olaf
   Hartong), y una instantánea para revertir.

2. **Ejecuta las técnicas registrando qué y cuándo**:

   ```powershell
   Invoke-AtomicTest T1059.001 -ExecutionLogPath C:\lab\atomic_log.csv
   Invoke-AtomicTest T1053.005 -ExecutionLogPath C:\lab\atomic_log.csv
   ```

3. **Exporta la telemetría de Sysmon** al esquema JSON Lines que lee el
   normalizador (`source: "sysmon"`).

4. **Etiqueta y mide**:

   ```python
   from cybersentinel.ingestion import Normalizer
   from cybersentinel.ingestion.datasets import AtomicRedTeamGroundTruth

   eventos = Normalizer().from_jsonl("telemetria_lab.jsonl")
   verdad = AtomicRedTeamGroundTruth.from_csv("atomic_log.csv", window_seconds=120)
   etiquetados = verdad.label_events(eventos)
   ```

   Todo evento del mismo host dentro de la ventana posterior a una ejecución se
   atribuye a esa técnica.

**Límite de la ventana temporal**: 120 s es una aproximación. Un artefacto de
persistencia puede generar eventos mucho después, y actividad benigna simultánea
queda etiquetada como ataque. Declara la ventana que uses al reportar.

---

## Cómo reportar los resultados

Cuatro cosas que un tribunal va a mirar:

1. **Precisión y exhaustividad por separado, nunca solo la exactitud.** Con un 1%
   de ataques, un detector que no marque nada acierta el 99%.

2. **AUC-PR junto al AUC-ROC.** Con clases desbalanceadas la ROC da una impresión
   optimista: la tasa de falsos positivos se diluye en el enorme número de
   negativos. La curva precisión-exhaustividad refleja el trabajo real del
   analista. En la evaluación sintética de referencia, el AUC-ROC es 0.958 y el
   AUC-PR 0.826 sobre los mismos datos: esa distancia es justo lo que hay que
   explicar.

3. **El desglose por familia de ataque.** Un F1 global razonable puede esconder
   que una familia entera nunca se detecta. `evaluate-detection` lo imprime.

4. **El punto de operación, y por qué ese.** La tabla de barrido de umbrales
   muestra el intercambio; elegir un punto es una decisión con criterio operativo
   (cuántos falsos positivos tolera el equipo), no un valor por defecto.

### Qué esperar, y por qué

El detector está construido sobre características de **telemetría de host**
(entropía del comando, rareza del usuario, hora). Sobre flujos de red puros, la
mitad de esas características quedan vacías y solo quedan las de volumen y
puerto. Es esperable que:

- los ataques **volumétricos o de puerto raro** (exfiltración, canal de mando) se
  detecten bien;
- los que **imitan tráfico normal** (explotación de una aplicación web) se
  detecten mal.

Esa asimetría no es un fallo que ocultar: es el argumento a favor de la
**detección híbrida** que defiende el proyecto. Lo que el modelo no supervisado
no ve, lo ven las reglas; lo que las reglas no conocen, lo ve el modelo.
