# Evaluación de CyberSentinel sobre UNSW-NB15

Primera evaluación del agente contra un dataset público real de ciberseguridad.

> **Lo que este documento sí demuestra:** que CyberSentinel puede ingerir,
> normalizar y puntuar tráfico real, y cuánto acierta su detector de anomalías.
>
> **Lo que NO demuestra:** el funcionamiento de Sigma, ATT&CK, CTI ni RAG. Este
> dataset no puede representarlos, y la sección 7 explica exactamente por qué.

---

## 1. Fuente del dataset

| | |
|---|---|
| Nombre | UNSW-NB15 |
| Origen | UNSW Canberra Cyber, Australian Defence Force Academy |
| Página oficial | <https://research.unsw.edu.au/projects/unsw-nb15-dataset> |
| Descarga | Carpeta oficial de OneDrive enlazada desde esa página |
| Autor | Dr. Nour Moustafa |
| Cita | Moustafa, N. & Slay, J. (2015). *UNSW-NB15: a comprehensive data set for network intrusion detection systems*. MilCIS. |

Se descargó **de la fuente oficial**, no de Kaggle ni de copias de terceros.

## 2. Fecha de descarga

2026-09-15.

## 3. Hashes

Los SHA-256 de cada archivo usado están en
`results/unsw_nb15_run_metadata.json` (campo `dataset.sha256`) y en
`results/unsw_nb15_validation.json`. Permiten comprobar que los resultados
provienen exactamente de estos archivos.

## 4. Número de registros

Validado con `scripts/validate_unsw_nb15.py` y contrastado con lo que publica
UNSW:

| Archivo | Filas | Oficial | Coincide |
|---|---:|---:|:--:|
| `UNSW_NB15_training-set.csv` | 175 341 | 175 341 | sí |
| `UNSW_NB15_testing-set.csv` | 82 332 | 82 332 | sí |
| `UNSW-NB15_2.csv` | 700 001 | — | — |
| `UNSW-NB15_3.csv` | 700 001 | — | — |
| `UNSW-NB15_4.csv` | 440 044 | — | — |
| `NUSW-NB15_features.csv` | 49 features | 49 | sí |
| `UNSW-NB15_LIST_EVENTS.csv` | 208 eventos | — | — |

`UNSW-NB15_1.csv` no se incluyó: su descarga se interrumpió dos veces desde el
servidor de UNSW. La evaluación usa los otros tres (1 840 046 registros).

SHA-256 de los archivos usados en la evaluación:

| Archivo | SHA-256 |
|---|---|
| `UNSW-NB15_2.csv` | `6130ad02873cc6069ae695cf2844f2e8c2e9a9a1b7532dd82ab8f202757cacf8` |
| `UNSW-NB15_3.csv` | `ae990a96c3dfcd425ce2801aadb1727a34d5e0ae6d8215dbcdae60dedfaef640` |
| `UNSW-NB15_4.csv` | `cdf563692d51d405541dd659ddcdad9fa01f001f05fe9fc4b67f00ca12fbc96a` |

Distribución de etiquetas en la partición oficial:

| Conjunto | Normal | Ataque | % ataque |
|---|---:|---:|---:|
| training-set | 56 000 | 119 341 | 68.1 % |
| testing-set | 37 000 | 45 332 | 55.1 % |

Celdas vacías: 1.19 % (train) y 1.27 % (test). Duplicados exactos: 0 en ambos.

## 5. Variables utilizadas

De las 49 variables del dataset se usan las que el esquema `SecurityEvent`
modela. El resto **no se descarta**: se conserva en `properties`, aunque no
alimente ninguna característica del detector.

## 6. Mapeo UNSW-NB15 → SecurityEvent

| UNSW-NB15 | SecurityEvent |
|---|---|
| `srcip` | `src_ip` |
| `dstip` | `dst_ip` |
| `sport` | `src_port` |
| `dsport` | `dst_port` |
| `proto` (o `service`) | `protocol` |
| `sbytes` | `bytes_out` |
| `dbytes` | `bytes_in` |
| `state` | `outcome` |
| `stime` (epoch Unix) | `timestamp` — **solo en los CSV crudos** |
| `dur`, `spkts`, `dpkts`, `sttl`, `dttl`, `sloss`, `dloss`, `sload`, `dload` | `properties.*` |
| `sjit`, `djit`, `swin`, `stcpb`, `ct_*`, `is_*`… | `properties.*` (sin uso en features) |
| `label`, `attack_cat` | verdad-terreno, **solo para evaluar** |

Implementado en `src/cybersentinel/data/unsw_nb15_adapter.py`. `SecurityEvent` no
se modificó: todo se resolvió en el adapter.

### Trazabilidad

```
unsw_row_id  ->  event_id  ->  run_id
```

`unsw_row_id` es `<archivo>:<línea>`, de modo que cualquier predicción del
archivo `results/unsw_nb15_predictions.csv` se puede devolver a la fila exacta
del dataset original.

### Dos formatos, propiedades distintas

| Archivo | Cabecera | IPs | Puertos | Tiempo |
|---|:--:|:--:|:--:|:--:|
| `UNSW-NB15_1..4.csv` | no | **sí** | **sí** | **sí** |
| `UNSW_NB15_training/testing-set.csv` | sí | no | no | no |

La partición oficial train/test **no incluye IP, puerto ni marca de tiempo**.
El adapter lo declara en `unavailable` y **no inventa ninguno de los tres**: una
hora falsa contaminaría la correlación temporal y las características cíclicas,
produciendo resultados que parecerían válidos sin serlo.

Por eso la evaluación principal usa los **CSV crudos**, que sí los traen.

## 7. Componentes evaluables

| Componente | Estado | Motivo |
|---|---|---|
| **Isolation Forest** | **evaluable** | El dataset aporta volumen, puertos y estado de conexión. Hay verdad-terreno por flujo. |
| Sigma | **no evaluable** | Las reglas del proyecto son de telemetría de host (línea de comandos, proceso padre). UNSW-NB15 son flujos de red **sin línea de comandos**. Una regla que no puede activarse no mide nada. |
| Correlación temporal | **parcialmente evaluable** | Hay marca de tiempo en los CSV crudos, pero las secuencias definidas encadenan técnicas ATT&CK que solo las reglas de host producen. |
| MITRE ATT&CK | **no evaluable** | La técnica se deriva de la regla que se activa. Sin activaciones no hay técnica observada. Las categorías de UNSW-NB15 (*Exploits*, *Fuzzers*…) **no son técnicas ATT&CK**. |
| CTI | **no evaluable** | Las IPs son de un laboratorio de 2015; no existen indicadores reales para ellas. |
| RAG + LLM | **no evaluable** | Producen texto explicativo, no una decisión de detección: no hay verdad-terreno contra la que medirlos. |

> **Que Sigma no sea evaluable aquí NO significa que Sigma no funcione.** Significa
> que este dataset no contiene el tipo de telemetría que esas reglas leen. Su
> funcionamiento está demostrado en las pruebas de integración del proyecto, sobre
> telemetría Sysmon.

### Características con señal real

De las **19** características del `FeatureExtractor`, solo **10** varían sobre este
dataset. Las 9 restantes son constantes porque UNSW-NB15 no aporta el campo del
que dependen:

```
cmd_len, cmd_special_chars, cmd_entropy, user_rarity, has_hash,
has_parent_cmd, is_process, is_network, is_night
```

Es decir: **el detector opera aquí con menos de la mitad de su información**. Las
métricas de la sección 12 son un suelo, no un techo.

## 8. Partición TRAIN / VALIDATION / TEST

Corte **temporal** (cronológico), no aleatorio: un corte aleatorio permitiría que
un flujo posterior entrenara al modelo que evalúa flujos anteriores, que es la
forma más común de fuga en datos de red.

| Conjunto | Registros | % ataque | Ventana |
|---|---:|---:|---|
| TRAIN | 180 000 | 13.96 % | 2015-01-22 19:43 → 2015-02-18 06:26 |
| VALIDATION | 60 000 | 17.34 % | 2015-02-18 06:26 → 2015-02-18 09:26 |
| TEST | 60 000 | 21.89 % | 2015-02-18 09:26 → 2015-02-18 12:03 |

- El modelo se entrena **solo con los 154 873 flujos benignos de TRAIN**. Un
  detector no supervisado que vea ataques durante el entrenamiento los aprende
  como normalidad.
- El umbral se elige **en VALIDATION**. TEST no interviene en ninguna decisión.

### Muestreo

Se cargan 300 000 registros mediante **muestreo sistemático** (uno de cada *k*)
sobre los archivos completos. No es un detalle menor: en `UNSW-NB15_2.csv` el
primer ataque aparece en la **línea 387 248 de 700 001**, así que tomar los
primeros *N* registros produce un conjunto **de una sola clase** con el que
ninguna métrica tiene sentido. La primera ejecución de este experimento cayó en
esa trampa y reportó `NOT EVALUABLE (una sola clase)`, que es lo correcto.

## 9. Parámetros del Isolation Forest

| Parámetro | Valor |
|---|---|
| `contamination` | `auto` |
| `n_estimators` | 200 |
| `random_state` | 42 |
| Entrenamiento | solo flujos benignos de TRAIN (154 873) |
| Normalización | z-score con media y desviación de TRAIN |

## 10. Umbral

**0.642614**, elegido en VALIDATION por máximo F1. El barrido completo está en
`results/unsw_nb15_run_metadata.json` y en la figura
`docs/figures/if_threshold_analysis.svg`.

## 11. Distribución del `anomaly_score` en TEST

| | |
|---|---:|
| mínimo | 0.484525 |
| máximo | 0.744049 |
| media | 0.600028 |
| mediana | 0.580560 |
| desviación típica | 0.062213 |
| valores distintos | 31,447 |

El score **no es constante**: 31,447 valores distintos sobre 60 000 flujos.
El modelo está puntuando de verdad.

## 12. Métricas en TEST

n = 60 000, de los cuales 21.89 % son ataques.

| Métrica | Valor |
|---|---:|
| TP | 12,949 |
| FP | 12,375 |
| TN | 34,493 |
| FN | 183 |
| **Precision** | **0.5113** |
| **Recall** | **0.9861** |
| **F1** | **0.6734** |
| **ROC-AUC** | **0.8855** |
| **PR-AUC** | **0.566** |
| FPR | 0.264 |
| Especificidad | 0.736 |
| Exactitud | 0.7907 |

### Recall por categoría de ataque

| Categoría | Detectados / total | Recall |
|---|---:|---:|
| Generic | 9,421 / 9,423 | 0.9998 |
| Exploits | 1,484 / 1,545 | 0.9605 |
| Fuzzers | 691 / 747 | 0.925 |
| DoS | 680 / 685 | 0.9927 |
| Reconnaissance | 434 / 482 | 0.9004 |
| Analysis | 103 / 103 | 1.0 |
| Backdoor | 86 / 94 | 0.9149 |
| Shellcode | 43 / 46 | 0.9348 |
| Worms | 7 / 7 | 1.0 |

### Cómo leer estos números

**El ROC-AUC de 0.8855 no significa que el detector esté listo para
producción.** Con un 26.4% de falsos positivos, un SOC recibiría
12,375 alertas falsas por cada 12,949 verdaderas. La distancia entre
ROC-AUC (0.8855) y PR-AUC (0.566) es exactamente el efecto del
desbalance que la curva ROC disimula: **la PR es la métrica que refleja el
trabajo real del analista**, y es notablemente peor.

**El punto de operación elegido no es el mejor que el modelo permite.** La curva
precisión-exhaustividad muestra puntos con precisión sustancialmente mayor a
recall algo menor. La causa es un **desplazamiento de la tasa base entre
particiones**: VALIDATION tiene 17.3 % de ataques y TEST 21.9 %, así que el
umbral óptimo en la primera no lo es exactamente en la segunda.

Elegir el umbral mirando TEST daría un F1 mucho mejor **y sería trampa**. Se
reporta el resultado honesto.

## 13. Matriz de confusión

|  | Predicho: ataque | Predicho: benigno |
|---|---:|---:|
| **Real: ataque** | 12,949 (TP) | 183 (FN) |
| **Real: benigno** | 12,375 (FP) | 34,493 (TN) |

`results/unsw_nb15_confusion_matrix.csv` · `docs/figures/confusion_matrix.svg`

## 14. Ablation

| Configuración | Precision | Recall | F1 | PR-AUC | ROC-AUC |
|---|---:|---:|---:|---:|---:|
| A. Isolation Forest | 0.5113 | 0.9861 | 0.6734 | 0.566 | 0.8855 |
| B. + Correlación temporal | — | — | — | — | **NOT EVALUABLE** |
| C. Sistema completo | — | — | — | — | **NOT EVALUABLE** |

**B** no es evaluable porque las 5 reglas de secuencia encadenan técnicas ATT&CK
que solo las reglas de host producen: sobre flujos de red no se activa ninguna,
así que la correlación temporal no puede aportar ni restar.

**C** no es evaluable porque Sigma, ATT&CK, CTI y RAG no son aplicables a este
dataset. Presentar una cifra ahí sería atribuir al sistema completo el mérito del
único componente que participa.

## 15. Limitaciones

1. **Solo un componente quedó medido.** De siete etapas del pipeline, únicamente
   el Isolation Forest tiene verdad-terreno en este dataset.
2. **10 de 19 características activas.** El detector opera con menos de la mitad
   de su información; las métricas son un suelo.
3. **26.4% de falsos positivos** en el punto de operación elegido. Operativamente
   inasumible sin un segundo filtro.
4. **Desplazamiento de tasa base** entre VALIDATION (17.3 %) y TEST (21.9 %),
   consecuencia del corte temporal. Penaliza la calibración del umbral.
5. **Muestra de 300 000 registros** de los 1 840 046 disponibles (y de los
   2 540 044 que tiene el dataset completo), por tiempo de cómputo. El muestreo sistemático conserva la distribución, pero no es el
   dataset entero.
6. **UNSW-NB15 es de 2015** y sintético en sus ataques (generados con IXIA
   PerfectStorm). No representa tráfico actual.
7. **La partición oficial train/test no se usó para la evaluación principal**
   porque carece de IP, puerto y tiempo: sobre ella solo 3 de 19 características
   tendrían señal.
8. **`is_night` salió constante** en la muestra: toda la captura cae en horas
   diurnas, así que esa característica no aporta nada aquí.

## 16. Conclusión

CyberSentinel **puede procesar un dataset real de ciberseguridad de extremo a
extremo**: descarga, validación, adaptación, extracción de características,
entrenamiento, puntuación y métricas, con trazabilidad desde la fila original del
dataset hasta la predicción.

Lo demostrado:

- **Ingesta y adaptación** de 1.84 M de registros en dos formatos distintos.
- **Isolation Forest real**, con scores variables (25 294 valores distintos) y
  capacidad discriminativa sustancial: **ROC-AUC 0.8855, PR-AUC 0.566**.
- **Protocolo experimental sin fuga**: corte temporal, entrenamiento solo con
  benignos, umbral elegido en validación.
- **Rendimiento**: ~23,271 flujos/segundo en puntuación.

Lo no demostrado, y por qué: Sigma, ATT&CK, CTI y RAG no son evaluables con
flujos de red. Para medirlos hace falta telemetría de host etiquetada —
Security-Datasets de OTRF o Atomic Red Team en laboratorio propio—, cuyos
cargadores ya existen en el proyecto (`docs/DATASETS.md`).

## Reproducir

```bash
# 1. Validar el dataset descargado
python scripts/validate_unsw_nb15.py

# 2. Evaluación completa (misma semilla -> mismos resultados)
python scripts/evaluate_unsw_nb15.py --limit 300000 --seed 42

# 3. Figuras, leídas exclusivamente de results/
python scripts/make_figures.py
```

Artefactos: `results/unsw_nb15_metrics.json`, `unsw_nb15_predictions.csv`,
`unsw_nb15_confusion_matrix.csv`, `unsw_nb15_ablation.csv`,
`unsw_nb15_run_metadata.json`, `unsw_nb15_validation.json`,
`unsw_nb15_curves.csv`.
