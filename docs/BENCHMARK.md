# Rendimiento y falsos positivos medidos

Todo lo que aparece aquí procede de `scripts/benchmark_enterprise.py`. Ningún
número está escrito a mano. Lo que no se pudo medir dice `NOT EVALUABLE` en vez
de rellenarse.

```bash
python scripts/benchmark_enterprise.py --seconds 10 --benign 2000
```

Ejecución de referencia: `run_id` `dca7cbcd-5ecb-4b0f-839c-08449f2c0a32`,
artefactos en `results/benchmark_<run_id>/`. Máquina: macOS x86-64, Python
3.11, proceso único. RAG y LLM desactivados: producen texto, no decisiones de
detección, y su coste dominaría la latencia sin mover un solo TP o FP.

---

## 1. Carga

Cinco intensidades, 10 s cada una. Calentamiento excluido y declarado: cargar
reglas y ajustar la línea base es un coste de arranque, no de régimen.

| Objetivo | Logrado | Servicio p50 | Servicio p99 | Respuesta p50 | Respuesta p99 | Atraso máx. | CPU media | RAM máx. | Errores |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 100 ev/s    | **100**   | 5,10 ms | 5,28 ms | 100 ms | 146 ms | 0,1 s | 52,1 % | 194,9 MB | 0 |
| 500 ev/s    | **497**   | 1,15 ms | 1,19 ms | 110 ms | 161 ms | 0,2 s | 59,1 % | 199,1 MB | 0 |
| 1.000 ev/s  | **993**   | 0,65 ms | 1,30 ms | 119 ms | 192 ms | 0,2 s | 67,6 % | 203,4 MB | 0 |
| 5.000 ev/s  | 3.381 ⚠   | 0,25 ms | 0,41 ms | 2.471 ms | 4.814 ms | 4,9 s | 99,1 % | 219,6 MB | 0 |
| 10.000 ev/s | 3.404 ⚠   | 0,25 ms | 0,43 ms | 9.688 ms | 19.257 ms | 19,4 s | 99,8 % | 238,5 MB | 0 |

⚠ saturado: el caudal logrado no alcanza el 95 % del objetivo.

**Hay dos latencias y confundirlas maquilla el resultado.** El *servicio* es lo
que el pipeline tarda en procesar un evento; la *respuesta* incluye la espera
desde que el evento debería haber entrado al ritmo objetivo. Bajo saturación la
primera se mantiene plana —incluso mejora, porque los lotes son mayores— mientras
la segunda crece sin techo. Reportar solo el servicio haría parecer que el
sistema aguanta 10.000 ev/s con 0,25 ms de latencia; lo que realmente ocurre es
que acumula 19,4 s de atraso.

**Techo medido: ~3.400 ev/s** en un proceso, con la CPU al 99 %. El límite es
cómputo, no memoria: la RAM sube de 195 a 238 MB entre el escenario más flojo y
el más exigente.

Nada se pierde porque el banco es síncrono y sin cola acotada. La API de ingesta
sí tiene cola acotada y devuelve 429 con `Retry-After`; ahí la saturación se
manifiesta como rechazo explícito en lugar de atraso.

## 2. Coste por componente

Milisegundos por evento y reparto del tiempo de servicio. La cobertura indica
qué fracción del tiempo explican las fases medidas: un desglose que no suma el
total no es un desglose, es una selección.

| Escenario | Servicio medio | Cobertura | ML | Bucle por evento | Sigma | Temporal |
|---|---:|---:|---:|---:|---:|---:|
| 100 ev/s    | 5,1125 ms | 99,9 % | **98,3 %** | 1,3 % | 0,4 % | 0,0 % |
| 500 ev/s    | 1,1582 ms | 99,8 % | **92,2 %** | 6,3 % | 1,5 % | 0,0 % |
| 1.000 ev/s  | 0,6612 ms | 99,7 % | **86,2 %** | 11,2 % | 2,6 % | 0,1 % |
| 5.000 ev/s  | 0,2779 ms | 99,2 % | **63,9 %** | 29,9 % | 6,1 % | 0,1 % |
| 10.000 ev/s | 0,2776 ms | 99,2 % | **63,6 %** | 30,4 % | 5,9 % | 0,2 % |

El Isolation Forest consume entre el 64 % y el 98 % del cómputo. Ténganlo
presente al leer la sección 3.

> **Corrección de la instrumentación.** La primera versión de este desglose
> atribuía 0,007 ms de los 0,25 ms reales —un 3 %—. El motivo: Sigma con
> agregación, la correlación y el ajuste del modelo se ejecutan **por lote**,
> antes del bucle por evento, y la traza por evento solo cronometraba la
> consulta al resultado ya calculado. Se añadió `PipelineReport.batch_timings_ms`
> para medir donde ocurre el trabajo. La cobertura pasó del 3 % al 99 %.

## 3. Ablación

Siete configuraciones sobre **los mismos** 2.192 eventos con verdad-terreno
conocida por diseño (62 maliciosos, 2.130 benignos). Se cuenta como detección
que el evento supere el umbral de alerta, que es la decisión que el sistema toma
de verdad.

| Config | Componentes | TP | FP | TN | FN | Precisión | Recall | F1 | FPR | Incidentes | Score máx. |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| A | Sigma            | 47 | 0 | 2130 | 15 | 1,0000 | 0,7581 | 0,8624 | 0,0000 | 7/7 | 50,00 |
| B | ML               | 0 | 0 | 2130 | 62 | NOT EVALUABLE | 0,0000 | NOT EVALUABLE | 0,0000 | 0/7 | 8,96 * |
| C | Temporal         | 0 | 0 | 2130 | 62 | NOT EVALUABLE | 0,0000 | NOT EVALUABLE | 0,0000 | 0/7 | 0,00 * |
| D | Sigma + ML       | 47 | 0 | 2130 | 15 | 1,0000 | 0,7581 | 0,8624 | 0,0000 | 7/7 | 56,54 |
| E | Sigma + temporal | 47 | 0 | 2130 | 15 | 1,0000 | 0,7581 | 0,8624 | 0,0000 | 7/7 | 80,00 |
| F | ML + temporal    | 0 | 0 | 2130 | 62 | NOT EVALUABLE | 0,0000 | NOT EVALUABLE | 0,0000 | 0/7 | 8,96 * |
| G | Completo         | 47 | 0 | 2130 | 15 | 1,0000 | 0,7581 | 0,8624 | 0,0000 | 7/7 | 86,46 |

`*` **ciego por construcción**: ninguna puntuación de esa configuración alcanza
el umbral de 50,0. Su recall de 0 mide la capa de puntuación, no la calidad de
la señal.

### Lo que dice esta tabla

**Sigma decide; ML y temporal solo añaden confianza.** A, D, E y G tienen
TP/FP/TN/FN **idénticos**. Sumar el modelo, la correlación o ambos no cambia ni
una sola decisión: sube la puntuación (50 → 56,54 → 80 → 86,46) sin cruzar
ningún umbral que no estuviera ya cruzado. Combinado con la sección 2, el
componente que consume el 64–98 % del cómputo aporta 0 detecciones nuevas y 0
falsos positivos evitados.

**B, C y F no son resultados de calidad, son resultados de diseño.** La
puntuación híbrida concede como máximo 20 puntos al ML y 30 a la correlación,
frente a los 50 de una regla; el máximo realmente observado fue 8,96 y 0,00. Con
un umbral de 50, ninguna configuración sin Sigma puede emitir una alerta, pase
lo que pase en la telemetría. Esto confirma sobre datos sintéticos lo que la
evaluación de UNSW-NB15 ya mostró sobre datos reales: **ROC-AUC 0,9462 y cero
hallazgos**. El detector ve; la capa de alerta no le deja hablar.

La correlación temporal marca 0,00 sin Sigma por una razón distinta: correla
*aciertos de reglas*, así que sin reglas no tiene entrada. No es un umbral bajo,
es una dependencia estructural.

### Recall por evento frente a recall por incidente

| Escenario de ataque | Eventos detectados | Incidente detectado |
|---|---:|:-:|
| PowerShell ofuscado (T1059)  | 12/12 | sí |
| Persistencia (T1053)         | 10/10 | sí |
| Descubrimiento (T1046)       | 8/8   | sí |
| Exfiltración (T1048)         | 6/6   | sí |
| Movimiento lateral (T1021)   | 6/6   | sí |
| Baliza C2 (T1071)            | 4/12  | sí |
| Fuerza bruta (T1110)         | 1/8   | sí |

Los 15 FN se concentran en las dos reglas **agregadas**. No son fallos: una regla
de fuerza bruta detecta *la secuencia* cuando se completa el recuento, no cada
intento que la compone. Contarlos por evento penaliza a esas reglas por hacer
exactamente lo que deben. Por eso se reportan las dos unidades: 0,7581 de recall
por evento y 7/7 por incidente, que es lo que ve un analista.

## 4. Falsos positivos

**0 falsos positivos sobre 2.130 eventos benignos** (FPR 0,0000), incluidos 130
casos difíciles deliberados: administración legítima con `robocopy`,
transferencias de 50–99 MB a un NAS interno y fallos de autenticación aislados.

### Causa raíz: el conjunto, no el detector

Este cero **no debe leerse como una tasa de falsos positivos en producción**. Es
un resultado sobre telemetría sintética cuya diversidad la fija el propio
generador, y la diversidad es justamente lo que produce falsos positivos en un
entorno real. El dato honesto es: sobre este conjunto, ninguna regla se dispara
fuera de su objetivo.

Una versión anterior del generador **sí** producía 6 FP, todos de `RULE-0001`
sobre el escenario `benigno_dificil_fallo_aislado`. La causa resultó ser el
etiquetado, no la regla: el escenario decía "aislado" pero generaba 30 fallos
consecutivos del mismo usuario desde la misma IP, que es precisamente lo que una
regla de fuerza bruta debe detectar. Se corrigió variando usuario, host e IP en
cada uno. Queda anotado aquí porque es el modo de fallo más fácil de cometer al
medir falsos positivos: **un FP puede ser un error de la etiqueta y no del
detector**, y ajustar el umbral para hacerlo desaparecer habría escondido el
problema en lugar de resolverlo.

El banco atribuye cada FP a la señal que cruzó el umbral —regla, correlación,
umbral del modelo o sin atribución clara— y guarda hasta 15 ejemplos con su
puntuación y su comando en `false_positive_analysis.json`.

## 5. Artefactos

`results/benchmark_<run_id>/`:

| Fichero | Contenido |
|---|---|
| `metrics.json` | Por escenario: recibidos, aceptados, procesados, rechazados, perdidos, caudal, servicio y respuesta (media/p50/p95/p99/máx), CPU, RAM, errores por tipo |
| `latency_breakdown.json` | Traza por evento, fases por lote y atribución con su cobertura |
| `ablation.json` | Las 7 configuraciones: matriz de confusión, métricas, distribución de puntuaciones, desglose por escenario y recall por incidente |
| `false_positive_analysis.json` | Recuento por escenario y por causa, tasa y ejemplos |
| `run_metadata.json` | `run_id`, semilla, composición del conjunto, umbral, versiones, tiempo total |

## 6. Limitaciones

- **Un solo proceso, una sola máquina.** El techo de ~3.400 ev/s es de un
  proceso Python. No se ha medido escalado horizontal.
- **Telemetría sintética.** La verdad-terreno es conocida porque el generador la
  fija; ese es el único modo de medir falsos positivos sin circularidad, pero
  limita la validez externa. La evaluación sobre datos reales está en
  `docs/UNSW-NB15-EVALUATION.md`.
- **RAG y LLM fuera de la medición.** No participan en la decisión de detección.
  Su coste de latencia **no** está en estas cifras.
- **La respuesta se mide por lote.** Todos los eventos de un lote se dan por
  completados al terminar este, así que la latencia de respuesta se redondea al
  alza dentro del lote.
- **62 eventos maliciosos** en 7 escenarios. Suficiente para comparar
  configuraciones entre sí, insuficiente para un intervalo de confianza sobre el
  recall.
