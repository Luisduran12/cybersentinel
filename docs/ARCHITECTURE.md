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
Cada fuente tiene un parser (sysmon, auth, firewall, netflow, web); añadir una
fuente = añadir un parser. Soporta lectura completa y *streaming* para archivos
grandes, con la lectura completa apoyada en la de streaming para que no puedan
divergir.

Principio de esta capa: **nada se descarta ni se falsea en silencio**. Un
registro de una fuente sin parser, con un timestamp ilegible o en una línea
corrupta se procesa igual —perder telemetría es peor— pero queda **etiquetado**
(`fuente_desconocida`, `timestamp_invalido`) y registrado en el log. Sustituir un
timestamp ilegible por la hora actual sin dejar rastro desplaza el evento dentro
de la ventana de correlación y puede meterlo en un incidente al que no pertenece.

El parser de `netflow` acepta además las convenciones de nombres de UNSW-NB15
(`srcip`, `sbytes`) y Zeek (`id.orig_h`).

`ingestion/datasets.py` añade los cargadores de datasets **etiquetados**, que es
lo que permite medir en lugar de solo demostrar: UNSW-NB15 (en sus dos formatos,
incluidos los CSV crudos sin cabecera), CICIDS2017, Security-Datasets de OTRF y
la verdad-terreno temporal de Atomic Red Team. Cada uno devuelve `LabeledEvent`:
el evento normalizado más su etiqueta.

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
- Mapea a **MITRE ATT&CK** desde el STIX oficial de MITRE (`attack_data.py`),
  resumido en una caché de 81 KB que se versiona con el proyecto. Hay tres
  niveles de respaldo —caché, STIX, subconjunto embebido— para que el sistema
  arranque siempre, incluso en un clon recién descargado sin dependencias
  opcionales.

  Sustituir el subconjunto escrito a mano por la matriz real destapó tres cosas
  que conviene llevar preparadas a la defensa:
  1. La táctica `defense-evasion` **ya no existe**: MITRE la dividió en `stealth`
     y `defense-impairment`, y la matriz pasó de 14 a 15 fases. Un subconjunto
     manual habría seguido prediciendo sobre una cadena obsoleta.
  2. **Una técnica puede pertenecer a varias tácticas.** `T1053` está en tres y
     `T1078` en cuatro. Donde hace falta un valor escalar se toma la fase **más
     temprana**, para que un único hallazgo no haga parecer que el ataque está
     más avanzado de lo que demuestra la evidencia.
  3. Hay técnicas **revocadas** que un subconjunto manual mantiene vivas.
- Exporta **capas de ATT&CK Navigator** (`navigator.py`): una por incidentes
  detectados, coloreada por riesgo, y otra de **cobertura**, que muestra qué
  parte de la matriz es capaz de detectar el sistema.
- **Predice la fase siguiente** con un modelo de secuencia intercambiable
  (`sequence_model.py`). Hay dos implementaciones y una interfaz:
  - `CanonicalBaseline`: el orden canónico de la cadena. Es la línea base contra
    la que se mide todo lo demás.
  - `MarkovChainModel`: cadena de Markov de primer orden sobre tácticas, con
    suavizado de Laplace, entrenada con campañas etiquetadas. Estima además la
    probabilidad de que el ataque **se detenga** en la fase actual.
  - `SequenceModel`: la interfaz. Un LSTM futuro hereda de ella y el correlador
    no cambia.

  Tres decisiones condicionan la predicción:
  1. La fase actual del incidente es la **más profunda** alcanzada, no la última
     vista en el tiempo. Un evento tardío de una fase temprana no devuelve al
     atacante a esa fase.
  2. Solo se proponen fases **posteriores** a la actual y no observadas todavía.
     Sin esa restricción, cuando la fase actual es terminal casi toda la masa de
     probabilidad se va al estado final, el resto queda repartido por el
     suavizado y el modelo acaba proponiendo una fase ya superada. Cuesta 0.4
     puntos de precisión@1 y evita predicciones absurdas: es un intercambio
     deliberado.
  3. Las probabilidades **no se renormalizan** sobre las candidatas que quedan.
     Son la probabilidad condicional de la matriz de transición, de modo que
     "Impacto 4%" junto a "91% de que el ataque se detenga aquí" es coherente;
     renormalizar daría un "Impacto 100%" engañoso.
- Calcula un **riesgo agregado** (severidad + profundidad en la cadena + volumen).

### 2.4 Explicación (`explanation/`)
Genera una narrativa: resumen, razonamiento, evidencia citada, predicción y
confianza. Modo **local determinista** por defecto; modo **LLM (Claude)** opcional
para un resumen ejecutivo más fluido, con *fallback* automático.

**Superficie de ataque del modo LLM.** La evidencia contiene texto escrito por el
atacante, así que enviarla a un modelo es una vía de inyección de prompt. El
diseño la acota en tres niveles:

1. *El modelo no decide.* Solo reescribe `summary`. Severidad, riesgo, técnicas,
   predicción y contramedidas ya están calculados y no pasan por él. Una
   narrativa manipulada no puede alterar una decisión de gobernanza — esta es la
   defensa que importa, porque las otras dos son mitigaciones parciales.
2. *Delimitación y escapado.* La telemetría viaja dentro de una etiqueta que el
   prompt de sistema declara como datos no fiables, con el cierre de esa etiqueta
   neutralizado dentro del propio dato, caracteres de control eliminados y
   longitud acotada.
3. *Trazabilidad.* La narrativa declara su origen (`local` / `llm`) y el modelo,
   y ambos quedan en el log de auditoría.

Conviene decirlo sin adornos en la defensa: **no existe una defensa completa
contra la inyección de prompt**. Por eso la arquitectura no le confía ninguna
decisión al modelo.

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
- Corre de punta a punta sobre datos sintéticos y **ingiere datasets públicos
  etiquetados** (UNSW-NB15, CICIDS2017, Security-Datasets) para medirse con
  precisión, exhaustividad, F1, ROC y precisión-exhaustividad.

**Lo que NO es (y no debe venderse como tal):**
- La confianza de una regla **no es una probabilidad calibrada**: se deriva de la
  severidad que le puso su autor, es decir, de cuánto "pesa" la regla, no de
  cuántas veces acierta. Calibrarla exige medir contra un dataset etiquetado.
- El detector de anomalías entrena y puntúa sobre el mismo lote. Es aceptable
  para una demo no supervisada, pero **no para medir**: la evaluación
  cuantitativa exige entrenar sobre una línea base y puntuar sobre un conjunto
  separado.
- El modo LLM está **mitigado, no blindado**, frente a la inyección de prompt. La
  garantía real es arquitectónica: el modelo no toma ninguna decisión.
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

## 4.bis Evaluación de la predicción

Protocolo: de cada campaña retenida se derivan ejemplos por **prefijo** (dada
`[A, B, C, D]` se pregunta la fase siguiente tras `[A]`, tras `[A, B]` y tras
`[A, B, C]`), de modo que se mide la predicción en cada punto de la cadena y no
solo al final. Partición 70/30 con semilla fija.

| Modelo | precisión@1 | precisión@3 | F1 macro | F1 ponderado | Cobertura |
|---|---:|---:|---:|---:|---:|
| Heurística canónica (línea base) | 0.479 | 0.818 | 0.401 | 0.457 | 1.000 |
| Cadena de Markov (orden 1) | 0.584 | 0.893 | 0.397 | 0.498 | 1.000 |

Medido sobre la matriz ATT&CK oficial de 15 tácticas. Con el subconjunto de 14
escrito a mano, la heurística daba 0.422 y la ventaja de la Markov era de 15.3
puntos en lugar de 10.5: **el orden oficial de tácticas es por sí solo una línea
base mejor de lo que parecía**. En F1 macro la heurística queda marginalmente por
delante (0.401 frente a 0.397), porque esa métrica pesa todas las tácticas por
igual y penaliza que la Markov nunca proponga las fases raras.

Se reporta la **cobertura** junto a la precisión porque un modelo que casi nunca
responde puede tener buena precisión y ser inútil. La precisión se divide entre
*todos* los prefijos, no solo los respondidos: no responder cuenta como fallo.

Límites de esta evaluación, en orden de importancia:

1. El corpus es **sintético y propio** (`data/generate_campaigns.py`). Mide
   capacidad de aprender estructura, no eficacia frente a adversarios reales.
2. `command-and-control` e `impact` tienen **F1 = 0**: el modelo de orden 1 nunca
   las propone como primera opción. Un modelo de orden 2 o un LSTM, con contexto
   más largo, es la vía natural de mejora.
3. La comparación con la línea base sí es sólida: mismas campañas retenidas,
   mismo criterio de acierto, y ninguno de los dos modelos conoce el generador.

## 4.ter Evaluación del detector de anomalías

**Protocolo.** El detector es no supervisado, lo que impone dos condiciones que la
demostración no cumplía y la evaluación sí:

1. Se entrena **solo con tráfico benigno**. Entrenar con los ataques dentro hace
   que el modelo los aprenda como parte de la normalidad.
2. Se mide sobre eventos **que no vio**, con todos los ataques en el conjunto de
   evaluación.

**Métricas y por qué estas.** Las clases están muy desbalanceadas, así que la
exactitud engaña: con un 1% de ataques, no marcar nada acierta el 99%. Se
reportan precisión y exhaustividad por separado, matriz de confusión, AUC-ROC y
**AUC-PR**, exhaustividad **por familia de ataque** y una tabla de puntos de
operación.

Resultado de referencia sobre flujos sintéticos en formato UNSW-NB15 (5000
flujos, 10% de ataques; sirve para validar la tubería, no para la memoria):

| Métrica | Valor |
|---|---:|
| Precisión | 0.894 |
| Exhaustividad | 0.304 |
| F1 | 0.454 |
| Tasa de falsos positivos | 0.008 |
| AUC-ROC | 0.958 |
| AUC-PR | 0.826 |

Tres lecturas que conviene llevar preparadas a la defensa:

- **El AUC-ROC de 0.958 no significa que el detector funcione bien.** En el punto
  de operación por defecto, la exhaustividad es 0.30: encuentra tres de cada diez
  ataques. La distancia entre el AUC-ROC y el AUC-PR (0.826) es exactamente el
  efecto del desbalance que la ROC disimula.
- **El desglose por familia explica el promedio.** La exfiltración se detecta al
  100% y el canal de mando al 81%, pero la explotación web al 9% y la denegación
  de servicio al 14%. El detector ve lo volumétrico y lo de puerto raro; no ve lo
  que imita tráfico normal.
- **Eso es el argumento a favor de la detección híbrida**, no un defecto que
  esconder: lo que el modelo no supervisado no ve, lo ven las reglas; lo que las
  reglas no conocen, lo ve el modelo. El proyecto defiende esa combinación y aquí
  está la evidencia numérica de por qué hace falta.

El punto de operación es una decisión con criterio operativo. Con el mismo
detector, el percentil 75 da F1 = 0.717 con un 11.6% de falsos positivos, y el
percentil 99 da precisión 1.000 con exhaustividad 0.056. No hay un valor por
defecto correcto: depende de cuántos falsos positivos tolere el equipo.

## 4.quater Cobertura de ATT&CK

`attack-sync --coverage` responde a la pregunta que un tribunal hará tarde o
temprano: **¿qué parte de ATT&CK cubre esto?**

| | |
|---|---:|
| Técnicas con al menos una regla | 7 |
| Técnicas de la matriz empresarial | 222 |
| **Cobertura** | **3.1%** |

Repartidas en seis de las quince tácticas. Sin cobertura: reconocimiento,
desarrollo de recursos, acceso inicial, sigilo, degradación de defensas,
recolección e impacto.

Un 3.1% es un resultado honesto para un prototipo de laboratorio con siete reglas
escritas a mano, y es la justificación numérica de la siguiente fase: integrar
las más de 3000 reglas Sigma de la comunidad multiplica esa cifra sin escribir
detecciones una a una. La capa de cobertura de Navigator convierte ese número en
una figura donde el hueco se ve de un vistazo.

## 5. Hoja de ruta (trabajo futuro)

1. ~~Matriz ATT&CK completa desde el STIX oficial de MITRE~~ **hecho**
   (`attack_data.py`, caché versionada, capas de Navigator).
2. Parser Sigma completo (para reutilizar miles de reglas de la comunidad).
   Justificación medida: la cobertura actual es del 3.1% de la matriz.
3. ~~Modelo de secuencia entrenable para la predicción, con métricas~~ **hecho**
   (Markov de orden 1 + precisión@k, matriz de confusión y F1). Siguiente paso:
   orden 2 o LSTM, y reentrenar con secuencias observadas en vez de sintéticas.
4. ~~Evaluación cuantitativa sobre CICIDS2017 / UNSW-NB15 con matriz de confusión
   y curvas ROC~~ **hecho** (cargadores, protocolo de medición, precision/recall/
   F1, ROC y precisión-exhaustividad, desglose por familia). Siguiente paso:
   ejecutarla sobre los datasets reales descargados y sobre telemetría propia de
   Atomic Red Team, y usar los resultados para calibrar la confianza de las
   reglas, que hoy se deriva de la severidad y no está calibrada.
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
