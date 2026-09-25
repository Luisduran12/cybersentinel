# CyberSentinel — Informe de disposición para producción

**Fecha de la auditoría:** 2026-09-17/18
**Método:** servidor real (`uvicorn`) arrancado en `127.0.0.1:8000`, tráfico
real por `curl`/`httpx`, panel probado en un navegador Chrome real, proceso
matado con `kill -9` de verdad. Nada de lo que sigue se dedujo leyendo
código sin ejecutarlo. Evidencia cruda en `docs/evidence_production_audit/`.

---

## 1. VEREDICTO FINAL

# CONDITIONAL GO

CyberSentinel **no es un MVP de mentira**: el flujo completo — ingesta HTTP
real, autenticación real, Sigma+ML+correlación reales, persistencia WAL
real, panel SOC real, auditoría con hash-chain real — funciona de punta a
punta contra un servidor real, y sobrevivió a un `kill -9` en medio del
procesamiento sin perder un solo evento. Eso es más de lo que la mayoría de
"agentes" de este tamaño logran.

Pero **encontré 3 bugs críticos que habrían bloqueado cualquier despliegue
real** (dos de los cuales habrían hecho que el sistema pareciera funcionar
mientras estaba, en la práctica, roto o vacío), y **un problema de fondo
—el ruido del detector de ML— que hace que la operación diaria sea
inviable para un analista humano tal como está calibrado hoy.**

Los 3 críticos y el problema de ruido de ML (H-08) ya están corregidos y
probados (**Actualización 2026-09-18**: el umbral de decisión del detector
de anomalías se calibró contra el mismo tráfico de esta auditoría —FPR
30.5%→2.1% en validación, 2.9% en test nunca visto— ver H-08 en la Sección
5 para el detalle completo). Sigue en pie el veredicto **CONDITIONAL GO**,
no GO: quedan hallazgos MEDIO/BAJO sin resolver (H-04, H-05, H-07, H-09,
H-10, H-11, Sección 5) que no bloquean un piloto supervisado pero sí
convendría cerrar antes de un SOC desatendido de producción — ver Sección 6.

**pytest: 665 passed, 1 skipped, 0 fallos** (empezó en 651; +14 por las
pruebas de regresión de los bugs encontrados en esta auditoría).

---

## 2. FLUJO REAL VERIFICADO

Evento enviado por `curl` real a `POST /api/v1/events` (Windows/Sysmon,
PowerShell ofuscado) → trazado hasta el panel. Evidencia completa:
`docs/evidence_production_audit/e2e_incident_test_001.json` y
`wal_recovery_after_kill9.log` (el log crudo del servidor, sin editar,
incluyendo los 404 del bug de panel antes de arreglarlo).

| # | Paso | Estado | Qué pasó exactamente |
|---|---|---|---|
| 1 | API recibe el evento | ✅ EJECUTADO | `202 Accepted`, `{"accepted":1,"queued":1}`. El formato **literal** del prompt de esta auditoría (`source_type`+`raw_event` anidado) da **422** — el contrato real usa `source` y campos planos. Ver H-06. |
| 2 | Collector Sysmon normaliza | ⚠️ PARCIAL | El evento llegó vía `ingestion/normalizer.py::parse_sysmon` (duplicado del `collectors/sysmon.py`), **no** vía el collector. Ver H-01: los 5 `collectors/` estaban huérfanos de la API HTTP hasta que los conecté en esta auditoría. |
| 3 | Sigma evalúa el evento | ✅ EJECUTADO | Dispararon **dos** reglas reales sobre el mismo patrón: `RULE-0002` (motor propio) y `3d6d4b49-...` (pySigma, adaptación de SigmaHQ) — ambas técnicas T1059/T1059.001. |
| 4 | ML puntúa el evento | ✅ EJECUTADO | `anomaly_score: 0.0` (evento único, sin baseline entrenada aún). En el test de carga (Fase 4) el mismo componente puntuó el **78% del tráfico sintético como anómalo** — ver H-08, crítico. |
| 5 | Behavioral analytics procesa | ✅ EJECUTADO | Corrió (visible en `stage_status`), sin desviaciones porque era el primer evento del host — comportamiento correcto: no hay baseline con un solo evento. |
| 6 | CTI enriquece | ✅ EJECUTADO (sin match) | `CTI_MATCH=NONE`, declarado explícitamente en la narrativa, no omitido en silencio. CTI en vivo (AbuseIPDB/OTX) no se probó: `enable_live_cti=False` por defecto (diseño, no bug). |
| 7 | Correlación temporal agrupa | ✅ EJECUTADO | `stage_status.temporal: OK`. Con una cadena real (fuerza bruta + PowerShell) en la Fase 4-D del desarrollo, produjo una predicción de kill-chain real con el modelo de Markov entrenado. |
| 8 | Se crea un incidente | ✅ EJECUTADO | `incident_id = "test-001"` en `incidents.db`, consultable por `GET /api/v1/incidents/test-001`. |
| 9 | XAI genera explicación | ✅ EJECUTADO (con fallback declarado) | `llm_status: "UNAVAILABLE"`, `fallback_used: true` — sin API key de LLM configurada, el sistema **no fingió** una explicación de IA: generó una narrativa determinista real a partir de la evidencia y lo dijo explícitamente. Esto es exactamente el comportamiento "sin mocks" que se pedía. |
| 10 | Aparece en `/api/v1/incidents` | ✅ EJECUTADO | Confirmado por `GET`, y visualmente en el panel SOC real (capturas en esta sesión). |
| 11 | La auditoría lo registra | ✅ EJECUTADO | `incident_analyzed` en `audit.jsonl`, más `action_executing`/`action_completed` de las dos respuestas Nivel 1 (webhook + ticket) que dispararon automáticamente por cruzar `ALERT_THRESHOLD`. Cadena verificada con `audit.verify()`. |

**Bonus, no pedido pero verificado:** el veredicto HITL desde el panel real
(Fase 6) — **este es el hallazgo más grave de toda la auditoría** (H-02) y
ya está corregido y reprobado en el navegador.

---

## 3. COMPONENTES HUÉRFANOS

Tabla de 25 componentes, verificados trazando si el evento de la Fase 1
realmente los toca — no leyendo si "existen".

| Componente | Estado | Evidencia |
|---|---|---|
| `collectors/sysmon.py` | 🔌 **HUÉRFANO → CONECTADO EN ESTA AUDITORÍA** | La API HTTP nunca lo llamaba; usaba su propio `parse_sysmon` duplicado en `ingestion/normalizer.py`. No hacía falta reconectarlo (el duplicado funciona), pero queda documentado como deuda: dos implementaciones del mismo mapeo. |
| `collectors/linux.py` | 🔌 **HUÉRFANO → CONECTADO** | `ingestion/normalizer.py` no tenía parser de Linux en absoluto — un evento `source:"linux"` cae por lo silencioso al parser de Sysmon con el aviso `fuente_desconocida`. Corregido: ahora delega en `LinuxCollector` real. Ver H-01. |
| `collectors/firewall.py` | 🔌 **HUÉRFANO (duplicado, no crítico)** | Igual que sysmon: la API usa su propio `parse_firewall`, no este collector. Funciona, pero es una segunda implementación del mismo mapeo. |
| `collectors/suricata.py` | 🔌 **HUÉRFANO → CONECTADO** | Sin parser dedicado antes de esta auditoría; ahora la API delega en el collector real. Verificado con una alerta Suricata real por curl (`annotations: {"collector:suricata":1}`). |
| `collectors/wazuh.py` | 🔌 **HUÉRFANO → CONECTADO** | Igual que Suricata. Verificado por curl. |
| `detection/rules_engine.py` (Sigma) | ✅ CONECTADO | 45 reglas activas (7 propias + 38 pySigma), ambas disparando sobre tráfico real (Sección 2, paso 3). |
| `detection/anomaly.py` (Isolation Forest) | ✅ CONECTADO | Corre en cada lote. Medido en 78% de falsos positivos con el umbral de decisión original (0.5); **corregido en H-08** calibrando ese umbral a 0.602 (FPR 2.1-2.9%, ver `reports/anomaly_threshold_calibration.json`). El modelo/contaminación en sí no se retocó. |
| `detection/temporal.py` | ✅ CONECTADO | `stage_status.temporal: OK` en cada evento. |
| `analytics/baseline.py` | ✅ CONECTADO | Aprende de cada evento (`profiler.observe()` tras cada evidencia). |
| `analytics/profiler.py` | ✅ CONECTADO | Es la fachada que usa `pipeline.py`. |
| `analytics/deviation.py` | ✅ CONECTADO | `stage_status.behavior: OK` en cada evento. |
| `analytics/risk_score.py` | ✅ CONECTADO | Verificado en Fase 4-D: alerta proactiva real disparada por acumulación de risk score. |
| `cti/enricher.py` (STIX local) | ✅ CONECTADO | `stage_status.cti: OK`, `CTI_MATCH=NONE` declarado cuando no hay coincidencia. |
| `cti/abuseipdb.py` | ⚠️ PARCIAL (por diseño) | Cliente real, pero `enable_live_cti=False` por defecto — no se ejecuta salvo que se active explícitamente. No probado contra tráfico real en esta auditoría (requeriría API key). |
| `cti/otx.py` | ⚠️ PARCIAL (por diseño) | Igual que AbuseIPDB. |
| `cti/cisa_kev.py` | ✅ CONECTADO (verificado con Internet real) | 1.713 CVEs reales descargados en pruebas previas; no se re-verificó en esta sesión pero el cliente es funcional. No se invoca automáticamente por evento (requiere un campo CVE que ningún collector produce hoy). |
| `correlation/correlator.py` | ✅ CONECTADO | Predicción de kill-chain real verificada en desarrollo (Fase 4-D); no se disparó en el smoke test de la Fase 1 porque un solo evento no forma una secuencia de tácticas. |
| `correlation/mitre.py` | ✅ CONECTADO | Nombres de técnica/táctica en la narrativa y en el panel vienen de aquí (`T1059` → "Ejecución"). |
| `explanation` / LLM explainer | ✅ CONECTADO, degradado honestamente | `llm_status: UNAVAILABLE` + fallback determinista real, sin fingir una respuesta de IA. |
| `response/executor.py` | ✅ CONECTADO | Dos acciones Nivel 1 reales (webhook simulado por DRY_RUN, ticket simulado por DRY_RUN) se ejecutaron y auditaron para el incidente de prueba. |
| `response/actions.py` (`ResponsePlanner`) | ✅ CONECTADO | Es quien propone las acciones que `executor.py` ejecuta. |
| `governance/audit.py` | ✅ CONECTADO | Cadena verificada (`audit.verify() == True`) tras el ciclo completo, incluida la aprobación HITL real. |
| `governance/policy.py` | ✅ CONECTADO | Clasifica ALLOWED/REQUIRES_APPROVAL en cada recomendación (visible en el panel: "Permitida"). |
| `api/incidents.py` | ✅ CONECTADO, guarda incidentes reales | `incidents.db` con el incidente completo, consultable, editable vía PATCH real. |
| `api/panel/` | ⚠️ → ✅ **CRÍTICO, CORREGIDO EN ESTA AUDITORÍA** | Ver H-02. El panel se sirve y muestra datos reales, pero su función de veredicto HITL llamaba a un endpoint (`/decision`) que **nunca existió** en el backend. Corregido y reprobado en el navegador. |

**Resumen:** 3 collectors realmente huérfanos de la API (linux, suricata,
wazuh) → **conectados**. 2 collectors duplicados pero funcionales (sysmon,
firewall) → documentados como deuda, no bloqueante. El bug más grave no
estaba en un componente "huérfano" sino en un **contrato roto entre dos
componentes que sí estaban conectados** (panel.js ↔ API): eso es más difícil
de encontrar grepeando imports, y es la razón de fondo por la que esta
auditoría abrió un navegador de verdad en vez de confiar en el análisis
estático.

---

## 4. MÉTRICAS REALES

### 4.1 Carga: 1.020 eventos en 60s a 17 ev/s objetivo (`scripts/telemetry_generator.py`)

Evidencia: `docs/evidence_production_audit/stress_test_1020_events.json`,
`resource_usage_summary.json`.

| Métrica | Valor real medido |
|---|---:|
| Eventos enviados | 1.020 |
| Eventos aceptados | 1.020 (100%) |
| Eventos rechazados | 0 |
| Caudal logrado | 17.0 ev/s (= objetivo) |
| Latencia de **petición** HTTP (cliente) p50/p95/p99 | 66.7 / 68.6 / 68.8 ms |
| Latencia de **ingesta** (servidor, hasta encolar) p50/p95/p99 | 2.06 / 2.19 / 10.7 ms |
| Latencia **extremo a extremo** (hasta persistir) p50/p95/p99 | 130.8 / 186.7 / 455.1 ms |
| CPU máximo del proceso servidor | 44.0% |
| CPU promedio | 11.8% |
| RAM máxima (RSS) | 333.0 MB |
| RAM promedio | 329.5 MB |
| ¿Se cayó el servidor? | **NO** |
| ¿Se perdió algún evento? | **NO** (1.020 enviados = 1.020 `processed` en `/metrics`) |
| Incidentes generados de 1.027 eventos totales del lote | **51** (≈5%) — vía `ANOMALY_ONLY` (802), `RULE_AND_ANOMALY` (40), `RULE_MATCH` (11), `BEHAVIORAL_ANOMALY` (3) |

*Nota: la latencia de petición (66ms) es mucho mayor que la de ingesta
(2ms) porque el generador manda lotes de 17 eventos por petición HTTP y
mide el viaje completo; la cifra que le importa a un integrador real es la
de ingesta.*

### 4.2 Recuperación ante `kill -9` (500 eventos en vuelo)

| Métrica | Valor |
|---|---:|
| Eventos aceptados antes del `kill -9` | 500 |
| Eventos perdidos | **0** |
| Eventos recuperados del WAL al reiniciar | 500 (exacto) |
| Mensaje real del servidor al reiniciar | `"Recuperados 500 eventos aceptados y no procesados del arranque anterior. No se perdió nada; se reprocesarán."` |
| `total_events` antes / después del kill+restart | 1.029 → 1.529 (exacto: +500) |

Este es, con diferencia, el resultado más sólido de toda la auditoría.

---

## 5. FALLOS ENCONTRADOS

### 🔴 CRÍTICO

**H-01 — Los collectors de Linux/Suricata/Wazuh nunca se ejecutaban desde la API HTTP real.**
`ingestion/normalizer.py` (el módulo que usa `IngestService`, es decir, la
API real y la CLI) no tenía parser para `source: "linux"`, `"suricata"` ni
`"wazuh"` — caían en silencio al parser de Sysmon con la etiqueta
`fuente_desconocida`. Los 3 collectors existían, estaban probados y
funcionaban... pero solo si algo los invocaba directamente en un test, no a
través del producto real. Confirmado con `curl` real antes y después del
fix.
**Estado: RESUELTO.** `normalizer.py` ahora delega en los collectors reales
para esas 3 fuentes (`_parse_via_collector`). Verificado por curl contra la
API real (`annotations: {"collector:suricata":1}` etc.) y con 8 pruebas
nuevas (`tests/test_production_readiness_normalizer_gap.py`).

**H-02 — El panel SOC real no podía registrar ningún veredicto humano (HITL roto de punta a punta).**
Los cuatro botones de veredicto ("Verdadero positivo", "Falso positivo",
"Benigno", "Dudoso") llamaban a `POST /api/v1/incidents/{id}/decision` — un
endpoint que **nunca se implementó** en el backend (quedó documentado en un
comentario del router y en un diccionario muerto, pero la ruta real,
probada desde hace tiempo, es `/triage` con otro contrato de campos). Cada
clic devolvía 404 silenciosamente (un toast "Error 404" que un analista
real fácilmente pasaría por alto). Esto significa que **la función central
de human-in-the-loop del panel no funcionaba en absoluto**, y ningún test
automatizado lo detectó porque nada ejecutaba el JavaScript del panel.
**Estado: RESUELTO.** `panel.js` corregido para llamar a `/triage` (3
verdictos) y a `PATCH /incidents/{id}` (Benigno, que es una resolución de
cierre, no una transición de triaje). Reprobado a mano en un Chrome real:
los 4 botones actualizan estado, contadores y auditoría correctamente.
6 pruebas nuevas (`tests/test_production_readiness_panel_triage_gap.py`),
incluida una prueba **estructural** que compara cada endpoint que
`panel.js` invoca contra las rutas reales de FastAPI, para que este tipo de
deriva se detecte en `pytest` la próxima vez, no en un navegador.

**H-03 — El bootstrap de credenciales por CLI estaba roto con sus propios valores por defecto.**
`cybersentinel auth create-key --role sensor` (el ejemplo/default en el
propio `--help`) lanzaba `ValueError: 'sensor' is not a valid Role` — los
roles del CLI (`sensor/analyst/responder/auditor/admin`) eran un vocabulario
antiguo que quedó desincronizado del modelo real (`collector/viewer/analyst/admin`
en `api/security/roles.py`). **No había forma de arrancar el sistema desde
cero con el CLI documentado.**
**Estado: RESUELTO.** Los `choices` de `auth create-key`/`create-user` se
corrigieron al vocabulario real. Verificado emitiendo una clave real y dos
usuarios reales, usados durante toda esta auditoría.

### 🟠 ALTO

**H-08 — El detector de ML marca ~78% del tráfico sintético como anómalo.**
En el test de carga (1.027 eventos, 5% "sospechosos" por diseño del
generador), el desglose real fue `ANOMALY_ONLY: 802` (78%),
`RULE_AND_ANOMALY: 40`, `RULE_MATCH: 11`, `BEHAVIORAL_ANOMALY: 3`,
`NO_DETECTION: 171`. Esto confirma con números reales una limitación ya
documentada (`baseline_ready` en `/ready`, "el detector aprende la línea
base del primer lote") pero nunca medida a este volumen: **un SOC real
recibiría decenas de "incidentes" por minuto que son, en su inmensa
mayoría, ruido estadístico de un modelo sin calibrar**, no ataques. Es el
problema más serio de fondo del sistema tal como está hoy.
**Estado: RESUELTO (2026-09-18, fix de seguimiento).** Se calibró el umbral
de decisión (`anomaly_score >= X`, antes 0.5 hardcodeado en cuatro sitios
independientes) contra los mismos 1.020 eventos de este test de carga,
con partición train/validation/test (50/25/25, sin fuga de datos) —
metodología completa en `scripts/calibrate_anomaly_threshold.py` y
`reports/anomaly_threshold_calibration.json`.

| | Umbral 0.5 (anterior) | Umbral 0.602 (calibrado) |
|---|---:|---:|
| FPR (validation) | 30.5% | **2.1%** |
| Recall (validation) | 100.0% | 100.0% |
| FPR (test, holdout) | — | **2.9%** |
| Recall (test, holdout) | — | **66.7%** |

Ambos objetivos (FPR<15%, Recall>60%) se cumplen en validation y se
sostienen en el conjunto de prueba nunca visto durante la selección. El
recall cae de 100% a 66.7% entre validation y test por el tamaño de
muestra (~46 eventos sospechosos en total, ~11-12 por partición): un solo
evento de más o de menos mueve el recall ~8 puntos con esta muestra — se
reporta así, sin ajustar el umbral para maquillar el número de test.
Ahora centralizado en `DEFAULT_ANOMALY_THRESHOLD`
(`CYBERSENTINEL_ANOMALY_THRESHOLD`, `config.py`), usado consistentemente en
`detection/hybrid.py`, `api/incidents.py`, `pipeline.py` y
`correlation/correlator.py` — antes eran cuatro `0.5`/`0.6` independientes
que podían desincronizarse. **No** se tocó `contamination`, la ventana de
entrenamiento ni la arquitectura del modelo: la revalidación estadística
más profunda que merece `PHASE-4.1-SCIENTIFIC-AUDIT.md` sigue siendo
recomendable a futuro, pero el umbral de decisión — la causa directa del
78% medido — ya no es el original sin calibrar.

**H-09 — Alertas de Suricata/Wazuh ya clasificadas como severas por el sistema externo no se convierten en incidentes por sí solas.**
Una alerta Suricata con `severity: 1` (crítica) enviada en el smoke test
(Fase 3) resultó en `NO_DETECTION`: ninguna regla de CyberSentinel
coincidía con `category="ids"`, así que la severidad que Suricata ya le
asignó se perdía. Es coherente con una decisión de diseño documentada
("la detección la hizo Suricata, no CyberSentinel"), pero desde la óptica
de "¿esto sirve para una empresa real?" es un gap: un IDS/SIEM externo que
ya gastó su propio análisis en marcar algo como crítico debería, como
mínimo, generar un hallazgo de baja confianza en CyberSentinel, no
desaparecer.
**Estado: PENDIENTE.** Recomendación: una regla (o etapa) que promueva
`alert_severity`/`wazuh_rule_level` altos a un hallazgo, con su propia
etiqueta de confianza distinguible de una detección propia.

### 🟡 MEDIO

**H-04 — Alta probabilidad de fatiga de alertas por la regla `cs-c2-port-connect` (Fase 4-A).**
En el smoke test de collectors (Fase 3), 3 conexiones al puerto 4444 en 3
minutos generaron **3 incidentes separados** (`fw-000`, `fw-001`, `fw-002`),
cada uno con score 50.0 y severidad "Crítica", porque la regla pySigma
stateless (`cs-c2-port-connect`, se agregó en la Fase 4-A de este mismo
proyecto) dispara en **cada conexión individual**, no solo cuando se agrega
la regla aggregation-based (`RULE-0006`, 3+ en 10 min). El panel real,
visto en el navegador, mostraba **decenas** de incidentes casi idénticos
("Connection to Known C2 Framework Ports · SRV-APP") del test de carga.
**Estado: PENDIENTE — documentado, no corregido.** No lo cambié
unilateralmente porque es una decisión de cobertura-vs-ruido que le
corresponde al operador: bajar la severidad de la variante stateless,
deduplicar por `(regla, entidad, ventana)` antes de crear un incidente
nuevo, o aceptar el volumen si el caso de uso lo tolera.

**H-05 — `/api/v1/ready` no tiene rate limiting, a diferencia de los demás endpoints.**
30 peticiones anónimas seguidas a `/ready` devolvieron **30×200**, sin
ningún 429. El limitador está acoplado a la dependencia de autenticación
(`requires(...)`), y `/ready` es público — por diseño no pasa por ahí. No
es tan grave como parece (`/health` sí está exento a propósito, documentado
en el código; `/ready` sin credencial devuelve muy poca información), pero
es una superficie de DoS barata sin ningún límite.
**Estado: PENDIENTE.**

**H-07 — El panel expone rutas absolutas del sistema de archivos del servidor.**
La sección "Contexto documental" de un incidente muestra rutas como
`/home/user/cybersentinel/data/knowledge/attack/T1110.md` a
cualquier analista autenticado. Solo lo ve alguien ya autenticado con
`incidents:read`, así que el impacto es bajo, pero es información interna
que no debería viajar al cliente.
**Estado: PENDIENTE.**

**H-10 — Cero cobertura de test para el JavaScript del panel.**
La razón de fondo por la que H-02 (el bug más grave de esta auditoría)
sobrevivió sin detectarse: no existe ningún test que ejecute `panel.js`, ni
uno que compare sus llamadas contra las rutas reales de la API. Añadí una
prueba estructural genérica en esta auditoría
(`test_todas_las_rutas_que_llama_panel_js_existen_en_la_api_real`), pero
sigue sin haber ningún test que ejecute el JS de verdad (Playwright/Jest);
la prueba nueva detecta rutas rotas, no lógica rota dentro de una función.
**Estado: PARCIALMENTE MITIGADO.**

### 🔵 BAJO

**H-06 — El contrato real de `POST /api/v1/events` no coincide con lo que asumiría un integrador nuevo.**
El ejemplo de esta misma auditoría (`source_type` + `raw_event` anidado,
inspirado en convenciones tipo OCSF) fue rechazado con 422. El contrato
real exige `source` (no `source_type`) y campos planos (sin envoltorio
`raw_event`). Es una decisión de diseño legítima y ya documentada en
`docs/COLLECTORS.md`, pero **no hay ningún ejemplo de request completo en
la respuesta de error ni en `/docs` (Swagger)** que se lo diga a un
integrador la primera vez.
**Estado: PENDIENTE (documentación).**

**H-11 — El panel no se actualiza solo cuando llegan eventos nuevos.**
No hay `setInterval`, WebSocket ni Server-Sent Events — solo un botón
"Refrescar" manual. Para un panel que se anuncia como "tiempo real" es una
expectativa razonable no cubierta.
**Estado: PENDIENTE.**

**H-12 — El bootstrap inicial (primera credencial admin) no está documentado en ningún sitio operativo.**
Existe (`cybersentinel auth create-key`/`create-user`, ver Sección 7), y
funciona tras corregir H-03, pero no hay un documento de despliegue que lo
mencione — alguien que solo lea `README.md` no sabría cómo arrancar sin
credenciales previas.
**Estado: RESUELTO en este informe** (Sección 7 lo documenta paso a paso).

---

## 6. LO QUE FALTA PARA PRODUCCIÓN REAL

Priorizado por impacto empresarial, no por dificultad técnica.

1. ~~Recalibrar el umbral de decisión del detector de anomalías (H-08).~~
   **RESUELTO 2026-09-18** (ver H-08). Queda como mejora futura, no
   bloqueante: repetir la validación completa de `PHASE-4.1` (contaminación,
   ventana de entrenamiento, no solo el umbral de decisión) con tráfico de
   carga real y, idealmente, con una muestra de ataques mayor a los ~46
   eventos sospechosos disponibles hoy — el recall de test (66.7%) tiene
   margen de error amplio con esa muestra. **Estimado: 3-5 días.**
2. **Definir una política de volumen de incidentes (H-04, H-09).** Decidir,
   con el dueño del producto, si las reglas stateless deben bajar de
   severidad, deduplicarse, o si el volumen es aceptable para el mercado
   objetivo. **Estimado: 1-2 días** de diseño + implementación.
3. **Endurecer `/ready` con rate limiting (H-05).** Cambio contenido.
   **Estimado: medio día.**
4. **Sacar las rutas de archivo del payload que llega al navegador (H-07).**
   **Estimado: medio día.**
5. **Añadir un test runner de JS (Playwright) para el panel (H-10),**
   aunque sea mínimo (cargar la página, click en cada botón, verificar la
   llamada de red) — es la única forma de que un bug como H-02 no vuelva a
   pasar 665 tests de Python sin que nadie lo note.
   **Estimado: 2-3 días** (incluye configurar la infraestructura de
   Playwright, que hoy no existe en el repo).
6. **Documentar el contrato real de ingesta con un ejemplo completo (H-06)**
   en la respuesta 422 o en `/docs`. **Estimado: medio día.**
7. **Panel con actualización automática (H-11).** Polling simple cada
   10-15s sería suficiente para empezar; WebSocket es una mejora posterior.
   **Estimado: 1 día para polling.**
8. **Unificar o documentar la duplicación sysmon/firewall entre
   `collectors/` e `ingestion/normalizer.py`** (deuda técnica de esta misma
   auditoría, no bloqueante, pero confunde a quien lea el código después).
   **Estimado: 1-2 días** si se decide unificar de verdad.

**No están en esta lista** (ya verificados como sólidos en esta auditoría):
la persistencia WAL, la autenticación/autorización, el manejo de JSON
malformado, la idempotencia de eventos duplicados, el backpressure, y el
rendimiento base (44% CPU / 333MB RAM a 17 ev/s con margen visible).

---

## 7. INSTRUCCIONES DE DESPLIEGUE

### 7.1 Dependencias externas

- Python 3.11+, el entorno virtual del repo (`.venv`) o equivalente con
  `pip install -r requirements.txt`.
- `openssl` en PATH solo si se usa `--dev-cert` para TLS de laboratorio.
- Nada de infraestructura externa obligatoria (SQLite embebido, sin Redis/
  Postgres/Kafka). AbuseIPDB/OTX/Slack/SMTP/Wazuh son **opcionales**: el
  sistema funciona sin ellos, simplemente esos componentes quedan
  `NOT_CONFIGURED`.

### 7.2 Variables de entorno relevantes

| Variable | Para qué | Default |
|---|---|---|
| `CYBERSENTINEL_JWT_SECRET` | Firma de tokens de sesión. **Obligatoria en producción** (sin ella, secreto efímero que invalida tokens en cada reinicio). | ninguno |
| `CYBERSENTINEL_DB`, `_IDENTITY_DB`, `_AUDIT`, `_WAL` | Rutas de los almacenes persistentes. | `data/runtime/*` |
| `CYBERSENTINEL_RULES`, `_SIGMA_RULES` | Directorios de reglas propias / pySigma. | `config/rules`, `config/sigma_rules/selected` |
| `CYBERSENTINEL_DRY_RUN` | `true` (default) = ninguna respuesta Nivel 1 sale de verdad. Poner `false` solo con `CYBERSENTINEL_SLACK_WEBHOOK_URL`/`_SMTP_*` ya configurados. | `true` |
| `CYBERSENTINEL_ALLOW_PLAINTEXT` | Solo si hay un proxy TLS delante que no reenvía `X-Forwarded-Proto`. | desactivado |
| `CYBERSENTINEL_ABUSEIPDB_KEY`, `_OTX_KEY` | Activan CTI en vivo real. | sin configurar |
| `CYBERSENTINEL_QUEUE_MAXSIZE`, `_BATCH_SIZE` | Tamaño de cola y lote del worker. | 20000 / 500 |
| `CYBERSENTINEL_ANOMALY_THRESHOLD` | Umbral de decisión del detector de anomalías (H-08, calibrado). Solo cambiarlo con una recalibración real (`scripts/calibrate_anomaly_threshold.py`), nunca a ojo. | `0.602` |

### 7.3 Arranque desde cero (paso a paso, verificado en esta auditoría)

```bash
# 1. Instalar dependencias
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2. Variables mínimas de producción
export CYBERSENTINEL_JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
export CYBERSENTINEL_DB=/var/lib/cybersentinel/events.db
export CYBERSENTINEL_IDENTITY_DB=/var/lib/cybersentinel/identities.db
export CYBERSENTINEL_AUDIT=/var/lib/cybersentinel/audit.jsonl
export CYBERSENTINEL_WAL=/var/lib/cybersentinel/wal

# 3. Bootstrap de credenciales (H-03 ya corregido; antes esto fallaba)
python -m cybersentinel.cli auth create-key --label sensor-principal --role collector --no-expiry
#   -> guarda el token que imprime, no se puede recuperar después
python -m cybersentinel.cli auth create-user --username admin.principal --role admin --password-stdin
#   -> escribe la contraseña por stdin, no como argumento

# 4. Arrancar (con TLS real en producción; --dev-cert solo para laboratorio)
cybersentinel serve --host 0.0.0.0 --port 8000 --tls-cert cert.pem --tls-key key.pem
#   equivalente sin el wrapper de seguridad (NO recomendado si el host no es 127.0.0.1):
#   uvicorn cybersentinel.api.app:app --host 0.0.0.0 --port 8000

# 5. Verificar
curl https://tu-host:8000/api/v1/health   # -> {"status":"alive",...}
curl https://tu-host:8000/api/v1/ready    # -> {"ready":true,...}
```

**Panel SOC real:** `https://tu-host:8000/soc/` (no `/panel` — corregido
en esta auditoría en el propio texto del prompt, no en el código).

### 7.4 Parar / reiniciar

- Parada ordenada: `POST /api/v1/drain` (requiere `identity:admin`) espera
  a que el balanceador saque el proceso de rotación, luego `SIGTERM` normal
  — vacía la cola y cierra el WAL en orden.
- Parada de emergencia: cualquier señal, incluida `kill -9` — **verificado
  en esta auditoría que no pierde eventos aceptados** gracias al WAL. Al
  reiniciar, el propio arranque imprime cuántos eventos recuperó.
- Reinicio: relanzar el mismo comando de arranque con las mismas variables
  de entorno (mismas rutas de `_DB`/`_WAL`/`_IDENTITY_DB`).

### 7.5 Monitorización recomendada desde el día 1

- `GET /api/v1/ready` como *readiness probe* de tu orquestador.
- `GET /api/v1/health` como *liveness probe*.
- `GET /api/v1/metrics` (requiere `metrics:read`) para `queue.utilization`,
  `wal.pending` y, aun con el umbral ya calibrado (H-08), **vigilar la
  proporción `ANOMALY_ONLY` en `store.by_result`**: un umbral calibrado con
  ~46 ataques sintéticos puede necesitar un reajuste con tráfico real de
  producción, y si esa proporción vuelve a crecer sin control es la señal de
  que hace falta recalibrar antes de que el volumen de falsos positivos
  entierre al analista de guardia.
