# CyberSentinel — Fase 4: capacidades del agente defensivo

Este documento se construye bloque a bloque, según se completan (A → B → C →
D → E). Cada sección dice qué se hizo, qué ya existía, qué es limitación real
y dónde está la evidencia en disco. Nada se marca como hecho hasta que
`pytest -q` pasa completo con esa sección incluida.

---

## Bloque A — Cobertura de detección Sigma

### Estado antes de esta fase

La auditoría inicial encontró algo más importante que "pocas reglas": **15
reglas Sigma (pySigma) reales ya existían** en `config/sigma_rules/selected/`,
con manifiesto y documentación completos, pero **`Pipeline` nunca las
cargaba**. Solo las usaba `scripts/evaluate_sigma_phase1.py` para un reporte
offline (`reports/sigma_phase1_*.json`). En producción (CLI y API real) solo
corrían las 7 reglas propias de `config/rules/`.

- Reglas realmente activas en producción antes: **7**
- Cobertura ATT&CK real en producción antes: **7/222 (3.2%)**
- El "18/222 (~8%)" que se suele citar es la cifra del reporte offline de
  Fase 1, que sí combinaba ambos motores — pero solo para el reporte, nunca
  para el pipeline que procesa tráfico real.

### Qué se hizo

1. **Se conectó `RulesEngine.from_sigma_directory()` a `Pipeline`** (nuevo
   parámetro `sigma_rules_dir`), y se activó por defecto en los dos puntos de
   entrada de producción: `IngestService` (la API, `src/cybersentinel/api/app.py`)
   y el comando `analyze` de la CLI (`src/cybersentinel/cli.py`). El motor de
   reglas propio (`config/rules/`) no se tocó ni se sustituyó: ambos se suman.
   - Variable de entorno `CYBERSENTINEL_SIGMA_RULES` permite desactivarlo o
     apuntar a otro directorio sin tocar código.
   - Si el directorio no existe, se registra un WARNING y el pipeline sigue
     con las reglas propias — no hay excepción no controlada.
2. **Se añadieron 23 reglas Sigma nuevas** (15 → 38), priorizando técnicas
   ATT&CK no cubiertas y compatibles con los campos reales de `SecurityEvent`
   (documentados en `docs/SIGMA-COMPATIBILITY-MATRIX.md`). Cada una tiene su
   entrada en `config/sigma_rules/manifest.yaml` con técnica, táctica,
   referencia SigmaHQ cuando aplica, y notas de adaptación.
   - Incluye DNS tunneling (`cs-dns-tunneling.yml`, T1071.004), la regla de
     red que el prompt señalaba como ausente.
   - Cierra dos tácticas que antes no tenían ninguna regla: **Impact**
     (`cs-inhibit-system-recovery`, `cs-service-stop-security`) y
     **Privilege Escalation** (`cs-sudoers-modification`) — ver la nota
     honesta al respecto en `docs/SIGMA-EXCLUSIONS.md`.
3. **Cada regla nueva se probó contra un evento sintético real** que
   representa la técnica que dice cubrir (no solo se verificó que el YAML
   parsea). Ver `tests/test_sigma_expansion.py`.

### Métricas: antes vs. después

| Métrica | Antes (producción real) | Después |
|---|---:|---:|
| Reglas activas en `Pipeline`/API/CLI | 7 | 45 (7 propias + 38 pySigma) |
| Reglas Sigma (pySigma) | 0 activas (15 existían, huérfanas) | 38 activas |
| Técnicas ATT&CK distintas cubiertas | 7 | 41 |
| Técnicas base (sin sub-técnica) cubiertas | 7 | 29 |
| Cobertura sobre 222 técnicas (convención del proyecto, cuenta sub-técnicas) | 3.2% | **18.5%** |
| Cobertura sobre 222 técnicas (solo técnica base) | 3.2% | **13.1%** |
| Tácticas con al menos una regla | 7 de 14 | **10 de 14** |
| pytest | 514 passed | **546 passed**, 1 skipped, 0 failed |

Capas Navigator generadas como evidencia:
`docs/navigator_phase4a_before.json`, `docs/navigator_phase4a_after.json`.

### Limitación honesta: por qué no se llega a 30%+

El objetivo del prompt (30%+ de 222 técnicas) **no se alcanza** ni contando
técnicas base (13.1%) ni con la convención más generosa del proyecto (18.5%).
No es un problema de cuántas reglas se escriben: es un techo de telemetría.

La mayoría de las ~180 técnicas restantes pertenecen a categorías que los
4 collectors actuales (Sysmon, Linux, Firewall, Suricata) **no pueden
observar en absoluto**, no porque falte una regla sino porque no existe el
dato de origen:

- **Cloud** (~40 técnicas): requiere logs de AWS CloudTrail / Azure AD /
  GCP Audit — un collector nuevo, no una regla.
- **Contenedores/Kubernetes** (~15): requiere eventos de runtime (containerd,
  auditd de Kubernetes) — un collector nuevo.
- **Móvil** (~80 en la matriz Mobile, normalmente ni se cuentan sobre
  Enterprise pero infla expectativas si se confunden matrices).
- **ICS** (matriz separada, no aplica a Enterprise 222).
- **Impacto físico/hardware, criptografía, side-channel**: no observables
  por ningún collector de red/endpoint.
- Dentro de Enterprise puro, quedan además ~10-15 técnicas de Windows que sí
  serían alcanzables pero requieren campos que `SecurityEvent` no tiene hoy
  (integridad de proceso, token de acceso, hash de imagen firmado) — están
  detalladas en `docs/SIGMA-EXCLUSIONS.md`.

Subir del 18.5% actual a un 30%+ realista requeriría, en orden de impacto:
1. Enriquecer `SecurityEvent`/collectors con campos ya mencionados en
   `SIGMA-EXCLUSIONS.md` (integrity level, token, hash de imagen) — más
   reglas Windows sin nuevo collector.
2. Un collector de logs cloud (AWS CloudTrail es el más estandarizado) —
   el salto más grande por esfuerzo invertido.
3. Reglas de comportamiento (Bloque B) que no dependen de firma, solo de
   desviación — cubren técnicas que ninguna regla estática puede expresar
   bien (T1078 Valid Accounts, por ejemplo).

Esto no se resuelve escribiendo reglas más débiles para inflar el número;
preferí reportar el número real.

---

## Bloque B — Behavioral Analytics

### Estado antes de esta fase

No existía nada: ni `analytics/`, ni baseline, ni noción de "normal" por
usuario u host. Código enteramente nuevo, sin conflicto con lo existente.

### Qué se hizo

`src/cybersentinel/analytics/`:
- **`baseline.py`** — `EntityBaseline` (horas típicas, IPs vistas, procesos
  vistos, muestras de volumen de salida) y `BaselineStore`, que aprende
  incrementalmente y persiste a JSON (`save`/`load`, mismo patrón que
  `MarkovChainModel`). `confidence` escala con el número de observaciones
  (0 hasta 50 eventos, luego se satura en 1.0): una alerta con 3 datos detrás
  no debería pesar igual que una con 300.
- **`profiler.py`** — `EntityProfiler`, la única puerta de entrada al store:
  `observe(event)` actualiza el baseline del usuario y del host del evento.
- **`deviation.py`** — `DeviationDetector.evaluate(event, profiler)` compara
  contra el baseline (sin actualizarlo todavía) y produce `Deviation`s con
  `score`, `confidence`, técnica ATT&CK si aplica y una explicación en texto:
  - `unusual_hour` (baseline de usuario) → T1078
  - `unknown_ip` (baseline de usuario) → T1078
  - `unknown_process` (baseline de host) → sin técnica específica
  - `unusual_volume` (baseline de host, z-score ≥ 3σ) → sin técnica específica
  - Gate explícito: con menos de 10 observaciones no se genera ninguna
    desviación — "nunca visto" con 3 datos no significa nada.

**Integración con el pipeline existente (tarea B3), sin pipeline paralelo:**
`DetectionEvidence` (`detection/hybrid.py`) gana un campo
`behavioral_deviations` y una propiedad `behavioral_score` (suma de
`score × confidence` de cada desviación — se suman, no se toma el máximo,
igual que los hits de CTI: un evento a deshora *y* con un proceso nunca visto
es más sospechoso que cualquiera de las dos señales sola). `hybrid_score`
suma `behavioral_score × 0.6`, calibrado para que una única señal fuerte con
baseline plenamente confiable (volumen anómalo, score 100) ya cruce
`ALERT_THRESHOLD` por sí sola, igual que una regla Sigma. En `pipeline.py`,
cada evento se evalúa contra el baseline **antes** de que ese mismo evento lo
actualice (si no, un evento nunca se distinguiría de sí mismo).

### Evidencia en disco

`docs/evidence_phase4b_behavioral_detection.json` — corrida real de
`Pipeline.run_events` (sin mocks): 60 eventos "normales" de `ana` en
`SRV-DB` en horario de oficina, seguidos de un evento con `mimikatz.exe` a
las 3:17am. Resultado real: dos desviaciones (`unusual_hour` T1078,
`unknown_process`), `hybrid_score=90.28`, muy por encima de `ALERT_THRESHOLD`
(50.0) — se vuelve incidente sin que ninguna regla Sigma lo tocara.

### Pruebas

`tests/test_behavioral_analytics.py` (13 pruebas): baseline aprende
correctamente, confianza escala con observaciones, persistencia
guardar/cargar, las 4 desviaciones detectadas contra datos sintéticos reales,
2 controles negativos (evento normal no dispara nada; baseline con pocos
datos no alerta), y 2 pruebas de integración contra el `Pipeline` real
(desviación se vuelve hallazgo; comportamiento normal no genera ruido).

### Limitaciones honestas

- **Solo aprende de lo que el pipeline procesa.** Si el atacante es el
  primer evento que el sistema ve de una entidad, no hay baseline: la
  primera observación de cualquiera es, por definición, "normal" (no hay
  nada contra qué compararla). Esto es correcto — no inventar un baseline
  de la nada — pero significa que Bloque B no protege el "día 1" de un host
  o usuario nuevo.
- **`unknown_process`/`unusual_volume` no llevan técnica ATT&CK.** No hay un
  mapeo honesto de "proceso nunca visto" a una técnica específica sin
  inventar contexto que el dato no tiene; se documenta como señal genérica
  en vez de forzar una técnica que no corresponde.
- **La persistencia de baseline en la API real vive junto a `db_path`**
  (`baselines.json`), pero solo se guarda al final de cada lote procesado
  (`run_events`), no evento a evento: en un crash a mitad de lote se pierde
  el aprendizaje de ese lote (no la detección ya hecha, que sigue su camino
  normal por el WAL).
- **El umbral de "hora típica" (≥2% de la actividad total)** y el de
  volumen (z-score ≥ 3σ) son heurísticos razonables, no calibrados contra
  un dataset etiquetado de comportamiento — a diferencia del detector de
  anomalías ML, que si tiene esa validación (ver `docs/PHASE-4.1-SCIENTIFIC-AUDIT.md`).

## Bloque C — Threat Intelligence en vivo

### Estado antes de esta fase

Existía `cti/enrichment.py` + `stix_ingestor.py`: matching real de IOCs, pero
solo contra un bundle STIX **local**, sin ninguna llamada de red a un feed
externo. Ningún cliente de AbuseIPDB, OTX o CISA KEV existía.

### Qué se hizo

`src/cybersentinel/cti/`:
- **`feeds.py`** — interfaz común `CTIFeed` + `FeedResult`, con un
  vocabulario de estado explícito (`OK`, `NOT_CONFIGURED`, `ERROR`,
  `RATE_LIMITED`, `NOT_FOUND`): sin API key se declara `NOT_CONFIGURED`, no
  se inventa un resultado "limpio".
- **`abuseipdb.py`** — cliente HTTP real (vía `httpx`, ya era dependencia del
  proyecto) contra `api.abuseipdb.com`. Lee la key de
  `CYBERSENTINEL_ABUSEIPDB_KEY`. Malicioso si `abuseConfidenceScore ≥ 25`
  (el umbral que el propio AbuseIPDB recomienda).
- **`otx.py`** — cliente real contra `otx.alienvault.com`, lee
  `CYBERSENTINEL_OTX_KEY`. Score propio derivado de cuántos *pulses* de la
  comunidad reportan el observable (OTX no da un score 0-100 nativo).
- **`cisa_kev.py`** — cliente real del catálogo público (sin API key).
  **Verificado con acceso real a Internet, no solo con mocks**: cargó
  **1.713 CVEs reales** desde `cisa.gov` e identificó correctamente
  CVE-2021-44228 (Log4Shell) como explotado activamente. Evidencia:
  `docs/evidence_phase4c_cisa_kev_real.json`.
- **`cache.py`** — `CTICache` con TTL de 1 hora por `(feed, observable)`,
  persistida a disco: cumple literalmente "no consultar la misma IP dos
  veces en menos de una hora".
- **`enricher.py`** — `LiveCTIEnricher`: descarta IPs privadas/loopback
  (consultarlas es gasto de cuota sin sentido), consulta cada feed
  configurado con caché, y arma una `narrative` legible
  ("`185.220.101.5` reportada en `abuseipdb` (score 95/100)...") en el
  mismo formato que pide el prompt.

**Integración con el pipeline (tarea C2), con una decisión de diseño
explícita:** los feeds en vivo **no se consultan en todos los eventos**.
Se añadió una etapa `live_cti` en `pipeline.py`, gateada a que el evento
**ya** tenga alguna señal (una regla Sigma, `anomaly_score ≥ 0.5`, o una
desviación de comportamiento) — igual que dice el prompt: "cuando
CyberSentinel detecta un evento sospechoso, consulta CTI". Consultar en
*todo* evento agotaría la cuota gratuita de AbuseIPDB (1.000/día) en minutos
en cualquier volumen real, y además representaría una llamada de red
síncrona por evento que degradaría el throughput medido en el Bloque A.
`enable_live_cti=False` por defecto en `Pipeline` (a diferencia de
`enable_behavior`, que es cómputo local): esto sí implica red real y no
debe activarse sin que alguien lo pida explícitamente, ni en pruebas ni en
un análisis offline por lote.

`DetectionEvidence` gana `live_cti_hits`; `hybrid_score` suma
`(score/100) × 40` por cada hit malicioso (comparable en magnitud al CTI
STIX existente).

### Ejemplo real de enriquecimiento

Con un feed de prueba controlado (ver `tests/test_cti_live_feeds.py`): un
evento con una regla Sigma activada (`RULE-0002`, PowerShell ofuscado) hacia
`185.220.101.5` consulta CTI, recibe `malicious=True, score=90`, y el
`hybrid_score` sube de 50 (solo la regla) a 86.0. Con AbuseIPDB real
(requiere key propia), la narrativa sería exactamente la del prompt: *"IP
185.220.101.5 reportada en AbuseIPDB (score 90/100). ..."*.

### Pruebas

`tests/test_cti_live_feeds.py` (30 pruebas), sin dependender de Internet:
usa `httpx.MockTransport` para interceptar la red y probar el código real
(URL, headers, parseo, manejo de 429/errores) — no se sustituye la clase de
feed entera por un doble. Cubre: sin key → `NOT_CONFIGURED`; respuesta real
parseada; 429 → `RATE_LIMITED` sin excepción; error de red → `ERROR` sin
excepción; caché evita segunda consulta en la misma hora y expira pasado el
TTL; IPs privadas nunca se consultan; integración con el `Pipeline` real
mostrando que un evento benigno NO gasta cuota y uno con señal previa sí se
enriquece y sube su score.

### Limitaciones honestas

- **AbuseIPDB y OTX están reales pero inertes sin key propia** — decisión
  tomada explícitamente en esta conversación. El código funciona de punta a
  punta (verificado con `httpx.MockTransport`); falta que el operador
  configure `CYBERSENTINEL_ABUSEIPDB_KEY`/`CYBERSENTINEL_OTX_KEY` para que
  consulte de verdad en producción.
- **CISA KEV no puede correlacionar "software detectado"** como pide el
  prompt: ningún collector actual normaliza un CVE o una versión de
  software en `SecurityEvent`. El cliente es 100% real y consultable por
  CVE, pero la correlación automática necesitaría un campo de origen que
  hoy no existe (requeriría, por ejemplo, que el collector de Windows
  extrajera versión de producto de Sysmon EventID 1's `Product`/`Company`,
  que hoy se descarta).
- **El score de OTX es una heurística propia** (10 puntos por pulse, techo
  100), no algo que OTX entregue nativamente — se documenta para que nadie
  lo confunda con un score oficial de la plataforma.
- **La consulta a CTI en vivo es síncrona dentro de `run_events`**: con
  ambos feeds lentos o caídos, un evento con señal previa espera la
  respuesta HTTP (o su timeout de 5s) antes de seguir. Aceptable para el
  volumen que ya pasó el filtro de "solo eventos con señal", pero sería un
  cuello de botella real si ese filtro se relajara.

## Bloque D — Predicción mejorada

### Estado antes de esta fase

Igual que la Fase 4-A con las reglas Sigma: **`Correlator`/`KillChainPrediction`
(`correlation/correlator.py`) existían, bien probados (`tests/test_temporal_correlation.py`,
`test_sequence_model.py`, `test_mitre_attack.py`), pero `Pipeline.run_events()`
nunca los invocaba.** Solo los usaba `scripts/eval_5_3.py` para un reporte
offline. En producción no existía ninguna predicción de kill-chain — el
"predictor actual" que describe el problema del prompt no estaba corriendo.
Tampoco existía `analytics/risk_score.py`: `Incident.risk_score` es
**por incidente**, se recalcula desde cero cada vez y no recuerda nada entre
incidentes.

### Qué se hizo

1. **Se conectó `Correlator` a `Pipeline`** (`enable_kill_chain_prediction=True`
   por defecto — cómputo local puro, sin el riesgo de red del Bloque C). Al
   final de cada lote, `pipeline.py` construye `Finding`s desde los
   `RuleHit`/`AnomalyResult` reales del lote, los correlaciona por
   entidad/ventana y guarda la predicción en `PipelineReport.kill_chain_predictions`.
   Usa el modelo de Markov ya entrenado (`models/markov_tactics.json`,
   `cybersentinel train-prediction`) si existe; si no, cae a
   `CanonicalBaseline` (el propio default de `Correlator`).
2. **`correlation/prediction_context.py`** (tarea D1) — reordena/reescala la
   salida cruda de `predict_next` **sin tocar el modelo**, con cuatro
   factores: tipo de entidad (heurística de nombre: `SRV-`/`DB-`→servidor,
   `WKS-`/`PC-`→estación), severidad acumulada del incidente,
   eventos/minuto, y si CTI ya confirmó contexto de campaña. Cada factor
   multiplica, nunca renormaliza (mismo principio de honestidad que ya
   tenía `sequence_model.py`: la masa no repartida sigue siendo "no sé").
3. **`analytics/risk_score.py`** (tarea D2) — `RiskScoreTracker`: risk score
   por entidad, persistente entre incidentes y con decaimiento temporal
   (`DEFAULT_DECAY_PER_HOUR`). No necesitó un parámetro especial para "sube
   más rápido si correlaciona": como el score se acumula sobre lo que no ha
   decaído, dos detecciones cercanas en el tiempo se suman casi íntegras y
   dos separadas por días casi no dejan rastro la una de la otra — es una
   propiedad del diseño aditivo + decaimiento, no una regla aparte. Un hit de
   CTI confirmado (`cti_confirmed=True`) garantiza un piso de 60 puntos: "se
   dispara si CTI confirma compromiso".
4. **Alertas proactivas** (tarea D3) — al final de cada lote, cualquier
   entidad cuyo risk score cruce `PROACTIVE_ALERT_THRESHOLD` (70) genera una
   alerta en `PipelineReport.proactive_alerts` (y queda en el `AuditLog` si
   hay uno configurado), **antes** de que exista un incidente formal que la
   dispare. No se repite mientras el score siga por encima del umbral; se
   rearma si baja y vuelve a subir.

### Ejemplo real (evidencia en disco)

`docs/evidence_phase4d_kill_chain_and_risk.json` — 6 fallos de login +
5 PowerShell ofuscados contra `SRV-DB`, procesados por `Pipeline.run_events`
real:

- **Predicción de kill-chain real**, con el modelo de Markov entrenado:
  fase actual "Acceso a credenciales" (9/15), siguiente más probable
  "Descubrimiento" (52%), ajustada por contexto porque `SRV-DB` se infiere
  como servidor ("las fases de post-explotación se ponderaron al alza").
- **Alerta proactiva real**: *"SRV-DB tiene risk score 100/100, recomendamos
  investigación proactiva"* — exactamente el formato que pedía el prompt.

### Pruebas

`tests/test_phase4d_prediction_and_risk.py` (23 pruebas): inferencia de tipo
de entidad, reponderado (favorece fases tardías en servidores/CTI-flagged,
neutro sin factores, nunca supera 1.0), acumulación y decaimiento del risk
score, el boost mínimo por CTI confirmado, que la alerta proactiva se
dispara una sola vez por cruce y se rearma tras bajar y volver a subir,
persistencia a disco, y dos pruebas de integración contra el `Pipeline` real
(predicción de kill-chain real; alerta proactiva real; control negativo con
tráfico benigno).

### Limitaciones honestas

- **La heurística de tipo de entidad es de nomenclatura, no un inventario
  real.** Sin un CMDB conectado, un host que no siga la convención
  `SRV-`/`WKS-` cae en `"unknown"` — declarado, no adivinado.
- **`cti_flagged` depende de que el Bloque C haya corrido antes en el mismo
  lote.** Con `enable_live_cti=False` (el default) o sin API keys, ningún
  incidente se marca como confirmado por CTI; el reponderado sigue
  funcionando con los otros tres factores.
- **La predicción de kill-chain se recalcula por lote, no es un estado
  persistente por incidente entre lotes.** Un incidente que se correlaciona
  con findings de dos `run_events()` distintos (dos peticiones HTTP
  separadas a la API) se predice dos veces, de forma independiente — no
  hay, todavía, un `Incident` persistente entre llamadas.

## Bloque E — Respuesta defensiva real

### Estado antes de esta fase

El hallazgo más importante de las cinco fases: **había dos sistemas de
respuesta que no se hablaban entre sí.**

| Sistema | Conectado al `Pipeline` | Tests | Ejecuta algo real |
|---|---|---|---|
| `response/actions.py` (`ResponsePlanner`+`GovernancePolicy`) | Sí | Indirectos | No: `execute_allowed()` solo arma un string `"[DRY-RUN] ... simulada"`, y ni siquiera se llamaba desde el pipeline |
| `response/executor.py` (`ResponseAction`/`ActionStatus`) | **No, cero referencias fuera de su archivo** | **Cero** | No: `ExternalIntegrationMock`, simulado incluso en "modo real" |

`self.planner.plan(evidence)` sí corría en cada evento (incluidos los
benignos) y clasificaba correctamente ALLOWED/REQUIRES_APPROVAL/PROHIBITED
vía `GovernancePolicy` real — pero el resultado se guardaba en el reporte y
ahí se quedaba. Nada se ejecutaba, ni siquiera en simulación.

### Qué se hizo

1. **Se conectaron ambos sistemas** en vez de construir un tercero:
   `ResponsePlanner` sigue proponiendo y clasificando (no se tocó su
   lógica); cada `Recommendation` no prohibida se traduce
   (`RESPONSE_ACTION_MAP` en `pipeline.py`) a una `ResponseAction` real
   sometida a `ResponseExecutor`.
2. **`response/integrations.py`** (tarea E1) — cuatro integraciones reales
   reemplazando `ExternalIntegrationMock`:
   - `WebhookNotifier` — POST real a Slack/Teams (`CYBERSENTINEL_SLACK_WEBHOOK_URL`).
   - `EmailNotifier` — SMTP real (`CYBERSENTINEL_SMTP_*`).
   - `TicketWriter` — escribe un JSON real compatible con Jira/ServiceNow a disco.
   - `IOCBlocklist` — lista local real de IOCs bloqueados, idempotente.
   - Las cuatro respetan `dry_run` de forma **estricta**: con `dry_run=True`
     (el default, `CYBERSENTINEL_DRY_RUN`) no se ejecuta nada — ni HTTP, ni
     SMTP, ni escritura a disco — la interpretación más literal de "DRY_RUN
     no ejecuta nada real".
3. **Nivel 2 nunca ejecuta contra un sistema real**, se apruebe o no:
   `_generar_comando()` produce el comando exacto (`iptables ...`,
   `net user ... /active:no`, etc.) en cuanto se propone la acción — el
   analista ve qué se le pide aprobar, no una descripción vaga. Aprobarlo
   solo marca la acción como `COMPLETED` con
   `executed_against_real_system: false`: no hay integración real con un
   firewall/EDR/IdP en este proyecto, y añadir una sin autorización del
   operador sería ejecutar contra un sistema externo sin autorización
   —prohibido explícitamente por el prompt.
4. **Salvaguarda explícita "LLM no puede aprobar":** `approve_action`
   rechaza (`UnauthorizedApproverError`) cualquier `approved_by` que sea
   `llm`/`agent`/`system`/`ia`/vacío, sin importar quién lo invoque.
5. **`collectors/wazuh.py`** (tarea E2, Wazuh → CyberSentinel) — quinto
   collector, mismo contrato que los otros cuatro (`Collector`, nunca lanza
   excepción, campo ausente → `None`). Normaliza el JSON de alerta de
   Wazuh (`rule`, `agent`, `data`, `full_log`) a `SecurityEvent`,
   conservando `rule.level`/`rule.id` en `properties`.
6. **`response/wazuh_client.py`** (CyberSentinel → Wazuh) — cliente real de
   la API de respuesta activa del Wazuh Manager (`PUT /active-response`),
   mismo patrón "real pero inerte sin credenciales" que AbuseIPDB/OTX.

Solo se dispara respuesta para hallazgos reales (`hybrid_score ≥
ALERT_THRESHOLD`), no para cada evento benigno que también pasa por el
planner — mismo razonamiento de cuota que el Bloque C con CTI en vivo.

### Ejemplo real (evidencia en disco)

Un beacon C2 real (`RULE-0006`) sobre `WKS-01` produce, con
`Pipeline.run_events` real:

- **Nivel 1, ya ejecutado** (`docs/evidence_phase4e_response_dry_run.json`):
  webhook de alerta, registro en la lista local de IOCs y un ticket de
  preservación de evidencia — los tres en `DRY_RUN` (el default), sin
  ninguna llamada real.
- **Nivel 2, con aprobación humana real**
  (`docs/evidence_phase4e_response_hitl_approved.json`): la regla de
  firewall (`iptables -A INPUT -s 203.0.113.66 -j DROP`) queda `REQUESTED`
  hasta que `analista.maria` la aprueba; el resultado deja explícito
  `"executed_against_real_system": false`. Cada transición
  (`action_requested`→`action_approved`→`action_executing`→`action_completed`)
  queda en el `AuditLog` con hash verificable (`audit.verify()` → `True`).

### Pruebas

`tests/test_response_defense.py` (33 pruebas): las cuatro integraciones
reales (webhook/email/ticket/IOC), cada una con su caso `dry_run` y su caso
real (SMTP inyectado, `httpx.MockTransport`); Nivel 1 se autoaprueba y
ejecuta, Nivel 2 espera y genera el comando correcto para cada tipo;
**DRY_RUN explícito** (nada se ejecuta con el default, sí con
`CYBERSENTINEL_DRY_RUN=false`); **HITL explícito** (el LLM y el sistema no
pueden aprobar, un humano sí, no se puede aprobar dos veces, rechazar nunca
ejecuta); **auditoría explícita** (cadena verificable, hash presente);
integración con el `Pipeline` real (solo hallazgos generan acción; `block_ip`
genera Nivel 1 + Nivel 2 juntos); Wazuh collector (E2E real + negativas) y
`WazuhResponseClient` (dry_run, sin configurar, real, error de red).

### Limitaciones honestas

- **Nivel 2 nunca toca un sistema real, ni siquiera aprobado.** Es una
  decisión de alcance explícita: este proyecto no tiene una integración de
  firewall/EDR/IdP real, y añadir una sin que el operador la autorice
  específicamente estaría fuera del mandato del prompt ("no ejecutes
  acciones contra sistemas externos sin autorización"). El comando generado
  es el entregable de esta fase; ejecutarlo de verdad es la integración
  siguiente, con las credenciales del operador.
- **Los webhooks/email/Wazuh están reales pero inertes sin credenciales**,
  mismo patrón que AbuseIPDB/OTX del Bloque C.
- **La salvaguarda "LLM no puede aprobar" es una lista de nombres
  reservados**, no una verificación criptográfica de identidad humana. Un
  atacante que comprometa una cuenta humana real y la use para aprobar
  seguiría pasando — eso lo cubre la capa de autenticación de la API
  (`api/security/`), no esta.
- **`enrich_context` no tiene ejecutor real** (es puramente informativo, se
  queda como recomendación sin acción asociada) — documentado, no
  silenciado.
