# Arquitectura de producción — hoja de ruta y estado real

Este documento responde a una pregunta concreta: **¿qué haría falta para que
CyberSentinel deje de ser un prototipo y compita con un producto SIEM/SOAR
real?** Es un plan por fases, con archivos concretos, y con una regla que no
se negocia en ninguna fase:

> **Nada de lo nuevo reemplaza `SecurityEvent`, `Pipeline` ni el motor de
> detección (Sigma + ML + correlación temporal).** Todo lo que sigue se
> conecta *alrededor* de ellos, nunca por dentro. Un evento que hoy dispara
> `RULE-0002` con técnica `T1059` debe seguir disparándolo exactamente igual
> después de cada fase — y cada fase termina con `pytest -q` en verde como
> condición de aceptación, no como opcional.

La razón no es conservadurismo: es que el pipeline actual ya es lo único del
sistema que está *validado científicamente* (ver
`docs/PHASE-5.3-INTEGRAL-EVALUATION.md`, `docs/UNSW-NB15-EVALUATION.md`). Una
migración que lo tocara por dentro invalidaría esa evaluación sin que nadie lo
supiera hasta el próximo incidente real.

## Estado real al momento de escribir esto

Antes de proponer nada nuevo, esto es lo que ya existía o se acaba de construir:

| Pieza | Estado |
|---|---|
| API de ingestión (FastAPI), 4 collectors, panel SOC, WAL, auditoría encadenada | **Ya existía**, production-grade (ver `docs/SECURITY.md`, `docs/COLLECTORS.md`) |
| pySigma como parser/validador de reglas Sigma | **Ya existía** (`pysigma>=1.5.0` en `pyproject.toml`, usado en `detection/sigma_loader.py`/`sigma_adapter.py`) |
| MITRE ATT&CK vía STIX | **Ya existía** parcialmente: `stix2` ingiere bundles reales (`cti/stix_ingestor.py`), pero `mitreattack-python` solo se usa offline para regenerar una caché, no en runtime |
| CTI | **Ya existía**, pero 100% offline: coincide observables contra un bundle STIX local, sin llamadas en vivo a NVD/EPSS/KEV/OTX |
| RAG | **Ya existía**: FAISS vía `langchain-community`, indexando Markdown local |
| LLM | **Ya existía**, ya es read-only por diseño (`llm/providers.py`): explica, nunca decide detección ni respuesta |
| Orquestación multi-agente | **No existía**: `pipeline.py` es una clase lineal, sin grafo de estados |
| OCSF | **No existía** — se implementó en esta sesión (`ingestion/ocsf.py`) |
| Bus de mensajes (streaming) | **No existía** — se implementó en esta sesión (`streaming/`, `docker-compose.yml`) |
| Observabilidad (Prometheus/Grafana/Loki) | **No existía** |
| Contenedores / Kubernetes | **No existía** — `docker-compose.yml`/`Dockerfile` se crearon en esta sesión (Fase 1 solamente) |

Esto importa porque cambia el plan: varias de las "integraciones nuevas" que
pediste ya están hechas, con nombres de herramienta distintos a los que
propusiste (FAISS en vez de pgvector, un evaluador propio en vez de que
pySigma ejecute las reglas). Donde eso pasa, lo digo explícitamente en vez de
proponer una migración que no aporta nada nuevo.

---

## Fase 1 — Ingesta y normalización — **implementada en esta sesión**

### Qué se construyó

| Archivo | Qué hace |
|---|---|
| `src/cybersentinel/ingestion/ocsf.py` | `to_ocsf(SecurityEvent) -> dict` / `from_ocsf(dict) -> SecurityEvent`. Capa aditiva: no toca `schema.py`. |
| `src/cybersentinel/streaming/bus.py` | Cliente delgado sobre NATS JetStream (`nats-py`, opcional). |
| `src/cybersentinel/streaming/normalizer_service.py` | Consume `cybersentinel.raw.<source>`, normaliza con el `Normalizer` **existente**, convierte a OCSF, republica en `cybersentinel.ocsf.<source>`. |
| `Dockerfile` | Imagen única para `api` y `normalizer` (mismo código, distinto `command`). |
| `docker-compose.yml` | `nats` (JetStream) + `api` + `normalizer`. |
| `tests/test_ocsf.py`, `tests/test_streaming.py` | 12 pruebas nuevas, todas sin infraestructura (no requieren NATS ni Docker levantados). |

### Decisiones y por qué (incluyendo dónde tomé el atajo que permitiste)

**NATS JetStream, no Kafka.** Kafka exige ZooKeeper/KRaft, es más pesado para
correr en un portátil de desarrollo, y su ventaja real —un ecosistema enorme
de conectores (Kafka Connect, ksqlDB, Flink)— no aplica todavía porque no hay
un segundo consumidor además del normalizador. NATS da persistencia real
(JetStream, no "fire-and-forget"), un solo binario, cliente async nativo en
Python, y migrar a Kafka después es un cambio de `streaming/bus.py`, no de
arquitectura: el contrato (`publish`/`subscribe` sobre subjects) es el mismo.
**Migrar a Kafka el día que:** haya más de un consumidor real del stream de
eventos crudos, o el volumen supere lo que un solo nodo NATS JetStream
sostiene (cientos de miles de mensajes/s con persistencia — muy por encima
del techo medido hoy de ~3.400 eventos/s en el pipeline de detección, así que
no es el cuello de botella actual).

**Normalizador propio, no Substation ni Tenzir.** Ambos son herramientas
reales y usadas en producción para esto. La razón para no adoptarlos ahora es
la que tú mismo dejaste como salida: son binarios Go con su propio lenguaje de
transformación, y reimplementar en ese lenguaje la lógica de
`ingestion/normalizer.py` —ya escrita, ya probada contra 4 formatos reales—
significa mantener la misma semántica de normalización en dos sitios que
pueden divergir. El servicio que se construyó hace el mismo trabajo
(consumir → normalizar → enriquecer a OCSF → reenrutar) reutilizando el
normalizador real. Si el volumen de fuentes crece mucho (decenas de formatos
distintos, no 4), ahí sí un DSL declarativo empieza a pagar su complejidad —
`normalizer_service.process_raw_message` es el punto exacto donde ese
reemplazo entraría, ya aislado.

**OCSF como capa aditiva, no como reemplazo de `SecurityEvent`.** Ver el
docstring de `ocsf.py`: es un subconjunto de 4 clases OCSF (Process Activity,
Authentication, Network Activity, Detection Finding) que cubre exactamente lo
que los 4 collectors ya producen. **No está validado contra el JSON Schema
oficial de OCSF** (eso requeriría vendorizar los esquemas del repo
`ocsf/ocsf-schema` y correr un validador — se deja como Fase 1.1, es trabajo
acotado y de bajo riesgo, no bloquea nada de lo demás).

### Cómo probarlo

```bash
# Conversión OCSF y normalizador — sin infraestructura, corren en cualquier máquina
pytest tests/test_ocsf.py tests/test_streaming.py -q

# La pila completa (requiere Docker Desktop corriendo)
docker compose up --build
curl http://localhost:8222/varz          # NATS vivo
curl http://localhost:8000/api/v1/health # API viva
```

**Limitación declarada:** el `docker-compose.yml` se validó con
`docker compose config` (sintaxis correcta) pero **no se pudo construir ni
levantar en esta sesión** — el daemon de Docker Desktop no estaba corriendo en
esta máquina y no lo arranqué por mi cuenta (es una app de escritorio, no algo
que deba iniciar sin pedirlo). Antes de confiar en él para un despliegue real,
ejecuta `docker compose up --build` y confirma que los tres servicios quedan
`healthy`.

### Regresión

`pytest -q` completo tras esta fase: **503 passed, 1 skipped** (el *skipped*
es la prueba de integración contra NATS real, que se salta a propósito sin
servidor levantado). Cero regresiones sobre los 492 tests previos.

---

## Fase 2 — Motor de detección y reglas (plan, no implementado)

| Qué | Archivos | Decisión |
|---|---|---|
| Mantener el evaluador propio sobre el AST de pySigma | `detection/sigma_adapter.py` (sin cambios) | pySigma es un **traductor** (Sigma → SPL/KQL/Lucene), no un motor de ejecución; los backends generan *strings* para otro sistema. Evaluar ese AST directamente sobre `SecurityEvent` —lo que ya hace `sigma_adapter.py`— es más seguro que traducir a una consulta y además evitar `eval()`. Esto ya está bien resuelto; no se toca. |
| Retirar la duplicación con el motor nativo | `detection/rules_engine.py` (deprecar), reglas YAML nativas migradas a Sigma | Ya señalado en la auditoría previa (`docs/CYBERSENTINEL-ARCHITECTURE-AUDIT.md`, sección E) como deuda técnica. Antes de tocarlo: confirmar que ninguna regla nativa usa una capacidad (agregación `count()`) que Sigma+`sigma_adapter.py` todavía no soporta — si la usa, hay que añadir soporte de agregación al adaptador primero, o se pierde cobertura de detección al migrar. |
| Detection-as-code | `scripts/sigma_ci.py` (nuevo): `validate` (pySigma parsea + `SigmaCollection`), `lint` (convenciones propias: título, `level`, referencias MITRE obligatorias), `diff` (qué cambia entre dos versiones de una regla), `preview <backend>` (usa los backends reales de pySigma para mostrar cómo se vería en Splunk/Elastic — solo como previsualización, nunca para ejecutar) | **No se adoptó `droid` tal cual lo nombraste.** No pude verificar de forma independiente la procedencia/mantenimiento de un paquete con ese nombre exacto en PyPI, y añadir una dependencia de cadena de suministro no verificada a un sistema de detección es exactamente el tipo de riesgo que este proyecto evita en otras partes (ver la política de "nunca `eval()`" del propio adaptador). La alternativa: un script propio, pequeño, que hace lo mismo (validar/convertir/diff) apoyándose en pySigma —ya dependencia real—, sin instalar un wrapper de terceros sin auditar. Si `droid` resulta ser (tras que tú lo verifiques) el proyecto legítimo de FrackTech/otros mantenedores conocidos de la comunidad Sigma, se puede añadir como dependencia opcional encima de este script, no en su lugar. |
| Detección de runtime en contenedores | Nuevo collector `collectors/falco.py` (Falco emite JSON por stdout/syslog; mapear sus alertas a `SecurityEvent` con el mismo patrón que los 4 collectors existentes) + manifiesto K8s en Fase 5 | Falco necesita eBPF o un módulo de kernel Linux. **No es ejecutable ni probable en este entorno** (macOS + Docker Desktop en una VM LinuxKit sin el driver de Falco) — se documenta como objetivo de Fase 5 sobre un clúster K8s real, no como algo que esta sesión pueda validar. |

---

## Fase 3 — Inteligencia y contexto (plan, no implementado)

| Qué | Archivos | Decisión |
|---|---|---|
| MITRE ATT&CK en vivo | `correlation/mitre.py` (modificar): cargar `enterprise-attack.json` (bundle STIX 2.1 oficial) con `mitreattack-python` en el arranque, no solo para regenerar caché offline. Mantener la caché en disco (`data/attack/attack_cache.json`) como *fallback* si no hay red — la reproducibilidad científica del proyecto (ver `docs/PHASE-4.1-SCIENTIFIC-AUDIT.md`) depende de poder correr sin conexión. | Lift moderado: la dependencia ya está declarada (`attack` extra); es promoverla de "solo para regenerar caché" a "fuente de verdad con caché de respaldo". |
| CTI en vivo | `cti/enrichment.py` (extender, no reemplazar): clientes para NVD REST API 2.0, FIRST.org EPSS API y el feed JSON de CISA KEV — las tres son APIs **oficiales y públicas** (gobierno/FIRST), verificables por cualquiera, sin intermediario de terceros. Nuevo módulo `cti/live_sources.py`. | **No se adoptó "cti-mcp-server"** por la misma razón que "droid": no pude verificar su procedencia de forma independiente antes de recomendarlo como dependencia de un sistema de detección. Si ya lo conoces y confías en su origen, es un *frontend* razonable sobre las mismas fuentes — se podría montar delante de `cti/live_sources.py` en vez de en su lugar. OTX (AlienVault) sí es una integración razonable de añadir después: requiere una API key, así que se deja fuera de la ruta por defecto (no debe romper el sistema si no hay clave configurada — mismo principio que ya sigue `llm/providers.py` con Anthropic). |
| RAG con pgvector | Nuevo `rag/pgvector_store.py` implementando la misma interfaz que `rag/vector_store.py` (FAISS); `pipeline.py` elige backend por configuración. Nuevo servicio `postgres` (imagen `pgvector/pgvector:pg16`) en `docker-compose.yml`, bajo un *profile* `rag` para no forzarlo en Fase 1. | FAISS sigue siendo el default: los tests no deben depender de un Postgres levantado. pgvector aporta sobre todo cuando el corpus de documentos crece (miles de CVEs, no un puñado de `.md` de técnicas ATT&CK) y cuando hace falta que **varios procesos** compartan el mismo índice — hoy FAISS es un archivo local por proceso. |

---

## Fase 4 — Orquestación de agentes y LLM (plan, no implementado)

Ya existe la pieza de gobernanza sobre la que se apoyaría el nodo
`EthicalGovernor`: `response/models.py` define `ActionStatus`
(`requested → approved/rejected → executing → completed/failed`) y
`response/executor.py`/`response/store.py` ya implementan un flujo de
aprobación. El grafo de LangGraph **no sustituye esto, lo orquesta**.

| Nodo | Archivo | Responsabilidad | Reutiliza |
|---|---|---|---|
| `Decomposer` | `orchestration/graph.py` (nuevo) | Descompone un incidente (`IncidentResult` de `pipeline.py`) en sub-preguntas investigables | Nada nuevo que decidir aquí: lee la evidencia que ya produce `DetectionEvidence` |
| `EvidenceResearcher` | idem | Busca contexto adicional: RAG (`rag/vector_store.py`) + CTI (`cti/enrichment.py`) | Componentes existentes, sin cambios |
| `ResponsePlanner` | idem, delega en `response/actions.py::ResponsePlanner` | Propone contramedidas | **Ya existe** — el nodo LangGraph es un envoltorio fino |
| `EthicalGovernor` | idem, delega en `response/models.py::ActionStatus` + `response/executor.py` | Bloquea cualquier acción hasta que exista una decisión humana registrada | **Ya existe el modelo de aprobación** — el nodo formaliza que ninguna arista del grafo pasa de `ResponsePlanner` a "ejecutado" sin pasar por `ActionStatus.APPROVED` |

Restricción de diseño que no se negocia (y que ya es coherente con lo que el
sistema hace hoy): el nodo LLM (Claude, vía `llm/providers.py`) solo alimenta
`Decomposer`/`EvidenceResearcher` con texto explicativo — **ninguna arista del
grafo puede ir del LLM directamente a `ActionStatus.APPROVED`**. Eso ya es
cierto en el código actual (`llm/providers.py` es explícitamente de solo
lectura); el grafo solo tiene que no romperlo.

**Nueva dependencia:** `langgraph` (paquete oficial de LangChain, mismo
mantenedor que `langchain-core`, ya dependencia real del proyecto — sin el
problema de procedencia de las dos anteriores).

---

## Fase 5 — Observabilidad y despliegue (plan, no implementado)

| Qué | Archivos | Nota |
|---|---|---|
| Métricas Prometheus | Nuevo `GET /metrics/prometheus` en `api/app.py` (aditivo: `GET /api/v1/metrics` en JSON, que ya consume `panel.js`, no se toca) usando `prometheus_client` | Nueva dependencia opcional `observability = ["prometheus-client>=0.20"]` |
| Grafana + Loki | `docker-compose.yml`: perfil `observability` con `grafana`, `loki`, `promtail` | Dashboards versionados en `deploy/grafana/dashboards/*.json` |
| Kubernetes | `k8s/{api,normalizer,nats}-deployment.yaml`, `k8s/*-service.yaml`, `k8s/configmap.yaml` | Probes de liveness/readiness apuntando a `/api/v1/health` y `/api/v1/ready`, que **ya existen** y ya devuelven el código correcto (`503` cuando el worker no está listo) |
| Falco (runtime security) | `k8s/falco-daemonset.yaml` | No verificable en este entorno de desarrollo (ver Fase 2) — manifiesto documentado, no probado |

---

## Principios transversales (todas las fases)

- **Sin capacidades ofensivas.** Ninguna integración propuesta ejecuta,
  automatiza ni facilita una acción contra un tercero; todo lo que toca
  "respuesta" (`response/`) sigue siendo detección → propuesta → aprobación
  humana → ejecución, nunca detección → ejecución.
- **Human-in-the-loop obligatorio.** Ya es así en el código actual
  (`ActionStatus`, `/api/v1/incidents/{id}/triage`); el diseño de Fase 4 lo
  formaliza en el grafo, no lo introduce.
- **Trazabilidad y auditoría.** El `AuditLog` encadenado (HMAC + anclaje
  externo) ya registra decisiones humanas y cambios de identidad; cada fase
  nueva que escriba una decisión (aprobar una regla, aprobar una respuesta)
  debe escribir en el mismo registro, no en uno paralelo — el error que ya se
  corrigió una vez en `api/app.py` (dos `AuditLog` sobre el mismo archivo,
  cadenas entrelazadas) es exactamente el que hay que evitar repetir al añadir
  más escritores.
- **Cuando algo es demasiado complejo para el alcance de un prototipo, se dice
  y se ofrece la alternativa simple** — es lo que pasó con
  Substation/Tenzir → normalizador propio, Kafka → NATS, y `droid`/CTI-MCP →
  scripts y clientes propios sobre las mismas fuentes.

## Qué falta para que esto sea "producción" de verdad (honesto, no vendido)

1. Ninguna fase de streaming (Fase 1) tiene todavía un segundo consumidor real
   además del normalizador: el bus está para desacoplar, pero la API sigue
   ingiriendo por HTTP directo, no leyendo de `cybersentinel.ocsf.*`. Cerrar
   ese lazo (un `IngestWorker` que también consuma NATS) es el siguiente paso
   natural de la Fase 1, no de la 2.
2. El techo de rendimiento medido (~3.400 eventos/s, `docs/BENCHMARK.md`) es
   de un solo proceso. Nada de lo propuesto aquí lo sube por sí solo: NATS
   desacopla la ingesta, pero el Isolation Forest sigue siendo el 64-98% del
   cómputo por evento. Escalar eso requiere paralelizar `Pipeline.run_events`
   entre varios workers, que es un problema de Fase 1/2 combinado, no
   resuelto todavía.
3. Todo lo de la Fase 3 en adelante depende de decisiones que solo tú puedes
   tomar con información que yo no tengo: si vas a pagar por acceso a OTX o a
   una API de pago de EPSS/NVD con más cuota, y si `droid`/`cti-mcp-server`
   son proyectos que ya conoces y en los que confías (en cuyo caso, dime la
   URL/repositorio exacto y los reevalúo con eso en la mano en vez de la
   suposición conservadora que tomé aquí).
