# CyberSentinel — Matriz de madurez empresarial

Auditoría del repositorio completo. **Sin cambios de código**: solo inspección,
medición y documentación.

Fecha: 2026-09-15 · Commit auditado: `a0d807a` · `src/`: 8 293 líneas en 43 módulos

## Cómo leer los estados

| Estado | Significado | Criterio de asignación |
|:--:|---|---|
| **A** | Funcional de extremo a extremo | El pipeline lo ejecuta y hay una ejecución real que lo demuestra |
| **B** | Parcialmente funcional | El código existe y funciona, pero no participa en el flujo principal o le falta una pieza |
| **C** | Mock / hardcode | Simula algo que no ocurre, o el valor está fijado a mano sin calibrar |
| **D** | Desconectado | Existe, está probado, y nada en `src/` lo llama |
| **E** | No implementado | No existe código |

---

## Matriz de 30 capacidades

| # | CAPACIDAD | ESTADO | EVIDENCIA | QUÉ FALTA | PRIORIDAD |
|---|---|:--:|---|---|:--:|
| 1 | **Ingestión tiempo real** | **A** | API FastAPI + cola acotada con contrapresión y reserva + worker por lotes + **registro de escritura anticipada**: un 202 significa que el evento está en disco. Verificado con `kill -9`: 3 000 aceptados, 0 procesados, 3 000 recuperados | Receptor syslog nativo; cola compartida entre réplicas | P2 |
| 2 | **Windows / Sysmon** | **A** | `parse_sysmon` + `SecurityDatasetsLoader`; detecta T1059/T1053/T1046 sobre `sample_logs.jsonl` (17 hallazgos, 5 cadenas) | Cobertura de más EventIDs (7, 8, 10, 11, 22) | P2 |
| 3 | **Linux / auditd** | **E** | 0 ocurrencias de `auditd` en `src/` | Parser de auditd/journald y reglas asociadas | **P1** |
| 4 | **Firewall logs** | **A** | `parse_firewall`; produce las detecciones RDP/C2/exfiltración de la cadena sintética | Formatos de fabricante (ASA, Palo Alto, fortinet) | P2 |
| 5 | **IDS / Suricata** | **E** | 0 ocurrencias de suricata/zeek/eve.json | Parser de `eve.json` y correlación alerta↔flujo | **P1** |
| 6 | **Múltiples fuentes simultáneas** | **B** | 5 parsers coexisten y `Normalizer` enruta por `source`; pero el procesamiento es **un archivo por ejecución**, secuencial | Multiplexado concurrente, orden por reloj entre fuentes | **P1** |
| 7 | **Normalización** | **A** | `SecurityEvent` (ECS/OCSF); 700 001 registros UNSW-NB15 normalizados; nada se descarta en silencio (etiquetas `fuente_desconocida`, `timestamp_invalido`) | Esquema versionado y contrato de compatibilidad | P2 |
| 8 | **Motor Sigma (reglas propias)** | **A** | 7 reglas YAML con agregación temporal; falsos positivos corregidos y con pruebas de regresión | — | — |
| 9 | **Sigma público (pySigma)** | **D** | `sigma_adapter.py` (479 líneas) + 15 reglas en `config/sigma_rules/selected/`. **`from_sigma_directory()` solo lo llama `scripts/evaluate_sigma_phase1.py`**: ni el pipeline ni la CLI lo cargan | Conectarlo al pipeline y decidir la política de carga | **P0** |
| 10 | **Isolation Forest** | **A** | Sobre UNSW-NB15 real: **ROC-AUC 0.9462**, PR-AUC 0.4561, 19 874 scores distintos. Entrenado solo con benignos, umbral desde validación | Calibración y reentrenamiento programado | P2 |
| 11 | **Correlación temporal** | **B** | `TemporalCorrelator` conectado; 5 secuencias detectadas sobre Sysmon incluida la cadena completa T1110→T1059→T1053→T1048 | Las secuencias solo encadenan técnicas de host: **0 sobre telemetría de red** | P2 |
| 12 | **Predicción kill-chain (Markov)** | **D** | Entrenado y medido (p@1 **0.584** vs 0.479 de la heurística). **`sequence_model` no aparece en `pipeline.py`**: solo en `cli.py train-prediction` | Inyectarlo en el pipeline para que la predicción llegue a la evidencia | **P1** |
| 13 | **MITRE ATT&CK** | **A** | v19.2 desde STIX oficial, 222 técnicas + 475 subtécnicas en caché de 84 KB; `mitre_context` poblado desde las reglas disparadas | — | — |
| 14 | **CTI / STIX** | **A** | `StixIngestor` + `CTIEnricher`; coincidencia real sobre `203.0.113.66`, con filtrado de indicadores caducados y revocados probado | Feeds reales (MISP/OpenCTI/TAXII), no un bundle de laboratorio | **P1** |
| 15 | **RAG** | **A** | 222 documentos ATT&CK indexados, embeddings **LSA reales** (no aleatorios), recuperación anclada por técnica con procedencia citable | Embeddings neuronales; corpus de CTI propio | P2 |
| 16 | **Explicación LLM** | **B** | `llm/providers.py`: Claude real si hay credenciales, respaldo determinista declarado (`llm_status`, `fallback_used`). Protección contra inyección de prompt con pruebas | **La ruta con Claude nunca se ha ejecutado** (sin `ANTHROPIC_API_KEY` en este entorno) | P2 |
| 17 | **HITL** | **A** | `cybersentinel decide` **y el panel SOC**: el botón de veredicto escribe en el mismo `DatasetManager` con la misma `StructuredDecision` y la evidencia sellada. `UNCERTAIN` no cierra el incidente y el panel lo dice | Acuerdo entre varios analistas sobre el mismo incidente | P2 |
| 18 | **Gestión de incidentes** | **B** | `api/incidents.py`: entidad persistente en SQLite con evidencia completa, ciclo de vida validado (`new→triaged→in_progress→closed`, cerrar exige resolución, reabrir vuelve a triaje), propietario y cronología de solo-añadir. 31 pruebas | **Un incidente por evento, no por campaña**: una cadena de 8 pasos son 8 incidentes. Sin SLA ni notificaciones | **P1** |
| 19 | **Respuesta controlada** | **B** | `ResponsePlanner` + `GovernancePolicy` conectados; clasifica en permitida / requiere aprobación / prohibida | **Todo es dry-run**: no hay ejecutores reales (EDR, firewall) ni flujo de aprobación | P2 |
| 20 | **Autenticación de API** | **A** | `api/security/`: clave de API para sensores (SHA-256, **19 062 verif./s** medidas) y JWT HS256 para personas (scrypt n=2¹⁵). 41 pruebas nombran el ataque que frenan: `alg:none`, firma manipulada, token de otro secreto, clave revocada, enumeración de usuarios, fuerza bruta | MFA; rotación de contraseñas | P2 |
| 21 | **Autorización RBAC** | **A** | 5 roles (sensor/analyst/responder/auditor/admin) sobre 7 permisos. El código pregunta por permiso, nunca por rol. Probado: el sensor no lee incidentes, el analista no ingiere, el auditor no escribe, el admin no inyecta telemetría | Permisos por origen de telemetría (multi-tenant) | P2 |
| 22 | **TLS** | **A** | `security/transport.py`: el texto en claro solo se acepta desde bucle local; desde fuera exige HTTPS o un proxy declarado, y si no, **403 antes de autenticar**. `cybersentinel serve` se niega a abrir un puerto remoto sin certificado. HSTS solo sobre conexión ya segura. 9 pruebas | mTLS y fijación de certificado; rotación automática | P2 |
| 23 | **Gestión de secretos** | **B** | `CYBERSENTINEL_AUDIT_KEY` y `ANTHROPIC_API_KEY` por variable de entorno. 0 ocurrencias de vault/keyring | Almacén de secretos, rotación, no-exposición en logs | **P1** |
| 24 | **Rate limiting** | **A** | Cubo de fichas por cliente en dos ejes (peticiones y eventos), política por rol, cubos acotados por LRU. Verificado contra uvicorn real: 110×202 / 50×429 en una ráfaga de 160. **2,4 µs** por comprobación | Estado compartido entre réplicas (hoy es por proceso) | **P1** |
| 25 | **Audit log** | **A** | Cadena HMAC-SHA256 + ancla externa. Detecta edición, **truncado** y reescritura completa — con prueba por cada ataque | Anclaje en medio independiente (WORM / sellado de tiempo) | **P1** |
| 26 | **Métricas / observabilidad** | **B** | `TraceContext`: `run_id`, `event_ref`, estado y latencia por etapa (OK/NO_DATA/DISABLED/UNAVAILABLE/ERROR) | **No exporta**: 0 ocurrencias de prometheus/opentelemetry. Sin dashboards ni alertas operativas | **P1** |
| 27 | **Escalabilidad** | **B** | La ruta de servicio ya es acotada: cola con tope, lotes, SQLite en modo WAL y evidencia completa solo para incidentes. Varias réplicas comparten eventos e incidentes. **La ruta de CLI sigue igual**: `analyze --json` sobre 20 000 eventos → 129 MB de JSON y 4,2 GB de RSS | Particionado y cola compartida; arreglar `analyze --json` | **P1** |
| 28 | **Latencia medida** | **A** | Por etapa en `TraceContext`; benchmark con p95. Throughput medido: **23 270 flujos/s** en puntuación, 528 ev/s en pipeline completo | Objetivos de servicio (SLO) | P2 |
| 29 | **Falsos positivos medidos** | **A** | **FPR 0.0583** sobre UNSW-NB15 en el punto de operación calibrado; tráfico benigno sintético → 0 incidentes críticos (prueba de regresión) | Medición continua en producción | P2 |
| 30 | **Alta disponibilidad** | **B** | Recuperación sin pérdida tras `kill -9`; retirada ordenada (`POST /drain` → `/ready` 503 → SIGTERM); identidades, revocación de tokens, eventos e incidentes compartidos entre procesos; cadena de auditoría íntegra con varios escritores (`flock`). 25 pruebas | **Sin conmutación automática ni cola compartida**: cada réplica tiene su propio registro y su propio ingreso. Un solo host | **P1** |
| 31 | **Persistencia** | **B** | SQLite en **modo WAL** para eventos, incidentes y credenciales —varios procesos a la vez—; JSONL para el registro anticipado, la auditoría (cadena HMAC con `flock`) y las decisiones HITL | Decisiones aún en JSONL. SQLite es de **un host**: varias máquinas exigen una base en red (PostgreSQL) | **P1** |
| 32 | **Integración SIEM / EDR** | **E** | 0 ocurrencias de splunk/elastic/qradar/sentinel | Salida CEF/LEEF/ECS, webhooks, API de ingesta | **P1** |

> La numeración llega a 32 porque «persistencia» e «integración SIEM/EDR» se
> desglosaron de la lista original para poder puntuarlas por separado.

### Recuento

| Estado | Nº | Capacidades |
|:--:|--:|---|
| **A** — funcional | **17** | Sysmon, firewall, normalización, Sigma propio, Isolation Forest, ATT&CK, CTI, RAG, HITL, audit log, latencia, falsos positivos, autenticación, RBAC, rate limiting, TLS, **ingestión en tiempo real** |
| **B** — parcial | **11** | Múltiples fuentes, correlación temporal, LLM, respuesta, secretos, observabilidad, persistencia, gestión de incidentes, **escalabilidad**, **alta disponibilidad**, (Sigma público si se cuenta como parcial) |
| **C** — mock/hardcode | **2** | `hybrid_score`, umbral `ready_for_training` |
| **D** — desconectado | **3** | Sigma público (pySigma), Markov/kill-chain, `explanation/explainer.py` |
| **E** — no implementado | **3** | auditd, Suricata, SIEM/EDR |

> Actualizado tras `docs/SECURITY.md`, `docs/SOC-PANEL.md` y
> `docs/HIGH-AVAILABILITY.md`. **No queda ningún P0.** Lo que sigue en **E** son
> tres trabajos de cobertura, aislados y paralelizables: dos parsers y un
> exportador. Lo que sigue en **B** es de escala: un solo host, SQLite y una
> cola por réplica. La frontera entre «esto aguanta un fallo» y «esto aguanta
> que se caiga la máquina» está exactamente ahí, y está dicha.

---

## Hallazgos de la inspección de código

### Lo que está sano

- **0 `except:` desnudos** en `src/`.
- **0 TODOs bloqueantes**. Los dos resultados de la búsqueda son la palabra
  «TODOS» dentro de un comentario y un `NotImplementedError` legítimo en una
  clase base abstracta.
- **0 mocks en producción**. Las cuatro menciones a *fake/mock* en `src/` son
  docstrings que documentan **por qué se eliminaron**
  (`llm/providers.py`, `rag/embeddings.py`), más dos comentarios con la palabra
  «dummy» que no corresponden a ningún doble.
- Hay una prueba que **falla si `FakeEmbeddings` o `FakeListChatModel`
  reaparecen en `pipeline.py`**.

### Los hardcodes que quedan (estado C)

**1. `hybrid_score` — `detection/hybrid.py`**

```python
if self.rule_matches:          base += 50.0
ml_boost = max(0, (anomaly_score - 0.5) * 40.0)
if self.temporal_context:      base += 30.0
# CTI: +50 / +30 / +15 / +5 según etiqueta
```

Siete constantes ajustadas a mano, sin calibrar contra datos etiquetados. Tiene
una consecuencia medida y grave: **el ML aporta como máximo 20 de los 50 puntos
necesarios para alertar**, así que sobre telemetría donde ninguna regla aplica
—como UNSW-NB15— el sistema no emite un solo hallazgo aunque el modelo
discrimine con ROC-AUC 0.9462. El detector funciona; la capa de alertado lo
silencia.

**2. `ready_for_training` — `governance/dataset_manager.py:178`**

```python
"ready_for_training": counts["TRUE_POSITIVE"] > 1000 and counts["FALSE_POSITIVE"] > 1000  # Dummy threshold
```

Umbral arbitrario, marcado como provisional por su propio autor.

### Los desconectados (estado D) — lo más caro de esta auditoría

Tres componentes **funcionan, están probados y no participan en el flujo real**:

| Componente | Tamaño | Dónde se usa | Dónde NO se usa |
|---|--:|---|---|
| `detection/sigma_adapter.py` + 15 reglas Sigma | 479 líneas + 599 | `scripts/evaluate_sigma_phase1.py` | **pipeline, CLI** |
| `correlation/sequence_model.py` (Markov) | 313 líneas | `cli.py train-prediction` | **pipeline** |
| `explanation/explainer.py` | 270 líneas | nada en `src/` | todo |

Son ~1 660 líneas de código probado que un cliente **no recibiría**. El caso de
`sequence_model` es el más llamativo: la predicción de kill-chain es el
diferenciador declarado del proyecto, está entrenada y medida (p@1 0.584 frente
a 0.479 de la línea base), y **el agente nunca la ejecuta**.

---

## Arquitectura objetivo

La arquitectura actual **no se destruye**: todo el núcleo se conserva y pasa a
ser el motor de un producto. Lo que se añade son las capas que hoy faltan.

### Hoy

```
  archivo JSONL/CSV
        │
        ▼
  ┌──────────────────────────────────────────────────┐
  │ CLI (proceso único, en memoria, un archivo/vez)  │
  │   Normalizer → RulesEngine → IsolationForest     │
  │   → TemporalCorrelator → DetectionEvidence       │
  │   → ATT&CK → CTI → RAG → LLM → Governance        │
  │   → AuditLog(JSONL) → DatasetManager(JSONL)      │
  └──────────────────────────────────────────────────┘
        │
        ▼
  stdout + JSON en disco
```

### Objetivo

```
┌── CAPA 1 · RECOLECCIÓN ────────────────────────────────────────────┐
│  Sysmon/WEF   auditd   Suricata   firewall   netflow   nube        │
│         └────────┴─────────┴──────────┴─────────┴──── agentes /    │
│                                                        syslog / API│
└────────────────────────────┬───────────────────────────────────────┘
                             ▼
┌── CAPA 2 · TRANSPORTE ─────────────────────────────────────────────┐
│  Cola durable (Kafka/Redis Streams) · backpressure · reintentos    │
│  » NUEVO. Desacopla recolección de análisis; permite escalar       │
└────────────────────────────┬───────────────────────────────────────┘
                             ▼
┌── CAPA 3 · NÚCLEO DE ANÁLISIS  (el CyberSentinel actual) ──────────┐
│  Normalizer → SecurityEvent                                        │
│  Sigma propio + Sigma público (pySigma)   ← conectar #9            │
│  Isolation Forest                                                  │
│  TemporalCorrelator + Markov kill-chain   ← conectar #12           │
│  DetectionEvidence (run_id, event_ref, estado por etapa)           │
│  ATT&CK · CTI · RAG · LLM                                          │
│  » SE CONSERVA TAL CUAL. Pasa de proceso a *worker* replicable     │
└────────────────────────────┬───────────────────────────────────────┘
                             ▼
┌── CAPA 4 · ESTADO ─────────────────────────────────────────────────┐
│  PostgreSQL: incidentes, evidencia, decisiones, usuarios           │
│  Object store: telemetría cruda · Vector DB: corpus RAG            │
│  AuditLog con ancla en medio independiente (WORM)                  │
│  » NUEVO. Hoy todo vive en memoria y JSONL                         │
└────────────────────────────┬───────────────────────────────────────┘
                             ▼
┌── CAPA 5 · SERVICIO ───────────────────────────────────────────────┐
│  API REST/gRPC sobre TLS · OIDC/JWT · RBAC · rate limiting         │
│  Gestión de incidentes: estados, propietario, SLA                  │
│  » NUEVO. Es la capa que convierte el motor en producto            │
└────────────────────────────┬───────────────────────────────────────┘
                             ▼
┌── CAPA 6 · CONSUMO ────────────────────────────────────────────────┐
│  Consola del analista (HITL)   SIEM (CEF/ECS)   EDR/SOAR           │
│  Prometheus/OTel → dashboards y alertas operativas                 │
└────────────────────────────────────────────────────────────────────┘

        Gobernanza ética y auditoría: transversales a las capas 3–6.
        Ninguna acción sensible se ejecuta sin aprobación humana.
```

---

## Orden de implementación

Ordenado por **dependencias reales**, no por atractivo. Cada punto explica qué
desbloquea.

### Fase A — Hacer valer lo que ya está pagado (semanas 1–2)

| # | Trabajo | Por qué primero |
|---|---|---|
| A1 | **Conectar pySigma al pipeline** (#9) | 479 líneas y 15 reglas ya probadas que el producto no entrega. Es la mejor relación valor/esfuerzo del repositorio: cobertura ATT&CK sin escribir detecciones |
| A2 | **Conectar Markov al pipeline** (#12) | El diferenciador declarado del proyecto no se ejecuta. Ya está medido |
| A3 | **Calibrar `hybrid_score`** | Sin esto, el ML no puede alertar por sí solo. Bloquea cualquier despliegue sobre telemetría de red. Requiere A1 para tener detecciones con las que calibrar |
| A4 | **Eliminar `explanation/explainer.py`** o fusionarlo | 270 líneas muertas que confunden a quien lea el código |

*No requiere infraestructura nueva. Convierte trabajo hecho en producto.*

### Fase B — Cimientos sin los que nada más se sostiene (semanas 3–8)

| # | Trabajo | Por qué aquí |
|---|---|---|
| B1 | **Persistencia en PostgreSQL** (#31) | Prerrequisito duro de incidentes, RBAC, HA y multiusuario. Todo lo demás depende de esto |
| B2 | ~~**Gestión de incidentes**~~ → **hecho a medias** (#18) | Ya hay entidad persistente, ciclo de vida y panel. Falta agrupar una campaña en un solo incidente: hoy una cadena de 8 pasos son 8 incidentes |
| B3 | ~~**API + TLS + OIDC/JWT + RBAC**~~ → **hecho** (#20, #21, #22, #24) | Es la frontera del producto. Los usuarios se persistieron en SQLite en vez de esperar a PostgreSQL: la migración es un cambio de conexión, no de diseño. No es OIDC: sustituir `security/tokens.py` no toca ni los roles ni un solo manejador |
| B4 | **Exportar métricas (OTel/Prometheus)** (#26) | La instrumentación ya existe en `TraceContext`; falta el exportador. Barato y necesario para operar |

*Aquí es donde el laboratorio se convierte en servicio.*

### Fase C — Escala y tiempo real (semanas 9–16)

| # | Trabajo | Por qué aquí |
|---|---|---|
| C1 | ~~**Cola durable + workers**~~ → **hecha en disco**, no en un broker (#1, #27) | El registro anticipado da durabilidad y recuperación sin añadir Kafka ni Redis. Lo que no da es una cola **compartida**: cada réplica tiene la suya |
| C2 | ~~**Ingestión en tiempo real**~~ → **hecha** (#1, #6) | — |
| C3 | ~~**Alta disponibilidad**~~ → **a medias** (#30) | Hay recuperación, retirada ordenada y estado compartido entre procesos. Falta conmutación automática y salir de un solo host |

### Fase D — Amplitud de cobertura (en paralelo desde la Fase B)

| # | Trabajo | Por qué puede paralelizarse |
|---|---|---|
| D1 | **Parser auditd** (#3) | Aislado: un parser más, sin tocar el núcleo |
| D2 | **Parser Suricata `eve.json`** (#5) | Ídem. Aporta la telemetría de red que hoy no tiene reglas |
| D3 | **Feeds CTI reales (MISP/TAXII)** (#14) | El enriquecedor ya funciona; solo cambia la fuente |
| D4 | **Integración SIEM (CEF/ECS)** (#32) | Requiere la API de B3 |

### Lo que **no** haría todavía

- **Ejecutores de respuesta reales** (#19). Aislar un host o bloquear una IP
  automáticamente exige una madurez operativa que el producto aún no tiene.
  El *dry-run* con aprobación humana es la postura correcta hasta que existan
  B2 y B3.
- **Embeddings neuronales** (#15). El LSA local funciona y es reproducible;
  cambiarlo añade dependencia de red sin resolver ningún bloqueo.
- ~~**Rate limiting** (#24)~~. Se hizo junto con B3: una vez que hay credenciales,
  limitar por cliente es la mitad del trabajo, y sin ello la autenticación deja
  abierta la fuerza bruta contra las contraseñas.

---

## Resumen ejecutivo

### Qué funciona hoy, con evidencia

CyberSentinel es un **motor de detección y análisis sólido**. Doce capacidades
son funcionales de extremo a extremo y están demostradas con ejecuciones reales:
normalización multi-fuente (700 001 registros de UNSW-NB15 procesados), detección
por reglas con agregación temporal, Isolation Forest con **ROC-AUC 0.9462** sobre
datos públicos reales, MITRE ATT&CK v19.2 oficial, enriquecimiento CTI con
control de ciclo de vida, RAG con procedencia citable, human-in-the-loop, y una
cadena de auditoría que detecta edición, truncado y reescritura completa.

La calidad del código es buena: cero excepciones silenciadas, cero TODOs
bloqueantes y cero mocks en producción, con una prueba que impide que reaparezcan.

### Qué es crítico para una empresa

**Lo que falta no es detección: es producto.** Diez capacidades están sin
implementar, y son justo las que separan un motor de laboratorio de un sistema
que una organización puede desplegar:

1. **No hay servicio.** Sin API, autenticación, TLS ni RBAC, no hay forma de que
   varias personas lo usen ni de integrarlo con nada.
2. **No hay estado.** Sin base de datos no hay incidentes persistentes, ni
   asignación, ni historial, ni alta disponibilidad.
3. **No escala.** Proceso único en memoria: 20 000 eventos consumen 4,2 GB de RSS
   y producen 129 MB de JSON.
4. **No ingiere en tiempo real.** Hoy es un archivo por ejecución.

Y un problema que no es de infraestructura sino de diseño: **la capa de alertado
anula al detector**. El `hybrid_score` da como máximo 20 de los 50 puntos
necesarios a la señal del modelo, de modo que sobre telemetría sin reglas
aplicables el sistema no alerta nunca, por buena que sea la detección.

### La respuesta a la pregunta

> *¿Qué tiene CyberSentinel hoy que funciona realmente y qué debemos construir
> para que una empresa lo use?*

**Tiene** un núcleo de análisis que funciona y está medido sobre datos reales.
**Necesita** las capas que lo rodean —servicio, estado, escala e ingestión— y,
antes que nada, **cobrar el trabajo que ya está hecho**: pySigma y el modelo de
Markov están probados, medidos y desconectados. Son ~800 líneas de valor a las
que hoy no llega ningún cliente, y conectarlas no requiere infraestructura nueva.

Por eso la Fase A va primero.
