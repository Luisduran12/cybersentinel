# AUDIT_REPORT — Auditoría integral de seguridad, calidad y rendimiento de CyberSentinel

> **Estado de remediación (rama `security/audit-remediation`)**: este informe es la foto de solo lectura de `main@ad622c2`. SEC-01 y SEC-02 están corregidos en el commit `802120a` (tests en `tests/test_security_remediation_auth.py`). El resto de hallazgos sigue pendiente.

- **Repositorio**: https://github.com/Luisduran12/cybersentinel, rama `main`, commit `ad622c2`, árbol limpio (no se modificó nada).
- **Fecha**: 2026-10-22. **Entorno**: Ubuntu, Python 3.10.12, x86_64, 2 CPU, venv aislado (`pip check`: sin conflictos).
- **Modo**: solo lectura. Las pruebas usan datos sintéticos y se ejecutan en local. Los scripts de reproducción están en `poc/`.
- **Detalle de seguridad**: ver `SECURITY_FINDINGS.md`.

## 1. Resumen ejecutivo

CyberSentinel es un proyecto Python grande (unos 92 módulos analizados por mypy, ~110 ficheros en `src/`, 50+ ficheros de tests) con una base de seguridad cuidada: JWT HS256 validado como es debido, scrypt, API keys guardadas como hash, RBAC, TLS obligatorio, CSP, SQL parametrizado y respuesta en dry-run con aprobación humana. La suite existente **pasa: 676 passed, 2 skipped, en 57 s**.

Aun así, he confirmado con PoC **dos fallos de severidad ALTA en el control de fuerza bruta**, que juntos lo anulan:
1. **SEC-01**: la IP del cliente se toma del primer valor de `X-Forwarded-For`, que controla el cliente. Al rotarlo, el límite anónimo deja de aplicarse.
2. **SEC-02**: el contador de intentos fallidos tiene una condición de carrera. Con 20 intentos concurrentes se evaluaron las 20 contraseñas y la cuenta no se bloqueó (`failed_attempts=2`).

Otros hallazgos:
- **Integridad del triage (SEC-03)**: la decisión se guarda aunque la transición de estado falle con 422.
- **Bloqueo del event loop con scrypt (SEC-05)**: medido, efecto moderado.
- **Docker/NATS expuestos (SEC-07)**.
- **Rendimiento**: el pipeline completo procesa solo **~120-240 eventos/s** cuando el motor de reglas solo da **~3 000 eventos/s**. El cuello de botella es la auditoría (relee el fichero entero en cada escritura, O(n²)) y el almacén de respuestas (abre una conexión SQLite y hace commit en cada operación).
- **Detección**: tiene falsos positivos y falsos negativos comprobados (sección 5).

No he encontrado secretos reales, inyección SQL, XSS, deserialización insegura alcanzable ni ejecución dinámica.

## 2. Arquitectura y mapa de módulos

| Capa | Módulos (`src/cybersentinel/`) | Notas |
|------|-------------------------------|-------|
| Entrada | `api/app.py` (FastAPI, `create_app`), `cli.py` (`cybersentinel`), `streaming/normalizer_service.py` (NATS) | Uvicorn en `0.0.0.0:8000` |
| Frontera de seguridad | `api/security/{guard,tokens,identity,roles,ratelimit,transport}.py`, `governance/audit.py` | authenticate → rate limit → authorize; auditoría encadenada con hash/HMAC |
| Ingesta | `api/models.py` (lotes de hasta 10 000), `api/wal.py` (WAL con fsync configurable), `ingestion/normalizer.py`, `collectors/*` (sysmon JSON/XML, auth, firewall…) | `IngestService` + worker en segundo plano |
| Detección | `detection/rules_engine.py` (7 reglas YAML propias, con y sin estado), `detection/sigma_loader.py` + `sigma_adapter.py` (38 reglas Sigma vía AST de pySigma, sin `eval`), `detection/anomaly.py` (IsolationForest), temporal/behavior/kill chain | |
| Correlación/CTI | `cti/*` (STIX, AbuseIPDB, OTX, CISA KEV; los feeds en vivo están desactivados por defecto), MITRE mapping | |
| Explicación | `rag/*` (FAISS/LangChain), `llm/*` (Anthropic opcional) | Desactivables |
| Respuesta | `response/{executor,actions,store,integrations,wazuh_client}.py` | Dry-run por defecto; nivel 2 con aprobación humana y sin ejecución real |
| Persistencia | SQLite (eventos, incidentes, identidades, respuestas), JSONL (auditoría, feedback) | |
| Panel | `api/panel/` (HTML/JS estático en `/soc/`) | `textContent`, CSP |

Flujo principal: `POST /api/v1/events` → WAL → cola → `Pipeline.run_events` (normalizar → reglas/Sigma → ML → CTI → correlación → incidentes → acciones de respuesta → auditoría) → `GET /api/v1/incidents` / triage desde el panel.

## 3. Línea base de calidad (sin cambios)

| Comprobación | Comando | Resultado |
|---|---|---|
| Tests | `python -m pytest -q -p no:cacheprovider --durations=15` | **676 passed, 2 skipped, 3 warnings, 57,0 s** |
| Sintaxis | `python -m compileall -q src scripts` | OK |
| Lint | `ruff check .` | 577 avisos (451 se arreglan con `--fix`): `PLW1510`, `RUF012`, `SIM115`, `F811`, `S110`… |
| Tipos | `mypy src/cybersentinel --ignore-missing-imports` | 77 errores en 26 de 92 ficheros |
| SAST | `bandit -r src` | 0 high / 4 medium / 11 low (revisados en SECURITY_FINDINGS) |
| SAST | `semgrep p/python p/security-audit` | 2 hallazgos (defused-xml: real, baja; logger-credential: falso positivo) |
| Dependencias | `pip-audit` (entorno instalado) | diskcache (1 aviso, sin fix), pillow (24 avisos, fix 13.0.0) |
| Secretos | `detect-secrets scan` | 18 ficheros con coincidencias, todas falsos positivos |
| CI / pre-commit | — | No existe `.github/` ni `.pre-commit-config.yaml` |

Avisos durante los tests: `StarletteDeprecationWarning` por `HTTP_422_UNPROCESSABLE_ENTITY` (está deprecado; usar `HTTP_422_UNPROCESSABLE_CONTENT`).

## 4. Seguridad (resumen; detalle en SECURITY_FINDINGS.md)

| ID | Sev. | Estado | Ubicación | Esfuerzo | Prioridad |
|----|------|--------|-----------|----------|-----------|
| SEC-01 XFF leído por la izquierda | ALTA | Confirmado | `guard.py:127-130`, `transport.py` | Bajo | P1 |
| SEC-02 Carrera en el bloqueo de cuenta | ALTA | Confirmado | `identity.py:243-300` | Bajo | P1 |
| SEC-03 Triage persiste antes de validar | MEDIA | Confirmado | `app.py:726-741` | Bajo | P2 |
| SEC-04 `_failures` sin límite | MEDIA | Código | `guard.py:88,111` | Bajo | P2 |
| SEC-05 scrypt/SQLite síncronos en `async def` | MEDIA | Medido | `app.py:371` y otros manejadores | Bajo | P2 |
| SEC-07 NATS expuesto / contenedor root | MEDIA | Código | `docker-compose.yml`, `Dockerfile` | Bajo | P2 |
| SEC-06 Enumeración del estado de cuenta | BAJA | Código | `identity.py:261-270` | Bajo | P3 |
| SEC-08 XML sin defusedxml | BAJA | Código | `collectors/sysmon.py:86` | Bajo | P3 |
| SEC-09 chmod de la clave después de crearla | BAJA | Código | `cli.py:933-940` | Bajo | P4 |
| BUG-01 rol por defecto `"sensor"` inválido | BAJA | Confirmado | `api/models.py:126` | Trivial | P3 |

Controles revisados sin hallazgos: verificación JWT, almacenamiento de contraseñas y API keys, revocación, matriz RBAC (un rol desconocido no recibe permisos), política TLS/HSTS, cabeceras de seguridad, manejador global de errores (respuesta genérica), parametrización SQL de incidentes, límites de tamaño de Pydantic, panel (XSS), executor de respuesta (no ejecuta comandos), CLI `subprocess` sin `shell=True`.

## 5. Detección Sigma / MITRE: verificación empírica

Script: `poc/detect_verify.py`. Se cargan 7 reglas propias (`config/rules`) y 38 Sigma (`config/sigma_rules/selected`). Los eventos sintéticos pasan por el `Normalizer` real.

**Detección verificada** (positivo sintético → regla → técnica): certutil `-urlcache` (T1105), PowerShell `-enc`/`-e`/`-EncodedCommand` (T1059.001 + RULE-0002), `vssadmin delete shadows` y `wmic shadowcopy delete` (T1490), `wevtutil cl` (T1070.001), volcado de lsass con comsvcs/procdump (T1003.001), `schtasks /create` (T1053.005 + RULE-0003), `mshta http` (T1218.005), `regsvr32 scrobj` (T1218.010), `net group "Domain Admins"` (T1069), `bitsadmin /transfer` (T1197), `whoami.exe` por `Image` (T1033). Mayúsculas detectadas (comparación sin distinguir mayúsculas). Fuerza bruta agregada RULE-0001: 6 fallos en 3 min → alerta; 6 fallos espaciados 2 min (fuera de la ventana de 5) → no alerta (correcto).

**Falsos negativos confirmados**:
- `certutil.exe /urlcache /split /f …`: Windows acepta `/` como prefijo de opción y la regla solo busca `-urlcache`.
- `c^ertutil -urlcache`: ofuscación con caret de cmd.
- `pwsh.exe -ec …`: la regex solo contempla `powershell(\.exe)?` y no cubre `pwsh` ni `-ec`.

**Falso positivo confirmado**: `powershell.exe -NoProfile -Command Get-Process` dispara la regla Sigma `3d6d4b49` ("encoded command", nivel high, T1059.001) y RULE-0002. La causa es que ambas regex incluyen `-nop|-noprofile`, una opción muy habitual en scripts legítimos. Las dos reglas son duplicados funcionales (la misma regex en `config/rules/encoded_powershell.yaml` y en `cs-ps-encoded-cmd.yml`), así que un mismo evento produce doble alerta.

**Reglas sin estado que generan ruido**: `cs-auth-failure` (low) y `cs-auth-failure-external` (medium) alertan por **cada** fallo de autenticación, aunque los fallos estén espaciados. Es así por diseño (Sigma sin correlación), pero conviene tenerlo en cuenta en el volumen de alertas.

**Casos límite**: `CommandLine` vacío, 100 000 caracteres, Unicode/RLO/NUL, registros sin `timestamp` o con un `timestamp` inválido: sin excepciones.

**Cobertura**: lo anterior distingue entre reglas que *cargan* (45/45), reglas *ejecutadas con un positivo sintético* (las 14 técnicas listadas) y cobertura ATT&CK declarada en los metadatos. No he medido la precisión ni el recall sobre datasets públicos (pendiente).

## 6. Rendimiento (medido, no estimado)

Entorno: Python 3.10.12, 2 vCPU, sin RAG, sin LLM y sin CTI en vivo, semillas fijas.

| Prueba | Comando | Resultado |
|---|---|---|
| Normalizador | `poc/bench_engine.py` | 29 000-34 000 eventos/s (1k / 10k / 50k) |
| Motor de reglas (45 reglas) `evaluate()` | idem | 3 125 / 3 014 / 2 867 eventos/s para 1k / 10k / 50k (lineal); `evaluate_event` media ~170 µs, p95 213-234 µs; pico de memoria 7,5 MiB con 50k |
| `Pipeline.run_events` completo | `poc/bench_pipeline.py` | 500 ev → 4,06 s (123 ev/s); 2 000 → 8,45 s (237 ev/s); 5 000 → 32,5 s (154 ev/s) |
| Perfil cProfile, 1 500 eventos (9,4 s) | inline | `_dispatch_response_actions` 6,3 s (67 %); `AuditLog.record` 2,5 s; `ResponseStore.update` 2,95 s; reglas solo 1,06 s; `sqlite3.close` 1,8 s y `commit` 1,3 s |
| `AuditLog.record` según tamaño | inline | 0,33 ms/entrada con 1k entradas previas → 2,40 ms con 10k → **9,89 ms con 40k** (crece de forma lineal con el tamaño del log) |

Hallazgos:
- **PERF-01 (ALTA, rendimiento)**: `governance/audit.py:185-213`. `_sincronizar()` llama a `_lineas_en_disco()`, que lee y cuenta **todo** el fichero de auditoría en cada `record()`. El coste total es O(n²) y el log no se rota, así que la API se degrada con el tiempo de servicio. Corrección: guardar el tamaño/offset del fichero (`os.stat().st_size` + `seek`) y releer solo si cambia, o usar un único escritor.
- **PERF-02 (MEDIA)**: `response/store.py:70-80`. Cada operación abre una conexión SQLite, aplica tres `PRAGMA`, hace commit y cierra. Además, en cada incidente el executor audita dos veces y actualiza tres veces. Corrección: reutilizar la conexión por hilo y agrupar las acciones del lote en una transacción.
- **PERF-03 (BAJA)**: `sigma_adapter.py` y `rules_engine.py` construyen el patrón y llaman a `re.fullmatch/re.search` por evento y por regla. La caché interna de `re` (512 entradas) lo amortigua y el motor no es el cuello de botella; conviene precompilar al cargar.
- **PERF-04 (MEDIA)**: `async def` con trabajo síncrono (SEC-05) en `ingest_events`, `incidents` y `emitir_token`.

## 7. Calidad y arquitectura

- `pipeline.py` concentra la orquestación en `Pipeline.__init__` (más de 40 parámetros) y en `run_events` (~375 líneas, 503-878). Hay mucho acoplamiento y es difícil de probar por partes.
- `api/app.py` define todas las rutas dentro de `create_app` como closures (~800 líneas), lo que complica reutilizar y probar unidades.
- Reglas duplicadas (YAML propio y Sigma con la misma regex), que provocan doble alerta.
- 577 avisos de ruff y 77 errores de mypy. No hay CI que los vigile.
- No hay lockfile y los rangos de versiones están abiertos, así que las instalaciones no son reproducibles (se observó un conflicto entre fastapi y opentelemetry).
- Documentación extensa y honesta (`AUDIT-BASELINE.md` ya distingue entre "implementado" y "validado"). Este informe no la sustituye ni la sobrescribe.
- Los límites que declara el propio código (rate limit por proceso, auditoría multiproceso) están documentados y coinciden con lo observado.

## 8. Plan de corrección priorizado (propuesto, **no aplicado**)

| Prioridad | Cambio mínimo | Test de regresión |
|---|---|---|
| P1 | SEC-01: XFF por la derecha con un número de proxies de confianza (también X-Forwarded-Proto) | XFF rotado → 429 tras el burst |
| P1 | SEC-02: incremento atómico de `failed_attempts` y relectura del bloqueo | 20 hilos → cuenta bloqueada, `failed_attempts == 20` |
| P2 | PERF-01: sincronización de la auditoría por tamaño/offset | coste de `record` constante con 1k vs 40k; la cadena sigue verificando, también con dos instancias |
| P2 | SEC-03: validar la transición antes de persistir la decisión | triage inválido → 422 sin entrada `decision` ni feedback |
| P2 | SEC-04: `_failures` acotado (LRU) | 100k IPs → tamaño ≤ límite |
| P2 | SEC-05: `run_in_threadpool` para scrypt/SQLite | latencia de `/health` bajo carga de login |
| P2 | SEC-07: puertos NATS en loopback, usuario no root, multi-stage | revisión de `docker compose config` |
| P3 | BUG-01 (`role` sin default inválido), SEC-06 (mensaje genérico), SEC-08 (`defusedxml`) | tests unitarios |
| P3 | Detección: `pwsh` y `-ec`, `/urlcache`, quitar `-nop/-noprofile` de la regla "encoded", eliminar el duplicado | casos de `detect_verify.py` como tests |
| P4 | PERF-02, lockfile, CI con pytest+ruff+pip-audit, pillow ≥ 13 en el extra `viz` | — |

Cada cambio iría en la rama `security/audit-remediation`, con la suite completa antes y después y un PR sin merge.

## 9. Limitaciones, riesgos residuales y comprobaciones pendientes

- No he revisado en profundidad los módulos CTI con red (`cti/abuseipdb.py`, `otx.py`, `feeds.py`) en busca de SSRF. Las URLs observadas son constantes, pero no he trazado todas las rutas. Los módulos LLM/RAG se ejecutan desactivados en las pruebas.
- No he medido la precisión ni el recall con datasets públicos (Mordor/OTRF, EVTX-ATTACK-SAMPLES). Solo hay pruebas dirigidas con datos sintéticos.
- No hay benchmarks de la API HTTP bajo carga sostenida ni con varias réplicas. Las cifras son de una sola máquina de 2 vCPU.
- `pip-audit` se ejecutó sobre el entorno instalado, que incluye los extras `dev`. La imagen Docker real no se ha construido ni escaneado (p. ej. con Trivy).
- Despliegues multiproceso: el rate limit y la sincronización de la auditoría son por proceso (el propio código lo documenta).
- Los avisos de ruff y mypy no se han clasificado uno a uno.
