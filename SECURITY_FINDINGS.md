# SECURITY_FINDINGS — CyberSentinel

> **Estado de remediación (rama `security/audit-remediation`)**: este informe es la foto de solo lectura de `main@ad622c2`. SEC-01 y SEC-02 están corregidos en el commit `802120a` (tests en `tests/test_security_remediation_auth.py`). El resto de hallazgos sigue pendiente.

Auditoría de solo lectura sobre `main@ad622c2` (Luisduran12/cybersentinel), 2026-10-22.
Todas las pruebas se ejecutaron en local con datos sintéticos; ninguna contra terceros.
Los scripts de reproducción se entregan junto a este informe (`poc/`).

Leyenda de estado: **CONFIRMADO** (reproducido con PoC), **VERIFICADO EN CÓDIGO** (lectura de código sin PoC dinámico), **PROBABLE**, **TEÓRICO**, **FALSO POSITIVO**.

## Tabla resumen

| ID | Severidad | Estado | Componente | Título |
|----|-----------|--------|------------|--------|
| SEC-01 | ALTA | CONFIRMADO | `api/security/guard.py:127-130` | `X-Forwarded-For` se lee por la izquierda: el cliente controla su IP y evita el límite anónimo (fuerza bruta en `/auth/token`) |
| SEC-02 | ALTA | CONFIRMADO | `api/security/identity.py:243-300` | Condición de carrera en el bloqueo por intentos fallidos: con peticiones concurrentes la cuenta nunca se bloquea |
| SEC-03 | MEDIA | CONFIRMADO | `api/app.py:726-741` | El triage guarda la decisión del analista (feedback + timeline) **antes** de validar la transición; 422 deja estado incoherente y contamina el feedback |
| SEC-04 | MEDIA | VERIFICADO EN CÓDIGO | `api/security/guard.py:88,111` | `_failures` (contador por IP) no tiene cota: crecimiento de memoria sin límite, amplificado por SEC-01 |
| SEC-05 | MEDIA | CONFIRMADO (medido) | `api/app.py:371` + `identity.py` | `async def emitir_token` ejecuta scrypt (~81 ms) y SQLite de forma síncrona en el event loop |
| SEC-06 | BAJA | VERIFICADO EN CÓDIGO | `identity.py:261-270`, `app.py:388` | Enumeración de estado de cuenta: "cuenta deshabilitada"/"cuenta bloqueada" se devuelven sin verificar la contraseña |
| SEC-07 | MEDIA | VERIFICADO EN CÓDIGO | `docker-compose.yml:33-38`, `Dockerfile` | NATS publicado en 0.0.0.0:4222/8222 sin auth ni TLS; contenedor API como root con `build-essential` |
| SEC-08 | BAJA | VERIFICADO EN CÓDIGO | `collectors/sysmon.py:17,86` | `xml.etree.ElementTree.fromstring` sobre XML de entrada (Semgrep/Bandit B314); mitigado parcialmente por expat 2.4.7 |
| SEC-09 | BAJA | VERIFICADO EN CÓDIGO | `cli.py:933-940` | Clave privada de laboratorio creada y luego `chmod 600` (ventana con permisos de umask) |
| DEP-01 | BAJA | VERIFICADO | `diskcache 5.6.3` (vía pySigma) | GHSA-w8v5-vhqr-4h9v / CVE-2025-69872, sin versión corregida; módulo no importado por CyberSentinel |
| DEP-02 | INFO | VERIFICADO | `pillow 12.3.0` (vía matplotlib, extras `viz`/`dev`) | 24 avisos, corregidos en 13.0.0; no se instala en la imagen Docker |
| DEP-03 | BAJA | VERIFICADO | `pyproject.toml`, `requirements.txt`, `Dockerfile` | Sin lockfile; rangos `>=` abiertos; `nats-py>=2.6` sin fijar en la imagen |
| BUG-01 | BAJA | CONFIRMADO | `api/models.py:126` | `CreateKeyRequest.role` tiene default `"sensor"`, que no es un rol válido → 422 si se omite `role` |

## Detalle

### SEC-01 — Suplantación de IP vía `X-Forwarded-For` (ALTA, confianza alta)
- **Evidencia**: `guard.py:127-130`
  ```python
  if TRUST_FORWARDED:
      reenviada = request.headers.get("x-forwarded-for", "")
      if reenviada:
          return reenviada.split(",")[0].strip()
  ```
  El primer elemento lo escribe el cliente; los proxies estándar (nginx `$proxy_add_x_forwarded_for`, ALB, Traefik) **añaden** la IP real al final. Lo mismo aplica a `X-Forwarded-Proto` en `transport.py` (toma el primer valor).
- **Escenario**: despliegue detrás de proxy con `CYBERSENTINEL_TRUST_FORWARDED_FOR=1` (configuración documentada para producción). El atacante envía `X-Forwarded-For: <aleatorio>` en cada petición.
- **PoC** (`poc/poc_api.py`, burst anónimo = 3):
  - XFF fijo: `[401, 401, 401, 429, 429, …]`
  - XFF con valor falso rotado a la izquierda: `[401 × 12]` (nunca 429).
- **Impacto**: anula el límite anónimo previo a scrypt → fuerza bruta de contraseñas sin límite por IP y amplificación de CPU (scrypt). También falsea la IP en la auditoría de fallos. El bloqueo por cuenta (5 intentos) mitiga parcialmente, pero ver SEC-02.
- **Corrección mínima**: configurar el número de proxies de confianza (`CYBERSENTINEL_TRUSTED_PROXY_HOPS`, por defecto 1) y tomar `split(",")[-hops]`; o aceptar XFF solo si `request.client.host` está en una lista de proxies de confianza. Aplicar lo mismo a `X-Forwarded-Proto`.
- **Test de regresión**: el PoC anterior convertido en test (XFF rotado debe recibir 429 tras el burst).

### SEC-02 — Carrera en el bloqueo de cuenta (ALTA, confianza alta)
- **Evidencia**: `identity.py:243-300`. `verify_password` lee `failed_attempts` (sin bloqueo), deriva scrypt (~81 ms) y luego `_record_failure(username, fila["failed_attempts"] + 1)` **escribe un valor absoluto** (`SET failed_attempts = ?`). Las peticiones simultáneas leen el mismo valor y se pisan (lost update).
- **PoC** (`poc/poc_api.py`): 20 intentos concurrentes con contraseña errónea → **20 contraseñas evaluadas** (esperado ≤ 5), `failed_attempts = 2` en BD, `locked_until = NULL`: la cuenta nunca se bloquea.
- **Impacto**: combinado con SEC-01 o con varias réplicas/hilos, elimina el control de fuerza bruta por cuenta.
- **Corrección mínima**: incremento atómico en SQL `UPDATE users SET failed_attempts = failed_attempts + 1, locked_until = CASE WHEN failed_attempts + 1 >= ? THEN ? ELSE locked_until END WHERE username = ? RETURNING failed_attempts` (SQLite ≥ 3.35) o `BEGIN IMMEDIATE` + relectura; volver a comprobar `locked_until` después de derivar.
- **Test**: 20 hilos con contraseña errónea → `failed_attempts == 20` y `locked_until` no nulo; ≤ 5+N evaluadas.

### SEC-03 — Triage persiste antes de validar (MEDIA, confianza alta)
- **Evidencia**: `app.py:726-741`: `servicio.feedback.submit_decision(decision)` y `servicio.incidents.record_decision(...)` se ejecutan antes de `servicio.incidents.update(...)`, que es quien valida la máquina de estados y lanza `IncidentError` → 422.
- **PoC** (`poc/poc_api2.py`): incidente `resolved`; `CONFIRM`, `REJECT` y `UNCERTAIN` devuelven 422 (“no se puede pasar de 'resolved' a …”), el estado sigue `resolved`, pero la timeline contiene entradas `decision` (p. ej. "Decisión del analista: TRUE_POSITIVE") y el feedback quedó aceptado.
- **Impacto**: integridad de datos; decisiones contradictorias alimentan el bucle de feedback/reentrenamiento (envenenamiento accidental o deliberado por un analista). Además `datetime.fromisoformat(incidente["event_time"])` (`app.py:713`) puede lanzar → 500.
- **Corrección**: validar la transición (`incidents.can_transition`) antes de registrar, o envolver en una transacción y registrar solo si `update` tiene éxito.

### SEC-04 — `_failures` sin límite (MEDIA, confianza media)
- `guard.py:88` `self._failures: dict[str, _FailureCounter] = {}`; `guard.py:111` `setdefault(cliente, …)` sin expiración ni tamaño máximo (a diferencia de `RateLimiter`, acotado a 50 000 cubos). Con SEC-01 cada petición genera una clave nueva. Corrección: `OrderedDict` acotado/LRU como en `ratelimit.py`.

### SEC-05 — Bloqueo del event loop (MEDIA, confianza alta)
- `emitir_token` y otros manejadores son `async def` y llaman código síncrono costoso (scrypt ~81 ms medido, SQLite). FastAPI no los delega a un threadpool.
- Medición (`poc/poc_loop.py`, uvicorn 1 worker, loopback): `/health` media 32,5 ms / p95 36,0 ms sin carga → 46,8 ms / 66,8 ms con 4 clientes haciendo login en bucle. Efecto real pero moderado en este entorno; crece con concurrencia.
- Corrección: declarar los manejadores como `def` (threadpool) o `await run_in_threadpool(gate.issue_token, …)`.

### SEC-06 — Enumeración de estado de cuenta (BAJA)
- `identity.py:261-270` devuelve "cuenta deshabilitada" / "cuenta bloqueada…" antes de comprobar la contraseña; `app.py:388` copia `exc.motivo` en la respuesta. Un anónimo puede saber si un usuario existe y está bloqueado/deshabilitado. El comentario de `app.py` ("mismo mensaje para usuario inexistente y contraseña incorrecta") no cubre estos casos. Corrección: mensaje genérico al cliente, motivo detallado solo en auditoría (se puede mantener `Retry-After`).

### SEC-07 — Docker / Compose (MEDIA en despliegue, contexto: compose declarado de desarrollo)
- `docker-compose.yml`: NATS `4222:4222` y `8222:8222` publicados en todas las interfaces, sin `authorization`/TLS; el monitor HTTP (`/varz`, `/connz`) filtra topología. Cualquiera en la red podría publicar eventos en los subjects de ingesta, saltándose la autenticación de la API.
- `Dockerfile`: sin `USER` (corre como root), `build-essential` queda en la imagen final (sin multi-stage), sin `HEALTHCHECK`, `nats-py` sin fijar.
- Corrección: `127.0.0.1:` en los puertos o no publicarlos; credenciales NATS; multi-stage + usuario no root.

### SEC-08 — XML sin `defusedxml` (BAJA)
- `collectors/sysmon.py:86` `ET.fromstring(texto)`. ElementTree no resuelve entidades externas y expat 2.4.7 (instalado) mitiga "billion laughs", por lo que el riesgo residual es bajo; `defusedxml` es la corrección estándar y barata.

### SEC-09 — Permisos de clave privada de laboratorio (BAJA)
- `cli.py:933-940`: `openssl` escribe la clave y después `chmod 0o600`. Ventana breve con permisos por umask. Corrección: `os.umask(0o077)` durante la generación.

### DEP-01..03 — Dependencias
- `diskcache 5.6.3`: OSV GHSA-w8v5-vhqr-4h9v "DiskCache has unsafe pickle deserialization" (afecta ≤ 5.6.3, sin fix). Solo se usa en `sigma/data/mitre_attack.py` de pySigma; `grep` en `src/` y `scripts/` no encuentra imports de `sigma.data` → **no alcanzable** en CyberSentinel; requiere además escritura en el directorio de caché. Riesgo BAJO; vigilar.
- `pillow 12.3.0`: 24 avisos con fix en 13.0.0 (p. ej. GHSA-p4wg-p73j-c528). Entra solo vía `matplotlib` (extras `viz`/`dev`), usado en `detection/evaluation.py:303` y `scripts/make_figures.py` para figuras locales. INFO. Fijar `pillow>=13.0.0` en el extra `viz`.
- Sin lockfile ni hashes; rangos abiertos (`fastapi>=0.115`, `langchain-*>=0.3`…). Durante el setup apareció un conflicto `fastapi 0.159.1` ↔ `opentelemetry-api 1.37.0` resuelto al recrear el venv: evidencia de que las instalaciones no son reproducibles. Recomendado: `pip-compile`/`uv lock` con hashes y Dependabot/Renovate.

### Falsos positivos descartados
- **Bandit B608** (`incidents.py:353,525`): SQL con f-string, pero los nombres de columna salen de constantes internas y los valores van parametrizados → FALSO POSITIVO.
- **Semgrep `python-logger-credential-disclosure`** `app.py:341`: registra la *fuente* del secreto ("ephemeral"), no el secreto → FALSO POSITIVO.
- **detect-secrets** (18 ficheros): nombres de variables de entorno (`CYBERSENTINEL_JWT_SECRET`, `ANTHROPIC_API_KEY`), cabecera `X-API-Key`, enum `RESET_PASSWORD`, hashes de ejemplo en docs/fixtures y secretos de test → ningún secreto real encontrado.
- **Panel web**: `panel.js` usa `textContent` (sin `innerHTML`), CSP restrictiva y token en `sessionStorage` → sin XSS encontrado.
- **JWT**: `alg` fijado a HS256, `compare_digest`, `exp/nbf/iss` validados, secreto ≥ 32 bytes, revocación persistente → sin hallazgos.
- **Respuesta automática**: modo dry-run por defecto; las acciones sensibles requieren aprobación humana y nunca se ejecutan comandos reales → sin hallazgos.
