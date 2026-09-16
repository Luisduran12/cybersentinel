# Frontera del servicio — autenticación, RBAC y límite de caudal

> Estado: implementado y probado. 41 pruebas específicas en
> `tests/test_api_security.py`, verificado además contra un servidor uvicorn
> real. **Falta TLS**: ver [Lo que sigue sin estar](#lo-que-sigue-sin-estar).

Antes de esto, cualquiera con acceso de red al puerto 8000 podía inyectar
telemetría en el pipeline y leer el historial completo de incidentes. La API
existía; la frontera, no.

---

## Lo que se decidió y por qué

### 1. Dos tipos de credencial, porque hay dos tipos de cliente

| | Persona (analista, responsable, auditor) | Sensor (colector) |
|---|---|---|
| Credencial | usuario + contraseña → **token de sesión** | **clave de API** |
| Cabecera | `Authorization: Bearer <token>` | `X-API-Key: cs_<id>_<secreto>` |
| Secreto | elegido por un humano (poca entropía) | 256 bits de CSPRNG |
| Derivación | **scrypt** (n=2¹⁵, r=8) | **SHA-256**, una pasada |
| Vida | 1 hora | 1 año, revocable |
| Frecuencia | una vez por sesión | miles de veces por segundo |

**Por qué SHA-256 basta para la clave y no para la contraseña.** El derivado
lento existe para encarecer el ataque por diccionario sobre secretos que las
personas eligen y reutilizan. Una clave de 32 bytes aleatorios no tiene
diccionario: probarla exige recorrer 2²⁵⁶. Y aplicarle scrypt tendría un coste
medido:

```
operación                                  p50        p95        ops/s
----------------------------------------------------------------------
verify_api_key (SHA-256 + SQLite)        51.5µs      55.1µs       19,062
token JWT: verificar (HMAC-SHA256)       24.1µs      24.7µs       41,199
limitador: cubo de fichas                 2.4µs       2.5µs      412,802
verify_password (scrypt n=2^15)      113208.5µs  115771.3µs            9
```

*(`python scripts/benchmark_security.py`; informe en
`results/security_benchmark.json`.)*

La contraseña cuesta **2 165×** lo que la clave de máquina. Con scrypt en la
ruta de ingestión, el techo del servicio serían 9 peticiones por segundo.

### 2. El permiso es la unidad, no el rol

El código nunca pregunta «¿eres analista?»; pregunta «¿puedes leer incidentes?».
Preguntar por el rol esparce la política por todos los manejadores; preguntar
por el permiso la concentra en una tabla (`security/roles.py`).

| Rol | Permisos |
|---|---|
| `sensor` | `events:write` |
| `analyst` | `incidents:read`, `metrics:read` |
| `responder` | + `incidents:write`, `response:approve` |
| `auditor` | `incidents:read`, `metrics:read`, `audit:read` — **no escribe nada** |
| `admin` | todo lo anterior + `identity:admin`, **sin `events:write`** |

Dos ausencias son deliberadas y están probadas:

- **El sensor no lee.** Su credencial vive en un fichero de configuración de un
  host cualquiera. Robarla debe costar ruido en la cola, no el historial de
  incidentes de la organización.
- **El admin no ingiere.** Administrar no es emitir. Si el administrador pudiera
  inyectar telemetría, la auditoría no podría distinguir quién metió un evento
  en el sistema.
- **El auditor no escribe.** Quien puede modificar lo que audita anula la
  auditoría.

### 3. El límite de caudal es por cliente, y en dos ejes

Ya existía contrapresión: cuando la cola se llena, la API devuelve 429. Eso
protege al **servicio**, pero significa que un sensor mal configurado que envía
en bucle deja sin servicio a los otros cuarenta. El límite por cliente protege a
los **clientes entre sí**: el que se desmanda agota su propio cubo y nadie más
lo nota.

Se limitan **peticiones** y **eventos** por separado:

- solo peticiones → diez lotes de 10 000 eventos cumplen el límite y entregan
  100 000 eventos;
- solo eventos → mil peticiones vacías siguen costando mil validaciones.

Cubo de fichas, no ventana fija: una ventana de 60 s permite enviar el doble del
límite a caballo entre dos ventanas.

| Rol | Peticiones/s (ráfaga) | Eventos/s (ráfaga) |
|---|---|---|
| `sensor` | 50 (100) | 20 000 (40 000) |
| persona | 10 (20) | 1 000 (2 000) |
| sin autenticar | 1 (10) | — |

Configurable por entorno (`CYBERSENTINEL_RL_SENSOR_RPS`, `..._EPS`, `..._ANON_RPS`…).

### 4. El orden de las comprobaciones es la defensa

1. **Autenticar** → 2. **Limitar** → 3. **Autorizar**.

Con un matiz que cambia el resultado: el endpoint de emisión de tokens aplica el
límite por IP **antes** de derivar la contraseña. Verificar una contraseña
cuesta 113 ms de scrypt a propósito; si el límite se aplicara después, mil
peticiones por segundo con contraseñas falsas tumbarían el servicio sin
necesidad de acertar ninguna: el propio mecanismo de defensa sería la palanca.

Y el fallo de autenticación se cobra del cubo **anónimo del origen**, no del de
nadie más: quien prueba credenciales agota su propia cuota.

---

## Lo que se probó, nombrando el ataque

`tests/test_api_security.py` — 41 pruebas. No comprueban «que haya seguridad»,
comprueban que ataques concretos fallan:

| Ataque | Prueba | Resultado |
|---|---|---|
| Llegar sin credencial | `test_sin_credencial_no_se_pasa` | 401 en las 5 rutas protegidas |
| Reconocimiento por `/ready` | `test_ready_sin_credencial_no_revela_el_interior` | sin credencial devuelve solo `{"ready": …}` |
| Confusión de algoritmos (`alg: none`) | `test_token_alg_none_se_rechaza` | rechazado antes de tocar la firma |
| Escalada cambiando `role` en el token | `test_token_manipulado_se_rechaza` | firma inválida |
| Token de otra instalación | `test_token_de_otro_secreto_se_rechaza` | firma inválida |
| Token eterno (sin `exp`) | `test_token_sin_caducidad_se_rechaza` | rechazado |
| Confusión de credencial (dos a la vez) | `test_dos_credenciales_a_la_vez_se_rechazan` | 401 |
| Seguir usando una clave revocada | `test_clave_revocada_deja_de_valer` | 401 tras revocar |
| Enumeración de usuarios | `test_usuario_inexistente_y_contrasena_mala…` | mismo mensaje y mismo código |
| Fuerza bruta sobre contraseña | `test_bloqueo_por_intentos_fallidos` | bloqueo a los 5 intentos, 300 s |
| Filtración del almacén | `test_el_secreto_no_se_guarda_en_claro` | ni clave ni contraseña en el `.db` |
| Sensor leyendo incidentes | `test_el_sensor_no_puede_leer_incidentes` | 403 |
| Analista inyectando telemetría | `test_el_analista_no_puede_ingerir` | 403 |
| Auditor escribiendo | `test_el_auditor_no_escribe_nada` | 403 |
| Cliente desbocado | `test_el_limite_es_por_cliente_no_global` | solo se ahoga él |
| Agotar memoria con IPs falsas | `test_los_cubos_no_crecen_sin_limite` | cubos acotados (LRU) |
| Inflar el log de auditoría con fallos | `test_los_fallos_repetidos_no_inflan_la_auditoria` | agregados por ventana de 60 s |
| Filtrar secretos por la auditoría | `test_la_auditoria_no_guarda_secretos` | ni contraseñas ni claves |

Verificado además contra un uvicorn real, no solo con `TestClient`:

```
ráfaga de 160 peticiones (límite sensor 50/s, ráfaga 100)
 110 · 202 Accepted
  50 · 429 Too Many Requests

20 intentos de contraseña (límite anónimo 5/s, ráfaga 10)
  14 · 401   6 · 429
→ y después: {"error":"no_autenticado","reason":"cuenta bloqueada tras 5 intentos fallidos"}
```

Las dos defensas disparan por separado: el limitador frena el ritmo, el bloqueo
de cuenta frena el total.

---

## Auditoría

La frontera escribe en la **misma** cadena HMAC-SHA256 que el resto del sistema,
no en un archivo aparte: un registro de autenticación en su propio fichero se
borra sin romper ninguna cadena; aquí, borrar un intento fallido invalida la
verificación de todo lo posterior.

Se registran: `token_issued`, `auth_failed`, `authz_denied`, `rate_limited`,
`api_key_created`, `api_key_revoked`, `user_created`, `user_disabled`.

**No** se registra cada ingesta correcta: serían millones de entradas al día en
una cadena que se verifica entera. Para eso están las métricas y el almacén de
eventos.

Los fallos repetidos del mismo origen se agregan en ventanas de 60 s con el
contador incluido (`failures_since_last_entry`). Sin eso, un atacante que
dispara credenciales falsas escribe él mismo el tamaño del log de auditoría.

---

## Uso

### Crear credenciales

```bash
# Un sensor. La clave se muestra UNA vez: el almacén guarda solo su hash.
cybersentinel auth create-key --label "sysmon-SRV-APP"

# Una persona. La contraseña se pide por terminal, nunca por argumento:
# un --password lo ve cualquier proceso con `ps` y queda en el historial.
cybersentinel auth create-user --username ana --role analyst

cybersentinel auth list                      # inventario
cybersentinel auth revoke-key --key-id 731280f20527
cybersentinel auth disable-user --username ana
cybersentinel auth roles                     # matriz de autorización
```

### Arrancar el servicio

```bash
export CYBERSENTINEL_JWT_SECRET=$(openssl rand -hex 32)   # ≥32 bytes
export CYBERSENTINEL_IDENTITY_DB=/var/lib/cybersentinel/identities.db
uvicorn cybersentinel.api.app:app --host 0.0.0.0 --port 8000
```

Sin `CYBERSENTINEL_JWT_SECRET` el servicio **arranca igualmente** con un secreto
efímero y lo declara: en el log de arranque y en `/api/v1/ready`
(`security.token_secret_source: "ephemeral"`). Los tokens mueren al reiniciar y
no valen entre réplicas. La alternativa —un secreto por defecto en el código—
convertiría cualquier despliegue que olvide configurarlo en un sistema donde
cualquiera puede firmarse un token de admin. Eso no es un modo degradado, es una
puerta trasera.

### Usar la API

```bash
# Sensor
curl -X POST http://localhost:8000/api/v1/events \
     -H "X-API-Key: cs_731280f20527_dHSBqLp1..." \
     -H 'content-type: application/json' \
     -d '{"events":[{"source":"sysmon","action":"process_create","host":"SRV"}]}'

# Persona
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/token \
        -H 'content-type: application/json' \
        -d '{"username":"ana","password":"..."}' | jq -r .access_token)
curl http://localhost:8000/api/v1/incidents -H "Authorization: Bearer $TOKEN"
```

### Variables de entorno

| Variable | Defecto | Qué hace |
|---|---|---|
| `CYBERSENTINEL_JWT_SECRET` | *(efímero + aviso)* | Firma de los tokens. ≥32 bytes |
| `CYBERSENTINEL_IDENTITY_DB` | `data/runtime/identities.db` | Almacén de credenciales |
| `CYBERSENTINEL_TOKEN_TTL` | `3600` | Vida del token, en segundos |
| `CYBERSENTINEL_TRUST_FORWARDED_FOR` | `0` | Leer la IP de `X-Forwarded-For` |
| `CYBERSENTINEL_RL_SENSOR_RPS` / `_BURST` | `50` / `100` | Peticiones por sensor |
| `CYBERSENTINEL_RL_SENSOR_EPS` / `_BURST` | `20000` / `40000` | Eventos por sensor |
| `CYBERSENTINEL_RL_ANON_RPS` / `_BURST` | `1` / `10` | Peticiones sin autenticar |

`CYBERSENTINEL_TRUST_FORWARDED_FOR` viene **desactivado** a propósito: confiar en
esa cabecera sin un proxy delante permite a cualquiera falsificar su origen y
saltarse el límite por IP.

---

## Lo que sigue sin estar

Declarado aquí para que no haya que descubrirlo en producción.

1. **TLS.** El servicio habla HTTP en claro. Sin terminación TLS delante —proxy
   o `uvicorn --ssl-keyfile --ssl-certfile`— las credenciales viajan legibles y
   toda la autenticación de arriba no sirve de nada. **Es el siguiente
   requisito, no un detalle de despliegue.**

2. **Los límites son por proceso.** Los cubos viven en memoria. Con N réplicas,
   el límite efectivo es N veces el configurado. Mover el estado a un almacén
   compartido es parte del trabajo de alta disponibilidad.

3. **La revocación de tokens es por proceso.** La lista de `jti` revocados vive
   en memoria: al reiniciar, un token revocado vuelve a valer hasta su `exp`
   (una hora como mucho, con la configuración por defecto). Mismo destino que el
   punto anterior.

4. **No es OIDC.** No hay claves asimétricas, ni rotación por `kid`, ni
   proveedor externo, ni MFA. Integrarse con el directorio corporativo significa
   reemplazar `security/tokens.py` y la resolución del `Principal`; ni los roles,
   ni los límites, ni un solo manejador de la API cambian. Esa es la razón de que
   todo el sistema consuma un único objeto `Principal`.

5. **El contador de usos se vuelca cada 5 s.** Si el proceso muere de golpe se
   pierden hasta 5 s de estadística de uso. La comprobación de revocación **no**
   está diferida: se lee de la base de datos en cada petición.

6. **Sin rotación de contraseñas ni caducidad de cuentas.** Hay bloqueo por
   intentos fallidos y deshabilitación manual; no hay política de caducidad.

---

## Arquitectura

```
src/cybersentinel/api/security/
├── roles.py      permisos, roles y la matriz que los une
├── identity.py   personas (scrypt) y sensores (clave de API), en SQLite
├── tokens.py     JWT HS256 con la biblioteca estándar
├── ratelimit.py  cubo de fichas por cliente, dos ejes
└── guard.py      los une, aplica el orden y deja constancia
```

Ninguna dependencia nueva. El resto del sistema ve un solo objeto —`Principal`—
y una sola dependencia —`requires(permiso)`—. El pipeline de detección nunca
sabe quién le envió un evento, y eso es correcto: un motor que dependa de la
identidad del emisor es un motor que se engaña cambiando de credencial.
