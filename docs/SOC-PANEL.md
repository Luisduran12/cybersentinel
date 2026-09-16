# Panel SOC — del resultado efímero al incidente investigable

> Estado: implementado y probado. 31 pruebas en `tests/test_soc_panel.py`,
> verificado además contra un uvicorn real en un navegador, con los tres roles.

Antes de esto el sistema **detectaba pero no dejaba investigar**. Cada ejecución
producía resultados en memoria; `ResultStore` guardaba un resumen por evento
—puntuación, reglas, técnicas— y la evidencia que justificaba la alerta se
perdía al terminar el proceso. Un analista podía saber que algo puntuó 91,5 y no
tenía forma de saber *por qué*, ni de decir «esto lo llevo yo», ni de dejar
constancia de lo que había comprobado.

---

## Lo que se añadió

### 1. El incidente como entidad persistente (`api/incidents.py`)

| | `ResultStore` (ya existía) | `IncidentStore` (nuevo) |
|---|---|---|
| Responde a | ¿cuántos eventos vi y cómo fueron? | ¿qué tengo que investigar? |
| Alcance | **todos** los eventos | solo los que cruzaron el umbral |
| Contenido | resumen por evento | evidencia completa: reglas con confianza, evento normalizado, narrativa, CTI, contexto RAG con procedencia, contramedidas con su veredicto de gobernanza |
| Estado | ninguno | ciclo de vida, propietario, resolución, cronología |

Están separados a propósito. Ya se midió que volcar la evidencia íntegra de
20 000 eventos produce **129 MB de JSON**: guardarla para todo es inviable y no
guardarla para nada deja al analista sin el porqué. Los incidentes son una
fracción pequeña del caudal, y ahí sí cabe.

### 2. Un ciclo de vida que no acepta cualquier cosa

```
new ──► triaged ──► in_progress ──► closed
 │         ▲                          │
 └─────────┴──────── reabrir ─────────┘
```

- Cerrar **exige** una resolución (`true_positive`, `false_positive`, `benign`,
  `duplicate`). Un incidente cerrado sin motivo no enseña nada a quien venga
  después, ni al dataset de reentrenamiento.
- Reabrir devuelve a **triaje**, no a «en curso», y limpia la resolución:
  dejarla puesta haría creer que un incidente abierto ya está concluido.
- Lo que no está en la tabla de transiciones se rechaza con un 422 que dice qué
  sí se puede hacer. Un ciclo de vida que acepta cualquier cambio no es un ciclo
  de vida, es un campo de texto.

### 3. Cronología de solo-añadir

Cambiar de estado, asignar, anotar y decidir escriben una entrada nueva; **nada
se sobrescribe**. El estado actual es una columna por comodidad de consulta: la
verdad está en la cronología. Un panel que deja reescribir la historia no sirve
como registro de una investigación.

El ajuste manual de severidad queda marcado como tal (`ajustada por una
persona`, con la severidad que se derivaba de la puntuación): sin esa marca,
nadie sabría después si el orden del panel refleja el modelo o el criterio de un
analista.

### 4. El panel (`api/panel/`)

Servido por el propio proceso en `/soc/`. HTML, CSS y JavaScript sin cadena de
compilación, sin dependencias y **sin una sola descarga externa**: un centro de
operaciones puede estar en una red aislada, y un panel que pide una fuente a un
CDN se queda en blanco.

Tres decisiones del lado del navegador:

- **Todo se inserta con `textContent`, nunca con `innerHTML`.** La telemetría la
  escribe el atacante: una línea de comandos con `<img onerror=...>` ejecutaría
  su código en el navegador del analista que la está investigando. Es el mismo
  razonamiento que ya se aplica a la inyección de prompt en el explicador, en
  otra capa. Hay una prueba que lo comprueba sobre el archivo.
- **Sin `prompt`, `alert` ni `confirm`.** Un diálogo nativo congela la pestaña
  entera —incluidas las peticiones en vuelo— hasta que alguien lo cierra. Se
  comprobó por las malas: un `prompt` bloqueó la página durante la verificación
  en navegador hasta tener que cerrarla. La resolución de cierre y el motivo del
  veredicto se piden con controles de la propia página.
- **El token vive en `sessionStorage`**, que muere al cerrar la pestaña —el
  comportamiento que se espera de una consola de seguridad en un puesto
  compartido—. Sigue siendo accesible desde JavaScript: la defensa real contra
  el robo de token es la vida corta (una hora) y la revocación en
  `/auth/logout`, no el sitio donde se guarda.

Cabeceras que envía el servicio: `Content-Security-Policy` estricta
(`default-src 'self'`, `frame-ancestors 'none'`), `X-Content-Type-Options`,
`X-Frame-Options`, `Referrer-Policy`.

### 5. El veredicto no abre un circuito paralelo

El botón de veredicto escribe en el **mismo** almacén de decisiones que
`cybersentinel decide`, con la misma `StructuredDecision` y la evidencia sellada
dentro. Dos fuentes de verdad sobre lo que un humano decidió son cero fuentes de
verdad.

`UNCERTAIN` **no cierra** el incidente, aunque se pida el cierre: uno sobre el
que el analista duda no está resuelto, y cerrarlo lo escondería del panel sin
que nadie haya decidido nada. El panel lo dice en lugar de hacerlo en silencio.

### 6. Lo que el panel enseña y otros esconden

- **De dónde salió la narrativa.** Un párrafo del respaldo determinista y otro
  escrito por un modelo tienen valor probatorio distinto. El panel muestra el
  `llm_status` y una etiqueta «sin modelo» cuando corresponde.
- **Qué componente está degradado**, no «todo bien». La cabecera dice
  `llm: UNAVAILABLE` cuando no hay credenciales, en vez de un semáforo verde.
- **Que las contramedidas no se ejecutan desde aquí.** Se proponen y se
  clasifican (permitida / requiere aprobación / prohibida); ejecutarlas exige
  aprobación humana fuera de esta interfaz.
- **Que un incidente `ANOMALY_ONLY` casi nunca alcanza el umbral solo**, porque
  la puntuación híbrida concede como máximo 20 puntos al modelo. Es la
  limitación que ya documenta `docs/BENCHMARK.md`, dicha donde el analista la
  necesita.

---

## Endpoints

| Método | Ruta | Permiso |
|---|---|---|
| GET | `/api/v1/incidents` (filtros: `state`, `severity`, `owner`, `entity`, `technique`, `unassigned`, `q`, `since`, `limit`, `offset`) | `incidents:read` |
| GET | `/api/v1/incidents/stats` | `incidents:read` |
| GET | `/api/v1/incidents/{id}` | `incidents:read` |
| PATCH | `/api/v1/incidents/{id}` | `incidents:write` |
| POST | `/api/v1/incidents/{id}/notes` | `incidents:write` |
| POST | `/api/v1/incidents/{id}/decision` | `incidents:write` |
| GET | `/soc/` | público (estático; los datos sí exigen credencial) |

`/incidents/stats` se declara **antes** que `/incidents/{id}`: en caso
contrario, «stats» se interpreta como el identificador de un incidente. Hay una
prueba que lo fija.

---

## Un fallo real que esto destapó

La verificación en navegador no fue un trámite. Encontró tres cosas que las
pruebas no podían encontrar:

1. **La pantalla de acceso tapaba el panel ya cargado.** El DOM decía
   `hidden = true` y la captura mostraba el formulario: `.login { display: grid }`
   pisaba la regla `[hidden]` del navegador. Arreglado con
   `[hidden] { display: none !important }`.
2. **La cabecera marcaba como degradado todo lo que funcionaba.** El pipeline
   devuelve `"OK (7 reglas)"`, no `"OK"`, y la comparación era por igualdad. El
   panel gritaba en rojo con el servicio sano.
3. **Un `prompt()` bloqueó la pestaña entera** hasta tener que cerrarla. De ahí
   la regla de no usar diálogos nativos, y la prueba que la fija.

Y una cuarta, la más grave, que apareció al verificar la auditoría del
despliegue:

> **La cadena de auditoría estaba rota.** `verify-audit` devolvía «integridad
> COMPROMETIDA (entrada #0)».

La causa: al auditar la autenticación en el mismo registro que el pipeline había
**dos objetos `AuditLog` sobre el mismo archivo**, cada uno calculando `index` y
`prev_hash` desde su propia lista en memoria. El archivo acababa con dos cadenas
entrelazadas, ambas empezando en el índice 0. Lo grave no era perder la
verificación: era perderla justo cuando había más cosas que auditar.

Arreglado en `governance/audit.py`, en la causa y no en el síntoma: `record()`
relee el archivo si ha crecido por debajo de la instancia, y el candado es **por
archivo**, no por objeto —con uno por instancia, cuatro `AuditLog` sobre el
mismo registro tendrían cuatro candados y podrían intercalarse igual—. Dos
pruebas de regresión lo fijan. **Límite declarado:** esto resuelve varias
instancias en el mismo proceso; dos *procesos* escribiendo a la vez siguen
pudiendo entrelazarse, y eso exige un bloqueo de archivo o un único escritor.

Verificado después contra el despliegue, con el pipeline y la frontera
escribiendo alternadamente:

```
    2  incident_analyzed      ← pipeline
    2  incident_updated       ← frontera
    1  token_issued           ← frontera
    1  auth_failed            ← frontera
    1  authz_denied           ← frontera

Modo: firmada con clave (HMAC-SHA256) · 7 entradas
Cadena de auditoría íntegra. Cadena íntegra y anclada.
```

---

## Lo que sigue sin estar

1. **Un incidente por evento, no por campaña.** El correlador temporal existe y
   alimenta la evidencia, pero no agrupa. En una cadena de ataque de ocho pasos
   el analista verá ocho incidentes relacionados por entidad y ventana, no uno.
   Es la limitación más molesta de este panel y la siguiente que conviene
   resolver.
2. **Sin SLA ni notificaciones.** Hay estado y propietario; no hay reloj de
   respuesta, escalado ni aviso a nadie.
3. **Sin actualización en vivo.** La lista se refresca al pedirlo. No hay
   *server-sent events* ni *websocket*: en un panel abierto, un incidente nuevo
   no aparece solo.
4. **La búsqueda por técnica es un `LIKE` sobre JSON.** Con el volumen de un
   panel (miles, no millones) es suficiente; está dicho aquí para que nadie lo
   descubra midiendo.
5. **El almacén es SQLite.** Correcto para un proceso; la alta disponibilidad
   exige mover incidentes y credenciales a una base compartida.

---

## Uso

```bash
export CYBERSENTINEL_JWT_SECRET=$(openssl rand -hex 32)
export CYBERSENTINEL_AUDIT_KEY=$(openssl rand -hex 32)
cybersentinel auth create-user --username rosa --role responder
cybersentinel serve --host 0.0.0.0 --dev-cert
```

El panel queda en `https://localhost:8000/soc/` (y `/` redirige allí).

Si la página se abre por HTTP desde una máquina que no es la tuya, el formulario
de acceso **se deshabilita** y lo dice: la contraseña viajaría legible. Sobre
bucle local solo aparece una nota. El aviso se calcula, no está escrito fijo —un
aviso que sale siempre deja de leerse—.
