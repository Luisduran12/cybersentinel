# Alta disponibilidad — qué sobrevive a un fallo y qué no

> Estado: implementado y probado. 25 pruebas en `tests/test_high_availability.py`,
> verificado además con `kill -9` sobre un uvicorn real y con dos réplicas
> simultáneas.

La pregunta de partida era concreta: **si el proceso muere ahora mismo, ¿qué se
pierde?** La respuesta era: todo lo que estuviera en la cola en memoria. El
emisor tenía un `202 Accepted` en su registro y el sistema no tenía el evento.

Eso es peor que perder el evento a secas, porque **nadie sabe que falta**.

---

## 1. Que un 202 signifique algo

El orden es **registro → cola → respuesta**, nunca al revés. Nada se acepta
hasta estar escrito en disco; si el registro falla, la API devuelve el fallo y
el emisor reintenta. Un 503 honesto es mejor que un 202 que miente.

### La prueba

```
$ curl -X POST .../api/v1/events -d '{"events": [ ...3000... ]}'
{"accepted": 3000, "rejected": 0, "queued": 2500}

$ kill -9 5578
$ sqlite3 events.db "SELECT COUNT(*) FROM processed_events"
0                       ← nada llegó a procesarse
$ cat wal/checkpoint.json
(no existe)             ← ni un punto de control

# y al arrancar de nuevo:
Recuperados 3000 eventos aceptados y no procesados del arranque anterior.
No se perdió nada; se reprocesarán.

$ sqlite3 events.db "SELECT COUNT(*) FROM processed_events"
3000
```

Antes de este trabajo, esos 3 000 eventos no existían en ninguna parte.

### Decisiones del registro (`api/wal.py`)

- **Se guarda el registro crudo, no el evento normalizado.** Así la recuperación
  recorre exactamente el mismo camino que la ingestión y no puede divergir
  cuando un parser cambie.
- **Segmentos, no un archivo único.** Compactar un archivo grande obliga a
  reescribirlo entero; con segmentos basta con borrar los que están enteramente
  por debajo del punto de control.
- **El punto de control se mueve después de persistir, nunca antes.** Al revés,
  una caída entre ambas cosas daría por procesado lo que no llegó a guardarse:
  la pérdida silenciosa que todo esto existe para impedir.
- **Reprocesar es aceptable; perder, no.** Tras una caída puede repetirse un
  lote ya persistido. El almacén de incidentes usa `INSERT OR IGNORE` justo por
  esto. En detección, ver dos veces un evento es un problema menor.
- **Una línea truncada no se lleva por delante al resto.** La escritura que se
  cortó al morir el proceso se salta con un error registrado. Perder un evento
  por eso es malo; perder los diez mil de detrás es mucho peor.
- **Un punto de control ilegible reprocesa todo** en lugar de dar nada por hecho.

### La reserva de sitio, y por qué hace falta

El registro tiene que escribirse **antes** de aceptar, pero la cola puede estar
llena. Sin reserva solo quedan dos malas opciones: escribir y descubrir después
que no cabe —dejando eventos aceptados que nadie procesará hasta el siguiente
reinicio—, o comprobar el hueco y perderlo en la milésima siguiente frente a
otra petición.

`IngestQueue.reserve(n)` aparta el sitio antes de escribir. Así la contrapresión
se decide primero y el hueco ya no se lo puede quitar nadie. Reservar, registrar
y encolar ocurren bajo un mismo candado para que el orden de secuencia del
registro coincida con el de la cola: si no coincidieran, el punto de control
podría saltarse eventos sin procesar.

---

## 2. Cuánto cuesta, medido

```
150 lotes de 500 eventos (75 000 en total)

política     µs/evento     eventos/s    p95 lote   fsyncs
----------------------------------------------------------
always           47.45        21,076      25.33ms      150
interval          9.87       101,280       5.69ms        3
never             9.82       101,860       5.65ms        0
```

*(`python scripts/benchmark_wal.py`; informe en `results/wal_benchmark.json`.)*

| Política | Qué garantiza |
|---|---|
| `always` | ni un corte de corriente pierde un evento aceptado |
| `interval` *(defecto)* | se pierde como mucho una ventana de 200 ms ante un corte; **nada** ante la muerte del proceso |
| `never` | sobrevive a `kill -9`, no a que se vaya la luz |

**El dato que decide:** el pipeline completo mide 528 ev/s. Incluso la política
más cara deja el registro dos órdenes de magnitud por encima, así que la
durabilidad **no es lo que limita el caudal**.

### Una trampa que solo se ve midiendo

La primera versión del banco daba `always` y `never` prácticamente iguales
—10,26 µs/evento contra 9,87—, lo cual es imposible si `always` garantizase
algo. **Un `fsync` que no cuesta nada es un `fsync` que no hace nada.**

La causa: en macOS, `fsync()` entrega los datos al dispositivo pero no le obliga
a vaciar su caché de escritura. La llamada que sí lo garantiza es `F_FULLFSYNC`.
Con ella, el coste real aparece: 47,45 µs contra 9,82, **4,8×**. En Linux
`fsync()` sí llega al dispositivo.

Si esto no se hubiera medido, la documentación diría que `always` protege de un
corte de corriente y no sería verdad.

---

## 3. Apagado ordenado

`SIGTERM` a secas no basta: el proceso deja de escuchar de golpe y el
balanceador le sigue mandando tráfico durante los segundos que tarda en
enterarse. Esas peticiones se pierden.

```
1. POST /api/v1/drain        → /ready pasa a 503   (identity:admin)
2. esperar a que el balanceador lo saque de rotación
3. SIGTERM                   → se vacía la cola y se cierra el registro
```

`/ready` distingue **«me estoy apagando»** de **«me he roto»**:

```json
{"ready": false, "draining": true}
```

Confundirlas hace que el orquestador reinicie un proceso que estaba terminando
bien. El drenado no se puede deshacer desde la API a propósito: un proceso que
vuelve a aceptar tráfico después de anunciar que se retiraba es exactamente el
que el balanceador ya no vigila.

---

## 4. Lo que se comparte entre procesos, y lo que no

### Se comparte

| Estado | Cómo | Por qué tiene que compartirse |
|---|---|---|
| Identidades y claves | SQLite (modo WAL) | Sin esto, cada réplica tendría sus propios usuarios |
| **Revocación de tokens** | SQLite | Una revocación que depende de a qué réplica caiga la petición **no es una revocación** |
| Eventos e incidentes | SQLite (modo WAL) | El panel de una réplica tiene que ver lo que detectó la otra, o el analista trabaja con media verdad |
| Cadena de auditoría | JSONL + `flock` | Dos escritores sin candado producen dos cadenas entrelazadas y la verificación falla |

Verificado con dos réplicas reales:

```
token emitido en la réplica 1  → sirve en la réplica 2:           200
logout en la réplica 1         → en la réplica 2:                 401
20 lotes alternando entre ambas
incidentes que ve la réplica 1: 20
incidentes que ve la réplica 2: 20
Cadena de auditoría íntegra. Cadena íntegra y anclada.
```

### No se comparte: el registro anticipado

**Un solo escritor por directorio, y se impone con un candado.** Dos procesos
sobre el mismo registro calcularían la misma secuencia siguiente y abrirían el
mismo segmento: escribirían eventos distintos con el mismo número, y al
recuperar reproducirían las mismas entradas los dos. No sería una pérdida —sería
algo peor: duplicados silenciosos y un punto de control que da por procesado lo
que no lo está.

Por eso el segundo proceso **no arranca**:

```
$ uvicorn cybersentinel.api.app:app --port 8904
cybersentinel.api.wal.WalLocked: otro proceso ya usa el registro de .../wal.
Un registro admite un solo escritor: da a cada réplica su propio directorio
(CYBERSENTINEL_WAL) o pon una cola compartida delante.
```

Cada réplica necesita su propio `CYBERSENTINEL_WAL`.

---

## 5. La topología que esto soporta

```
                    ┌─────────────┐
   sensores ──TLS──►│ balanceador │
                    └──────┬──────┘
                    ┌──────┴──────┐
                    ▼             ▼
              ┌──────────┐  ┌──────────┐
              │ réplica 1│  │ réplica 2│     ← cada una con su WAL
              │  wal1/   │  │  wal2/   │
              └────┬─────┘  └─────┬────┘
                   └───────┬──────┘
                           ▼
              identities.db · events.db · incidents.db · audit.jsonl
                        (SQLite en modo WAL + flock)
```

- Si una réplica muere, el balanceador deja de mandarle tráfico; lo que había
  aceptado se recupera **cuando esa réplica vuelva**, desde su propio registro.
- Si se despliega una versión nueva, `drain` + `SIGTERM` por réplica, sin
  pérdida.
- El analista ve lo mismo entre en la que entre.

---

## Lo que sigue sin estar

Esto es **tolerancia a fallos en un host**, no alta disponibilidad de verdad.
La diferencia, dicha con precisión:

1. **No hay conmutación automática.** Lo que una réplica muerta tenía aceptado
   espera a que esa misma réplica vuelva. Nadie lo recoge en su lugar, porque el
   registro tiene un solo dueño. Resolverlo exige una cola compartida (un
   broker) o un protocolo de adopción del registro huérfano.

2. **Un solo host.** SQLite coordina varios procesos del mismo equipo. Sobre un
   sistema de archivos en red, sus candados no son fiables. Varias máquinas
   exigen PostgreSQL —y el cambio es de conexión, no de diseño: las consultas
   son SQL corriente—.

3. **La cadena de auditoría es un cuello de botella por diseño.** Un `flock`
   exclusivo por entrada serializa a todos los escritores. Con el volumen actual
   —solo se auditan decisiones e incidentes, no cada ingesta— no se nota; con
   cien réplicas, sí.

4. **Los límites de caudal siguen siendo por proceso.** Con N réplicas, el
   límite efectivo es N veces el configurado. Compartirlos exige un almacén con
   latencia de microsegundos, que es donde SQLite deja de servir.

5. **Sin réplica de los datos.** Si se pierde el disco, se pierde todo. No hay
   copia, ni instantáneas, ni envío de la auditoría a un medio independiente
   —que ya estaba declarado en `docs/ARCHITECTURE.md` como límite del anclaje—.

6. **`analyze --json` sigue como estaba**: 20 000 eventos → 129 MB de JSON y
   4,2 GB de RSS. La ruta de servicio es acotada; la de la CLI no.

---

## Configuración

| Variable | Defecto | Qué hace |
|---|---|---|
| `CYBERSENTINEL_WAL` | `data/runtime/wal` | Directorio del registro. **Uno por réplica** |
| `CYBERSENTINEL_WAL_FSYNC` | `interval` | `always`, `interval` o `never` |
| `CYBERSENTINEL_WAL_FSYNC_MS` | `200` | Ventana de pérdida con `interval` |
| `CYBERSENTINEL_WAL_SEGMENT` | `5000` | Registros por segmento |

```bash
# Réplica 1
CYBERSENTINEL_WAL=/var/lib/cybersentinel/wal1 cybersentinel serve --port 8443 ...
# Réplica 2
CYBERSENTINEL_WAL=/var/lib/cybersentinel/wal2 cybersentinel serve --port 8444 ...
```

El resto de rutas (`CYBERSENTINEL_DB`, `CYBERSENTINEL_IDENTITY_DB`,
`CYBERSENTINEL_AUDIT`) deben ser **las mismas** en todas las réplicas.
