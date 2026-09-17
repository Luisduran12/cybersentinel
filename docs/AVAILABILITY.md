# Disponibilidad y Resiliencia en CyberSentinel

CyberSentinel protege empresas. Debe protegerse a sí mismo.

Este documento detalla las garantías de disponibilidad del sistema, definiendo exactamente qué fallos tolera de forma automática y cuáles requieren intervención manual o rediseño a nivel de infraestructura.

**Nota importante:** Esto es resiliencia operativa de un nodo singular (o réplicas compartiendo almacenamiento), *no* es una arquitectura distribuida completa de Alta Disponibilidad (HA) multirregional.

## 1. Lo que SÍ toleramos (Resiliencia Operativa Automática)

### 1.1. Caídas del Worker Interno (Crash de Hilo)
- **Escenario:** El hilo en segundo plano que procesa eventos lanza una excepción no capturada o muere abruptamente.
- **Respuesta:** El proceso principal cuenta con un Supervisor activo (`IngestService._supervisor`) que monitorea la salud del worker cada 5 segundos. Si detecta que el worker ha muerto (y no está en estado de `draining`), lo reiniciará automáticamente.
- **Pérdida de datos:** Ninguna. Los eventos en vuelo se devuelven al estado pendiente en el Write-Ahead Log (WAL) local.

### 1.2. Interrupción Brusca del Proceso (Kill -9 / Caída de la Máquina)
- **Escenario:** El proceso de CyberSentinel muere instantáneamente sin tener tiempo de hacer un cierre limpio (Graceful Shutdown).
- **Respuesta:** Gracias a nuestro modelo estricto de Write-Ahead Log (WAL), cualquier evento que recibió un HTTP 202 (Accepted) ya está persistido en disco. Al reiniciar el proceso, el servicio lee el WAL, detecta los eventos aceptados pero no procesados, y reanuda el procesamiento desde el último punto de control (`checkpoint_seq`).
- **Pérdida de datos:** Ninguna, garantizado. El contrato del 202 es de hierro.

### 1.3. Recepción de Eventos Duplicados
- **Escenario:** Un colector o sensor envía la misma trama de datos dos veces por un reintento de red.
- **Respuesta:** El sistema es **idempotente** respecto a la creación de incidentes. Utilizamos un `event_id` determinista o proporcionado por el origen. Si se genera un incidente, su ID primario es este `event_id`. Una segunda pasada aplicará un `INSERT OR IGNORE` a nivel de base de datos SQL.
- **Pérdida de datos/Corrupción:** Ninguna. No se generan falsos duplicados en el panel del analista.

### 1.4. Fallos Temporales de Almacenamiento o Procesamiento
- **Escenario:** El almacenamiento secundario de incidentes o SQLite sufren bloqueos de I/O temporales, o la red está saturada.
- **Respuesta:** El worker tiene una política de reintentos exponencial acotada (`max_retries`). Si falla repetidas veces, el lote entero se desplaza a una cola persistida de fallidos (`dead-letters.jsonl`) para no bloquear el procesamiento del resto, y el WAL avanza para no atorarse en un bucle infinito.

## 2. Lo que NO toleramos (Límites Actuales)

- **Corrupción Física del Disco:** Si el volumen donde residen `events.db`, `incidents.db` o el directorio `wal/` se destruye sin copias de seguridad a nivel de sistema operativo, perdemos datos. No hay replicación a nivel de aplicación hacia otros nodos.
- **Escalabilidad Horizontal Múltiple (sin DB compartida):** Se pueden levantar varias réplicas de la API de CyberSentinel, PERO actualmente dependen de que SQLite opere en modo WAL sobre un volumen de red (NFS/EFS) compartido si quieren ver los mismos incidentes. La aplicación no es *stateless* a nivel de base de datos.
- **Caída Prolongada del Host:** Si el contenedor/VM entero muere, requerimos de un orquestador externo (ej. Docker Swarm, Kubernetes o systemd) para levantar de nuevo el proceso.

## 3. Apagado Ordenado (Graceful Shutdown)
El sistema soporta un endpoint administrativo `/api/v1/drain` y maneja señales `SIGTERM`.
Al iniciar un apagado ordenado:
1. Pone el estado a `draining = True`.
2. El endpoint `/health` y `/ready` responden con 503 para que el balanceador de carga deje de enviar tráfico.
3. Se espera hasta que todos los eventos actualmente encolados en memoria finalicen su procesamiento y se persistan.
4. Se libera el bloqueo exclusivo del directorio del WAL.

## 4. Métricas de Disponibilidad

El endpoint `/metrics` expone un snapshot en tiempo real con las siguientes métricas clave de resiliencia:

- `queue_depth`: Eventos esperando ser procesados en el buffer.
- `queue_utilization`: % de ocupación del buffer.
- `processing_failures`: Fallos crudos experimentados por el worker.
- `dropped_events`: Eventos movidos a dead-letters (se rindió el worker).
- `retries`: Contador total de reintentos de procesamiento.
- `recovery_time_ms`: Tiempo (en ms) que tardó la operación de recuperación de WAL en el último arranque.
- `uptime`: Segundos desde que el servicio arrancó.
