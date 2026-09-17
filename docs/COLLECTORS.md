# Collectors empresariales

Cuatro collectors traducen telemetría real a `SecurityEvent`. Ese es **todo** el
contrato: ninguno de ellos obliga a tocar Sigma, Isolation Forest, Markov ni la
correlación temporal. Hay una prueba que lo verifica inspeccionando los imports
reales con `ast` (`test_ningun_collector_obliga_a_tocar_el_motor`), no buscando
subcadenas.

```
telemetría cruda → Collector.collect() → SecurityEvent → Normalizer → Pipeline
```

| Collector | `source_type` | Entradas aceptadas |
|---|---|---|
| `SysmonCollector`  | `sysmon`   | Sysmon JSON (winlogbeat/NXLog) y XML `<Event>` nativo |
| `LinuxCollector`   | `linux`    | journald JSON, syslog RFC3164, auditd |
| `FirewallCollector`| `firewall` | syslog `clave=valor` y JSON de Palo Alto, Fortinet, pfSense, iptables, Zeek |
| `SuricataCollector`| `suricata` | EVE JSON (`alert`, `flow`) |

## Políticas comunes (`base.py`)

Están en la clase base a propósito: si cada collector decidiera por su cuenta qué
hacer con un payload gigante, el comportamiento del sistema dependería de la
fuente que lo alimenta.

- **`collect()` nunca lanza excepción.** Un registro corrupto devuelve un
  `CollectorResult` con errores. Una fuente no debe poder detener la ingesta.
- **Payloads > 5 MiB se rechazan** (`MAX_PAYLOAD_BYTES`) con la etiqueta
  `payload_excesivo`, antes de intentar parsear.
- **La decodificación de bytes prueba UTF-8 y, si falla, cae a Latin-1**
  (`Collector.decode_bytes`) en vez de sustituir los bytes inválidos por `�`:
  Latin-1 nunca lanza `UnicodeDecodeError`, así que es el último recurso antes
  de perder el dato.
- **Campos > 8.192 caracteres se truncan** (`MAX_FIELD_CHARS`) con la etiqueta
  `campo_truncado`. El truncado queda declarado, no oculto.
- **Un timestamp ilegible no se inventa**: se usa la hora de ingesta y se marca
  `timestamp_invalido`. Una marca temporal falsa y silenciosa corrompe la
  correlación temporal, que es precisamente lo que mide ventanas.
- **El registro original se conserva** en `properties["raw"]`.
- Cada collector lleva un contador `stats` con procesados, fallidos y descartados.

---

## Limitaciones conocidas

Están aquí porque un collector que parece entender más de lo que entiende es
peor que uno que declara sus límites.

### SysmonCollector

- Cubre **19 Event IDs** (1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17, 18,
  22, 23, 25). Un ID fuera del mapa produce un evento con `category="process"`
  genérica en lugar de fallar, pero **sin** semántica específica.
- El XML se aplana **ignorando el namespace**. Es robusto frente a cambios de
  esquema, pero dos campos homónimos en namespaces distintos colisionarían.
- No reconstruye árboles de procesos entre eventos: cada registro se traduce de
  forma independiente. La relación padre-hijo queda en `properties`, sin resolver.
- No descifra ni decodifica `-enc`; el comando ofuscado llega tal cual a las
  reglas, que es lo que estas esperan.
- Los canales que no son `Microsoft-Windows-Sysmon/Operational` (Security 4624,
  4625…) **no** están mapeados.

### LinuxCollector

- El formato RFC3164 **no lleva año**. Se asume el año en curso, o el anterior si
  eso situara el evento en el futuro. En un archivo histórico de más de 12 meses
  la fecha será incorrecta: use journald JSON, que sí lleva año.
- La clasificación (`category`, `action`, `outcome`) se infiere de **texto** con
  listas de tokens (`AUTH_FAIL` / `AUTH_OK`). Funciona con los mensajes habituales
  de sshd/sudo/PAM en inglés; un demonio con mensajes propios o en otro idioma
  cae en la categoría genérica.
- De auditd se parsean pares clave-valor con `shlex`, pero **no** se decodifican
  los campos hexadecimales (`a0=2f62696e`) ni se correlacionan los múltiples
  registros que comparten `msg=audit(...:serial)`. Cada línea es un evento.
- No hay soporte para syslog RFC5424 estructurado ni para `journalctl -o export`.

### FirewallCollector

- Es **agnóstico por sinónimos**, no por vendedor: mapea nombres de campo
  conocidos a campos lógicos. Un firewall con nomenclatura propia fuera del
  diccionario `SINONIMOS` producirá un evento con `src_ip`/`dst_port` vacíos, y
  el resto en `properties`. Añadir soporte es añadir sinónimos, no código.
- No se interpretan **reglas ni políticas**: el nombre de la regla del vendedor
  se conserva como dato, sin traducirse a semántica.
- Fortinet parte la marca temporal en `date=` y `time=`; se recompone. Los que
  emiten epoch o ISO se leen directamente. Cualquier otro formato cae en
  `timestamp_invalido`.
- **Las zonas horarias no se infieren**: un log sin desplazamiento explícito se
  interpreta como UTC. En un despliegue con dispositivos en hora local esto
  desplaza las ventanas de correlación.
- Los contadores de bytes se toman tal como los declara el dispositivo; no se
  distingue si son de la sesión completa o acumulados.

### SuricataCollector

- Solo `event_type` **`alert` y `flow`**. `dns`, `http`, `tls`, `fileinfo` y
  `anomaly` se ignoran; enriquecerían el contexto pero no están implementados.
- Suricata **ya ha decidido**. Su firma se conserva en `command_line` y se marca
  `properties["detected_by"] = "suricata"` para no atribuir a CyberSentinel una
  detección de otro sistema. Esa distinción importa al medir: sin ella, la
  precisión del sistema incluiría aciertos ajenos.
- La severidad se traduce con el mapa fijo `1→critical … 4→low`. Una instalación
  que reasigne severidades en sus reglas obtendrá una traducción incorrecta.
- No se consultan las reglas ni los metadatos de las firmas: no hay mapeo
  automático de firma a técnica ATT&CK.
- El `flow` se traduce como evento de red sin veredicto: no se marca como
  detección.

---

## Pruebas

`tests/test_collectors.py` — 44 pruebas.

- **E2E por collector**: telemetría real de cada formato atravesando el `Pipeline`
  real hasta producir evidencia. RAG y LLM se desactivan **solo** por tiempo de
  ejecución; Sigma, ML y correlación corren de verdad.
- **Negativas, parametrizadas sobre los cuatro**: evento corrupto, campo
  obligatorio ausente, timestamp inválido, payload excesivo (con el límite real
  de 5 MiB, no uno rebajado para la prueba) y encoding inválido (Latin-1) sin
  perder el dato.
- **Idempotencia end-to-end**: `test_evento_duplicado_se_procesa_pero_no_duplica_el_incidente`
  en `tests/test_api_ingestion.py` envía el mismo `event_id` dos veces por
  `POST /api/v1/events` real y comprueba en el `IncidentStore` que solo existe
  un incidente — no solo que la huella del collector sea estable.
- **Cobertura de campos que el contrato original no exponía**: `uid`, `gid`,
  `file_path`, `dst_ip`, `dst_port` y `return_code` en `LinuxCollector`
  (auditd `SYSCALL`/`PATH`/`NETFILTER_PKT` y journald), y `packets_in`/
  `packets_out` en `FirewallCollector`. Todos viven en `properties`, no en el
  esquema de `SecurityEvent`, siguiendo el mismo patrón que ya usaban los
  `hashes` de Sysmon.
- **Independencia del motor**: inspección de imports con `ast`.
