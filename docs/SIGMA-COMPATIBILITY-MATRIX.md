# SIGMA ↔ CyberSentinel — Matriz de Compatibilidad (FASE 1)

> **Estado**: Solo lectura / análisis. Ningún código de producción fue modificado.  
> **Fecha de inspección**: 2026-09-14  
> **Versiones inspeccionadas**: `schema.py` · `detection/rules_engine.py` · `config/rules/` (7 reglas) · `tests/`

---

## 1. Interfaz pública de `RulesEngine` — contrato que NO se puede romper

### 1.1 Constructores

| Firma | Descripción |
|---|---|
| `RulesEngine(rules: list[DetectionRule] \| None = None)` | Instanciación directa con reglas ya construidas |
| `RulesEngine.from_directory(directory: str \| Path) → RulesEngine` | **Método de fábrica principal**: carga todos los `.yaml`/`.yml` del directorio |

### 1.2 Métodos públicos de evaluación

| Firma | Entrada | Salida | Notas |
|---|---|---|---|
| `evaluate_event(event: SecurityEvent) → list[RuleHit]` | Un solo `SecurityEvent` | Lista de `RuleHit` (puede ser vacía) | Solo evalúa reglas **stateless** (sin `aggregation`) |
| `evaluate(events: list[SecurityEvent]) → list[RuleHit]` | Lista de `SecurityEvent` | Lista de `RuleHit` (puede ser vacía) | Evalúa stateless **y** reglas con `aggregation` |

### 1.3 Propiedades públicas (read-only)

| Propiedad | Tipo | Semántica |
|---|---|---|
| `rules` | `list[DetectionRule]` | Todas las reglas cargadas |
| `stateless_rules` | `list[DetectionRule]` | Reglas sin `aggregation` |
| `aggregated_rules` | `list[DetectionRule]` | Reglas con `aggregation` |

### 1.4 Cómo se cargan las reglas hoy

```
RulesEngine.from_directory(path)
  └─ sorted(path.glob("*.y*ml"))           ← orden alfabético
       └─ yaml.safe_load(file)
            └─ DetectionRule.from_dict(data)
                 ├─ Resolución de táctica via mitre.tactics_of(technique)
                 ├─ Construcción de Aggregation si existe la clave "aggregation"
                 └─ Severity(d.get("severity", "medium"))
```

Los campos YAML obligatorios para que `from_dict` no falle son: `id`, `title`.  
Los demás tienen valores por defecto (`description=""`, `severity="medium"`, `conditions=[]`).

### 1.5 Flujo interno de evaluación de un evento

```
evaluate_event(event)
  └─ for rule in stateless_rules:
       └─ all(_match_condition(event, cond) for cond in rule.conditions)
            └─ _field_value(event, field_name)
                 ├─ getattr(event, field_name, None)   ← campos tipados de SecurityEvent
                 └─ event.raw.get(field_name)           ← fallback en el dict crudo
            └─ Operadores: equals | in | contains | contains_any | regex | not_regex | gt | lt
                 (todo comparado en lowercase)
       → RuleHit(rule, event, confidence=_base_confidence(rule))

evaluate(events)
  ├─ evaluate_event(e) for each event   ← stateless
  └─ _evaluate_aggregated(rule, events) for each aggregated_rule
       ├─ Filtra eventos que cumplen todas las condiciones
       ├─ Agrupa por group_by (usando _field_value)
       ├─ Ventana deslizante sobre cada grupo (ordenado por timestamp)
       └─ RuleHit con match_count y related_fingerprints cuando len(window) >= agg.count
```

### 1.6 Cálculo de `confidence`

```python
_base_confidence(rule) = min(0.5 + (rule.severity.score / 200.0), 0.99)
# INFO=0.5, LOW=0.625, MEDIUM=0.75, HIGH=0.875, CRITICAL=0.99

# En reglas agregadas se suma un bonus:
confidence = min(_base_confidence(rule) + 0.02 * (len(window) - agg.count), 0.99)
```

---

## 2. Estructura exacta de `SecurityEvent`

```python
@dataclass
class SecurityEvent:
    # ── Identidad y tiempo (OBLIGATORIOS) ──────────────────────────────────
    event_id:       str              # UUID/ID único del evento
    timestamp:      datetime         # timezone-aware (UTC)
    source:         str              # "sysmon" | "auth" | "firewall" | "web" | "netflow"
    category:       str              # "process" | "authentication" | "network" | "file" | "dns" | "web"
    action:         str              # descripción corta: "process_create", "user_login", etc.

    # ── Host / Usuario (OPCIONALES) ────────────────────────────────────────
    host:           Optional[str]    # nombre del host
    user:           Optional[str]    # nombre de usuario

    # ── Red (OPCIONALES) ───────────────────────────────────────────────────
    src_ip:         Optional[str]    # IP de origen
    dst_ip:         Optional[str]    # IP de destino
    src_port:       Optional[int]    # puerto de origen
    dst_port:       Optional[int]    # puerto de destino
    protocol:       Optional[str]    # "tcp" | "udp" | "icmp" | etc.
    bytes_out:      Optional[int]    # bytes enviados
    bytes_in:       Optional[int]    # bytes recibidos

    # ── Proceso (OPCIONALES) ──────────────────────────────────────────────
    process_name:   Optional[str]    # nombre del ejecutable
    command_line:   Optional[str]    # línea de comando completa (también usada para URL en eventos web)
    parent_process: Optional[str]    # nombre del proceso padre

    # ── Resultado (OPCIONAL) ──────────────────────────────────────────────
    outcome:        Optional[str]    # "success" | "failure" | "unknown"

    # ── Metadatos libres (OPCIONALES) ─────────────────────────────────────
    raw:            dict[str, Any]   # campos crudos del normalizador original (fallback en _field_value)
    tags:           list[str]        # etiquetas libres (p.ej. "timestamp_invalido")
```

**Métodos relevantes para integración:**

| Método | Firma | Uso |
|---|---|---|
| `fingerprint()` | `→ str` (16 hex chars) | Deduplicación; base de `related_fingerprints` en `RuleHit` |
| `to_dict()` | `→ dict[str, Any]` | Serialización; `timestamp` como ISO string |
| `to_json()` | `→ str` | JSON completo del evento |

---

## 3. Objetos de salida: `RuleHit` y estructura serializada

### 3.1 `RuleHit`

```python
@dataclass
class RuleHit:
    rule:                  DetectionRule   # la regla que coincidió (referencia completa)
    event:                 SecurityEvent   # el evento ancla que cerró la ventana
    confidence:            float           # [0.5, 0.99] — ver fórmula en §1.6
    match_count:           int = 1         # N de eventos que cumplieron las condiciones (reglas agregadas)
    related_fingerprints:  list[str]       # fingerprints de los N-1 eventos previos (ventana)
```

### 3.2 `RuleHit.to_dict()` — forma serializada

```json
{
  "rule_id":              "RULE-0001",
  "title":               "Fuerza bruta de autenticacion",
  "severity":            "high",
  "mitre_technique":     "T1110",
  "mitre_tactic":        "credential-access",
  "confidence":          0.875,
  "event_fingerprint":   "a1b2c3d4e5f6g7h8",
  "match_count":         6,
  "related_fingerprints": ["fp1", "fp2", "fp3", "fp4", "fp5"]
}
```

> **Nota**: No existe un objeto `DetectionResult` independiente en producción.  
> El resultado compuesto del pipeline es `PipelineReport → list[IncidentResult] → Incident`.

---

## 4. Matriz de Compatibilidad Sigma ↔ SecurityEvent

### 4.1 Mapa de campos Sigma → SecurityEvent

| Campo Sigma | Categoría Sigma | Campo SecurityEvent | Estado | Notas |
|---|---|---|---|---|
| `EventID` | Windows | ❌ **AUSENTE** | NO COMPATIBLE | Sin telemetría de Windows Event Log |
| `Channel` | Windows | ❌ **AUSENTE** | NO COMPATIBLE | Sin canal WEL |
| `Image` | process_creation | `process_name` | ⚠️ PARCIAL | `Image` es ruta completa; `process_name` solo nombre base |
| `CommandLine` | process_creation | `command_line` | ✅ COMPATIBLE | Mapeo directo, usada en RULE-0002/0003/0004 |
| `ParentImage` | process_creation | `parent_process` | ⚠️ PARCIAL | `ParentImage` = ruta completa; `parent_process` = solo nombre |
| `ParentCommandLine` | process_creation | ❌ **AUSENTE** | NO COMPATIBLE | No se captura la CLI del proceso padre |
| `OriginalFileName` | process_creation | ❌ **AUSENTE** | NO COMPATIBLE | Metadato PE del binario; no disponible |
| `Hashes` / `sha256` | process_creation | ❌ **AUSENTE** | NO COMPATIBLE | Sin hash de proceso |
| `IntegrityLevel` | process_creation | ❌ **AUSENTE** | NO COMPATIBLE | Solo Windows, sin Sysmon real |
| `CurrentDirectory` | process_creation | ❌ **AUSENTE** | NO COMPATIBLE | Sin directorio de trabajo |
| `User` (proceso) | process_creation | `user` | ✅ COMPATIBLE | Mapeo directo |
| `LogonId` | process_creation | ❌ **AUSENTE** | NO COMPATIBLE | ID de sesión de logon |
| `TargetUsername` | authentication | `user` | ⚠️ PARCIAL | Solo hay un campo `user`; no distingue origen/destino |
| `SubjectUserName` | authentication | ❌ **AUSENTE** | NO COMPATIBLE | Usuario que inició la acción |
| `WorkstationName` | authentication | `host` | ⚠️ PARCIAL | Nombre del host, no distingue rol |
| `LogonType` | authentication | ❌ **AUSENTE** | NO COMPATIBLE | Tipo de logon (interactive, network, batch…) |
| `IpAddress` (auth) | authentication | `src_ip` | ✅ COMPATIBLE | Mapeo directo |
| `Status` / `SubStatus` | authentication | `outcome` | ⚠️ PARCIAL | `outcome` es éxito/fallo; `Status` tiene códigos NTSTATUS |
| `DestinationIp` | network | `dst_ip` | ✅ COMPATIBLE | Mapeo directo |
| `SourceIp` | network | `src_ip` | ✅ COMPATIBLE | Mapeo directo |
| `DestinationPort` | network | `dst_port` | ✅ COMPATIBLE | Mapeo directo, usado en RULE-0005/0006 |
| `SourcePort` | network | `src_port` | ✅ COMPATIBLE | Mapeo directo |
| `Protocol` | network | `protocol` | ✅ COMPATIBLE | Mapeo directo |
| `Initiated` | network | ❌ **AUSENTE** | NO COMPATIBLE | Dirección de la conexión (inbound/outbound) |
| `DestinationHostname` | network | ❌ **AUSENTE** | NO COMPATIBLE | Sin resolución DNS inversa |
| `RuleName` | Sysmon | ❌ **AUSENTE** | NO COMPATIBLE | Nombre de regla del propio Sysmon |
| `TargetFilename` | file_event | ❌ **AUSENTE** | NO COMPATIBLE | Sin telemetría de ficheros |
| `TargetObject` | registry | ❌ **AUSENTE** | NO COMPATIBLE | Sin telemetría de registro Windows |
| `Details` | registry | ❌ **AUSENTE** | NO COMPATIBLE | Sin telemetría de registro Windows |
| `QueryName` | dns | ❌ **AUSENTE** | NO COMPATIBLE | Sin telemetría DNS estructurada |
| `QueryResults` | dns | ❌ **AUSENTE** | NO COMPATIBLE | Sin telemetría DNS estructurada |
| `cs-uri-stem` / `cs-uri-query` | webserver | `command_line` | ⚠️ PARCIAL | El normalizador reutiliza `command_line` para URLs |
| `sc-status` | webserver | `outcome` | ⚠️ PARCIAL | `outcome` no guarda el código HTTP numérico |
| `c-useragent` | webserver | ❌ **AUSENTE** | NO COMPATIBLE | Sin User-Agent HTTP |
| `BytesOut` | network | `bytes_out` | ✅ COMPATIBLE | Mapeo directo, usado en RULE-0007 |
| `BytesIn` | network | `bytes_in` | ✅ COMPATIBLE | Mapeo directo |

### 4.2 Campos Sigma con soporte parcial vía `event.raw`

`_field_value()` tiene un fallback a `event.raw.get(field_name)`. Esto significa que si el normalizador preserva un campo bajo su nombre original en `raw`, las condiciones Sigma pueden evaluarlo. Sin embargo:

- Esta posibilidad **no está documentada ni garantizada** por el contrato de `SecurityEvent`.
- El nombre del campo en `raw` depende del normalizador concreto, no del esquema Sigma.
- **No se debe asumir disponibilidad** sin verificar cada normalizador.

---

## 5. Clasificación de reglas Sigma por tipo

### COMPATIBLES ✅ — Evaluables con la telemetría actual

| Categoría Sigma | Campos requeridos | Disponibles en SecurityEvent |
|---|---|---|
| `process_creation` (solo CommandLine + User) | `CommandLine`, `User`, `category="process"` | `command_line`, `user`, `category` |
| `network_connection` (IP + puerto) | `DestinationIp`, `DestinationPort`, `SourceIp` | `dst_ip`, `dst_port`, `src_ip` |
| `network_connection` (bytes/volumen) | `BytesOut`, `BytesIn` | `bytes_out`, `bytes_in` |
| `failed_logon` (brute-force por volumen) | `outcome`, `src_ip`, `user` | `outcome`, `src_ip`, `user` |

### PARCIALMENTE COMPATIBLES ⚠️

| Categoría Sigma | Problema | Campos ausentes clave |
|---|---|---|
| `process_creation` (con ruta completa o hash) | `Image` solo tiene nombre de proceso, no ruta | `OriginalFileName`, `Hashes`, `CurrentDirectory` |
| `process_creation` (cadena padre-hijo) | `parent_process` solo tiene nombre, no ruta completa | `ParentCommandLine`, `IntegrityLevel` |
| `authentication` (Windows) | `outcome` no tiene códigos NTSTATUS; no hay LogonType | `LogonType`, `SubjectUserName`, `Status` |
| `webserver` (HTTP avanzado) | No hay User-Agent ni código HTTP numérico | `c-useragent`, `sc-status` numérico |

### NO COMPATIBLES ❌ — Requieren telemetría inexistente

| Categoría Sigma | Razón de incompatibilidad |
|---|---|
| `windows/process_creation` con `EventID` | Sin Windows Event Log; sin canal, sin LogonId |
| `windows/registry_*` | Sin telemetría de registro (TargetObject, Details) |
| `windows/file_event` | Sin telemetría de operaciones de fichero (TargetFilename) |
| `windows/create_stream_hash` | Sin Alternate Data Streams |
| `dns` | Sin telemetría DNS estructurada (QueryName, QueryResults) |
| `proxy` | Sin proxy logs (c-useragent, cs-method completo) |
| `antivirus` | Sin telemetría de AV/EDR |
| `cloud/aws`, `cloud/azure`, `cloud/gcp` | Sin integración con logs cloud |
| `linux/auditd` | Sin telemetría de auditd |
| `powershell/scriptblock` | Sin Script Block Logging (EventID 4104) |

---

## 6. Campos Sigma que NO podemos soportar hoy y por qué

| Campo | Por qué no disponible |
|---|---|
| `EventID` | No consumimos Windows Event Log. Sin Sysmon real conectado. |
| `Channel` | Ídem; sin canal WEL. |
| `LogonType` | Requiere fuente `Security` WEL (EventID 4624/4625). |
| `TargetFilename` | Sin Sysmon Event 11 (FileCreate) ni equivalente. |
| `TargetObject` / `Details` | Sin Sysmon Event 12/13/14 (Registry). |
| `QueryName` / `QueryResults` | Sin Sysmon Event 22 (DNSEvent) ni resolver DNS local. |
| `Hashes` / `sha256` | No se calcula hash de proceso en la ingesta actual. |
| `ParentCommandLine` | El normalizador no captura la CLI del padre, solo su nombre. |
| `OriginalFileName` | Requiere lectura de metadatos PE del binario. |
| `IntegrityLevel` | Campo de token de Windows; sin acceso a él. |
| `DestinationHostname` | Sin resolución DNS inversa en la ingesta. |
| `RuleName` (Sysmon) | Sin Sysmon real; campo de configuración interna de Sysmon. |
| `c-useragent` | Sin parser de HTTP headers; User-Agent no se extrae. |
| `sc-status` numérico | `outcome` solo tiene `success`/`failure`/`unknown`, no códigos HTTP. |
| `SubjectUserName` | Un solo campo `user`; no distingue quién actúa vs. sobre quién. |
| `LogonId` | Sin contexto de sesión de logon de Windows. |
| `CurrentDirectory` | El normalizador no captura el directorio de trabajo del proceso. |

---

## 7. Tácticas ATT&CK fuera de alcance por falta de telemetría

| Táctica ATT&CK | Por qué queda fuera |
|---|---|
| **Resource Development** (TA0042) | Actividad en infraestructura del atacante; no hay telemetría interna. |
| **Initial Access** (TA0001) — phishing, supply chain | Requiere logs de email, proxy con User-Agent, script block logging. |
| **Defense Evasion** (TA0005) — timestomping, LOLBAS vía DLL | Sin hash, sin OriginalFileName, sin telemetría de fichero. |
| **Credential Access** (TA0006) — LSASS dump, DCSync | Sin Sysmon Event 10 (ProcessAccess) ni tráfico NTLM/Kerberos. |
| **Privilege Escalation** (TA0004) — token manipulation, UAC bypass | Sin IntegrityLevel, sin evento de impersonación. |
| **Collection** (TA0009) — clipboard, screen capture, audio | Sin telemetría de dispositivos ni de APIs de captura. |
| **Impact** (TA0040) — ransomware, disk wipe | Sin telemetría de operaciones de fichero masivas. |
| **Persistence** vía Registry (TA0003) | Sin telemetría de registro Windows. |

**Tácticas con cobertura real hoy** (parcial):

| Táctica | Técnicas cubiertas | Regla |
|---|---|---|
| Credential Access | T1110 (Brute Force) | RULE-0001 |
| Execution | T1059 (Command Scripting) | RULE-0002 |
| Persistence | T1053 (Scheduled Task) | RULE-0003 |
| Discovery | T1046 (Network Scan) | RULE-0004 |
| Lateral Movement | T1021 (Remote Services/RDP) | RULE-0005 |
| Command & Control | T1071 (App Layer Protocol) | RULE-0006 |
| Exfiltration | T1048 (Alt Protocol/volumen) | RULE-0007 |

---

## 8. Contrato inviolable de `RulesEngine` — resumen para integradores

```python
# ─── Firmas que NO se pueden cambiar ──────────────────────────────────────────
RulesEngine(rules: list[DetectionRule] | None = None)
RulesEngine.from_directory(directory: str | Path) → RulesEngine
RulesEngine.evaluate_event(event: SecurityEvent)  → list[RuleHit]
RulesEngine.evaluate(events: list[SecurityEvent]) → list[RuleHit]

# ─── Atributos de RuleHit que consumen correlación/tests ──────────────────────
RuleHit.rule:                 DetectionRule
RuleHit.event:                SecurityEvent
RuleHit.confidence:           float
RuleHit.match_count:          int
RuleHit.related_fingerprints: list[str]
RuleHit.to_dict()            → dict[str, Any]

# ─── Exportaciones públicas del paquete detection ─────────────────────────────
from cybersentinel.detection import RulesEngine, DetectionRule, RuleHit
from cybersentinel.detection import AnomalyDetector, AnomalyResult, severity_from_anomaly
```

**Consumidores del contrato (deben mantenerse sincronizados en cualquier cambio):**
- `pipeline.py` → `self.rules_engine.evaluate(events)`
- `test_detection_quality.py` → `evaluate_event()` y `evaluate()` directamente
- `test_pipeline.py` → vía `Pipeline.run_events()`
- `correlation/` → consume `list[RuleHit]` desde `correlator.build_findings(rule_hits, ...)`

---

*Documento generado en FASE 1 — Solo inspección. Sin modificaciones de código de producción.*
