# SIGMA-EXCLUSIONS.md — Reglas Sigma candidatas descartadas

**Versión:** 1.0 | **Fecha:** 2026-09-14 | **Fase:** 1 Parte 2

Documento de auditoría: registra explícitamente todas las reglas Sigma
candidatas que fueron evaluadas y rechazadas, junto con la razón exacta.
**Ninguna regla se descarta en silencio.**

---

## Criterios de selección (referencia)

Una regla pasa si cumple TODOS los criterios:

| # | Criterio |
|---|---|
| 1 | YAML válido y parseable por pySigma 1.5.0 |
| 2 | `id` UUID estable y verificable |
| 3 | `tags: attack.tXXXX` identificable |
| 4 | `status: stable` o `test` con madurez documentada |
| 5 | Solo usa campos disponibles en SecurityEvent (ver SIGMA-COMPATIBILITY-MATRIX.md) |
| 6 | No duplica táctica ya cubierta sin añadir valor diferencial |

---

## Reglas rechazadas por criterio 5 (campo no disponible en SecurityEvent)

### Grupo A — Campos de token Windows (Privilege Escalation / Defense Evasion)

Estas reglas requieren campos del token de acceso Windows (`IntegrityLevel`,
`TokenElevationType`, `LogonType`, `AccessMask`) que no están presentes en
`SecurityEvent`. Requieren Windows Event Log EventID 4688/4624/4625/4656 con
campos completos — nuestro normalizador no los captura.

**Tácticas afectadas:** Privilege Escalation, Defense Evasion (sub-category token)

| Regla candidata | Campo Sigma faltante | MITRE |
|---|---|---|
| proc_creation_win_uac_bypass_*.yml (familia) | `IntegrityLevel` | T1548.002 |
| proc_creation_win_token_impersonation.yml | `TokenElevationType` | T1134.001 |
| win_security_token_theft.yml | `AccessMask` | T1134 |
| win_security_susp_logon_types.yml | `LogonType` | T1078 |

**Decisión:** NOT_EVALUABLE. No se selecciona ninguna regla de esta familia.
Documentar como brecha de cobertura en la matriz de compatibilidad.

---

### Grupo B — Hash de proceso y firma digital

Requieren campos `Hashes`, `Imphash`, `Signature`, `SignatureStatus` de Sysmon
EventID 1. SecurityEvent no incluye hashes de proceso ni información de firma.

**Tácticas afectadas:** Defense Evasion (DLL hijacking, signed binary proxy)

| Regla candidata | Campo Sigma faltante | MITRE |
|---|---|---|
| proc_creation_win_*.yml con Imphash | `Imphash` | T1574.001 |
| proc_creation_win_signed_binary_proxy_execution.yml | `Signature` | T1218 |
| proc_creation_win_pe_injection*.yml | `Hashes` | T1055 |

**Decisión:** NOT_EVALUABLE. Requiere enriquecimiento de PE hash que no existe
en el esquema actual de SecurityEvent.

---

### Grupo C — Eventos de archivo (file_event)

Requieren `TargetFilename`, `TargetFileExtension`, campos de logsource
`file_event`. SecurityEvent no captura eventos de creación/modificación de
archivos en esta versión.

**Tácticas afectadas:** Defense Evasion (timestomping), Persistence (startup
folder), Collection (file staging)

| Regla candidata | Campo Sigma faltante | MITRE |
|---|---|---|
| file_event_win_timestomp.yml | `TargetFilename` | T1070.006 |
| file_event_win_startup_folder.yml | `TargetFilename` | T1547.001 |
| file_event_win_lsass_dump*.yml | `TargetFilename` | T1003.001 |

**Decisión:** NOT_EVALUABLE. Requiere categoría `file_event` no soportada
en la capa de ingesta actual.

---

### Grupo D — Events de registro Windows (registry_event)

Requieren `TargetObject`, `Details`, `EventType` del registro de Windows.
SecurityEvent no captura cambios de registro.

**Tácticas afectadas:** Persistence (Run keys), Defense Evasion (registry
modification), Privilege Escalation

| Regla candidata | Campo Sigma faltante | MITRE |
|---|---|---|
| registry_event_persistence_run_key.yml | `TargetObject` | T1547.001 |
| registry_event_disable_defender.yml | `TargetObject` | T1562.001 |
| registry_set_uac_bypass.yml | `Details` | T1548.002 |

**Decisión:** NOT_EVALUABLE. Requiere `registry_event` logsource category
no implementada.

---

### Grupo E — Eventos de red con campos DNS / hostname

Requieren `QueryName`, `DestinationHostname`, campos de resolución DNS.
SecurityEvent solo tiene `dst_ip` (dirección IP resuelta, si la hay).

**Tácticas afectadas:** Command and Control (T1071.004 DNS, T1568 Dynamic Resolution)

| Regla candidata | Campo Sigma faltante | MITRE |
|---|---|---|
| net_dns_query_c2.yml | `QueryName` | T1071.004 |
| net_connection_dns_over_https.yml | `DestinationHostname` | T1071.004 |
| net_dns_susp_mx_record.yml | `QueryName` | T1568 |

**Decisión:** NOT_EVALUABLE. `DestinationHostname` y `QueryName` no están
presentes en SecurityEvent. Se requeriría un parser DNS dedicado.

---

## Reglas rechazadas por criterio 3 (sin tag ATT&CK o tag inválido)

Algunas reglas SigmaHQ tienen `tags: []` o solo tags de fuente (`tlp.green`)
sin técnica MITRE. Sin técnica no podemos calcular cobertura ni alimentar
al correlador MITRE.

**Ejemplo:** `proc_creation_win_hktl_*.yml` (herramientas específicas de hacking
sin mapeo canónico ATT&CK oficial). Rechazadas por criterio 3.

---

## Reglas rechazadas por criterio 4 (aggregation Sigma / `count()`)

pySigma 1.5.0 genera un `ConditionSelector` para reglas con `count() by field > N`.
Nuestro evaluador AST no soporta aggregation Sigma (solo aggregation nativa de
CyberSentinel en RULE-0001 a RULE-0007). Estas reglas fallan con un error de
parseo del AST y se registran como NOT_EVALUABLE.

**Ejemplo:**
```yaml
condition: selection | count(TargetUserName) by ComputerName > 10
```
Esta sintaxis produce `ConditionSelector` (no soportada) en vez del árbol
AND/OR/NOT estándar.

**Tácticas afectadas:** Credential Access (brute force con count), Discovery (recon
patterns with threshold), Impact (high-volume actions).

**Decisión:** NOT_EVALUABLE en esta fase. La aggregation Sigma podría soportarse
en Fase 2 mediante un pre-procesador de ventana deslizante.

---

## Reglas rechazadas por criterio 6 (duplicación sin valor diferencial)

Las siguientes reglas cubren la misma táctica/técnica con el mismo campo y
operador que una regla ya seleccionada, sin añadir contexto diferencial:

| Regla candidata | Duplica | Razón del rechazo |
|---|---|---|
| proc_creation_win_powershell_b64.yml | cs-ps-encoded-cmd.yml | Mismo CommandLine|re, más estrecho |
| proc_creation_win_net_scan.yml | cs-net-recon.yml | Subconjunto del cs-net-recon |
| win_susp_certutil_verifyctl.yml | cs-certutil-download.yml | Subconjunto de flags |

---

## Tácticas sin cobertura (NOT EVALUABLE — falta de telemetría)

| Táctica MITRE | Razón | Cobertura posible en futuro |
|---|---|---|
| Initial Access | Requiere email/web delivery metadata | Integrar SMTP parser, proxy logs |
| Privilege Escalation | Requiere token/integrity fields | Sysmon EventID 4688 completo |
| Collection | Requiere file/clipboard/screen events | File event logging pipeline |
| Impact | Requiere disk/encryption events | System-level agent |
| Resource Development | Sin telemetría interna | Out of scope (OSINT/external) |

---

*Este documento se actualiza con cada selección de reglas. Nunca se descarta
una regla sin registrarla aquí.*
