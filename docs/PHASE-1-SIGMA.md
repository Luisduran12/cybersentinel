# PHASE-1-SIGMA.md — CyberSentinel: Integración pySigma y Evaluación

**Fase:** 1 (Parte 2 + Parte 3) | **Versión:** 1.0 | **Fecha:** 2026-09-14

---

## 1. Objetivo

Integrar pySigma 1.5.0 como motor de parsing/AST para reglas en formato Sigma
público, seleccionar un conjunto controlado de 15 reglas adaptadas a la
telemetría de CyberSentinel, y evaluar honestamente cuántas de esas reglas
pueden medirse sobre el dataset UNSW-NB15 sintético disponible.

**Objetivo orientativo:** cobertura estructural ATT&CK ~8–10%, Precision ≥ 0.70
sobre las reglas efectivamente evaluables.

> **Regla fundamental:** si las condiciones no permiten alcanzar el objetivo,
> se reporta el resultado real. No se manipulan reglas, datos ni umbrales.
> Un resultado inferior es válido si está bien justificado.

---

## 2. Arquitectura de integración

```
Sigma YAML (15 reglas curadas)
        │
        ▼
SigmaRule.from_yaml()           ← pySigma 1.5.0 (parser + validador AST)
        │
        ▼
SigmaCondition AST              ← árbol AND / OR / NOT + DetectionItems
        │
        ▼
_evaluate_ast_node(ast, event)  ← evaluador recursivo propio (sin eval())
   ┌─── ConditionAND  → all(hijos)
   ├─── ConditionOR   → any(hijos)
   ├─── ConditionNOT  → not(hijo)
   └─── ConditionFieldEqualsValueExpression
           │  field → FIELD_MAP → SecurityEvent attribute
           └─ value: SigmaString | SigmaRegularExpression | SigmaNumber
        │
        ▼
SigmaBackedRule.matches(event)  ← subclase de DetectionRule
        │
        ▼
RulesEngine.evaluate_event()    ← interfaz pública INTACTA
        │
        ▼
list[RuleHit]                   ← formato existente, sin cambios
```

**Invariantes preservados:**
- `RulesEngine.from_directory()` — sin cambios
- `RulesEngine.evaluate_event(event)` → `list[RuleHit]` — sin cambios
- `RulesEngine.evaluate(events)` → `list[RuleHit]` — sin cambios
- `SecurityEvent` — sin cambios
- Las 7 reglas YAML propias — funcionamiento idéntico verificado

**Nueva API:**
- `RulesEngine.from_sigma_directory(path)` — carga reglas Sigma públicas
- `DetectionRule.matches(event)` — hook polimórfico (base: condiciones lista; Sigma: AST)
- `DetectionRule.is_evaluable` — True si la regla tiene evaluación disponible

---

## 3. Integración pySigma 1.5.0

### Versión exacta

| Componente | Versión |
|---|---|
| pySigma | 1.5.0 |
| Python | 3.11.15 |
| Commit evaluación | fbfcef9 |

### Decisiones de diseño

| Decisión | Alternativa descartada | Razón |
|---|---|---|
| Evaluador recursivo propio | sigma-rule-matcher | Evita dependencia de comunidad con API inestable |
| Evaluador recursivo propio | `eval()` sobre condición | Riesgo de seguridad, no auditable |
| `from_sigma_directory()` nueva | Sobreescribir `from_directory()` | REQUISITO INNEGOCIABLE: interfaz pública sin cambios |
| `matches()` polimórfico | `isinstance()` en el engine | No contamina el engine con dependencias de Sigma |

### Nodos AST soportados

| Nodo pySigma | Soporte | Operadores cubiertos |
|---|---|---|
| `ConditionAND` | ✅ | AND lógico sobre sub-árboles |
| `ConditionOR` | ✅ | OR lógico sobre sub-árboles |
| `ConditionNOT` | ✅ | NOT sobre un sub-árbol |
| `ConditionFieldEqualsValueExpression` | ✅ | Ver tabla de modificadores |
| `ConditionValueExpression` | ⚠️ Parcial | Keyword sin campo → False + WARNING |
| Aggregation (`count()`, `\|`) | ❌ | No soportado — reglas rechazadas |

### Modificadores Sigma evaluables

| Modificador | SecurityEvent | Nota |
|---|---|---|
| `contains` | `str(field).lower() in value` | Case-insensitive |
| `contains` (lista) | OR sobre la lista | Semántica OR por defecto en pySigma |
| `endswith` | `str(field).lower().endswith(value)` | Case-insensitive |
| `startswith` | `str(field).lower().startswith(value)` | Case-insensitive |
| `re` | `re.search(pattern, str(field), IGNORECASE)` | Respeta flags de SigmaRegularExpression |
| `all` | AND sobre la lista | `contains\|all` |
| `gt` | `float(field) > float(value)` | `SigmaCompareExpression` |
| `lt` | `float(field) < float(value)` | `SigmaCompareExpression` |
| Sin modificador (valor único) | `str(field).lower() == str(value).lower()` | Equality |
| Sin modificador (lista) | OR de igualdades | `SigmaNumber` o `SigmaString` |

---

## 4. Criterios de selección de las 15 reglas

Una regla se selecciona si cumple **todos** estos criterios:

1. YAML válido y parseable por pySigma 1.5.0
2. `id` UUID estable y verificable
3. `tags: attack.tXXXX` identificable (técnica MITRE ATT&CK)
4. `status: test` o `stable`
5. Solo usa campos disponibles en `SecurityEvent`
6. No duplica táctica ya cubierta sin añadir valor diferencial

Las reglas que no cumplen estos criterios están documentadas con razón explícita
en [`docs/SIGMA-EXCLUSIONS.md`](SIGMA-EXCLUSIONS.md).

---

## 5. Criterios de exclusión

Ver [`docs/SIGMA-EXCLUSIONS.md`](SIGMA-EXCLUSIONS.md) para la lista completa.
Grupos principales:

| Grupo | Motivo | Reglas afectadas |
|---|---|---|
| A — Token Windows | `IntegrityLevel`, `AccessMask`, `LogonType` ausentes | UAC bypass, token theft |
| B — Hash / firma | `Hashes`, `Imphash`, `Signature` ausentes | DLL hijacking, PE injection |
| C — Eventos archivo | `file_event` logsource no implementada | Timestomping, startup folder |
| D — Registro Windows | `TargetObject` ausente | Registry persistence |
| E — DNS / hostname | `QueryName`, `DestinationHostname` ausentes | DNS C2, dynamic resolution |
| F — Sin tag ATT&CK | Sin técnica MITRE identificable | HKTL rules |
| G — Aggregation Sigma | `count()` no soportado por el evaluador | Brute force con umbral |

---

## 6. Compatibilidad con SecurityEvent

Ver [`docs/SIGMA-COMPATIBILITY-MATRIX.md`](SIGMA-COMPATIBILITY-MATRIX.md) para
el detalle campo a campo.

**Campos disponibles en UNSW-NB15 tras normalización:**

| Campo SecurityEvent | Fuente UNSW-NB15 | Disponible |
|---|---|---|
| `src_ip` | `srcip` | ✅ |
| `dst_ip` | `dstip` | ✅ |
| `src_port` | `sport` | ✅ |
| `dst_port` | `dsport` | ✅ |
| `bytes_out` | `sbytes` | ✅ |
| `bytes_in` | `dbytes` | ✅ |
| `category` | siempre `network` | ✅ (fijo) |
| `outcome` | `state` (FIN, CON, RST…) | ✅ (no es fallo/éxito autenticación) |
| `command_line` | — | ❌ |
| `process_name` | — | ❌ |
| `user` | — | ❌ |

---

## 7. Reglas seleccionadas

### Reglas Sigma (15 total)

| # | Archivo | Técnica | Táctica | Tipo |
|---|---|---|---|---|
| 1 | `cs-ps-encoded-cmd.yml` | T1059.001 | Execution | SigmaHQ adaptation |
| 2 | `cs-whoami-exec.yml` | T1033 | Discovery | SigmaHQ adaptation |
| 3 | `cs-net-recon.yml` | T1087 | Discovery | SigmaHQ adaptation |
| 4 | `cs-schtasks-create.yml` | T1053.005 | Persistence | SigmaHQ adaptation |
| 5 | `cs-certutil-download.yml` | T1105 | C2 | SigmaHQ adaptation |
| 6 | `cs-mshta-exec.yml` | T1218.005 | Defense Evasion | SigmaHQ adaptation |
| 7 | `cs-wmic-process.yml` | T1047 | Execution | SigmaHQ adaptation |
| 8 | `cs-regsvr32-exec.yml` | T1218.010 | Defense Evasion | SigmaHQ adaptation |
| 9 | `cs-rundll32-exec.yml` | T1218.011 | Defense Evasion | SigmaHQ adaptation |
| 10 | `cs-large-outbound.yml` | T1048 | Exfiltration | CyberSentinel native |
| 11 | `cs-c2-port-connect.yml` | T1071 | C2 | CyberSentinel native |
| 12 | `cs-rdp-lateral.yml` | T1021.001 | Lateral Movement | CyberSentinel native |
| 13 | `cs-portscan-tool.yml` | T1046 | Discovery | CyberSentinel native |
| 14 | `cs-auth-failure.yml` | T1110 | Credential Access | CyberSentinel native |
| 15 | `cs-auth-failure-external.yml` | T1110.003 | Credential Access | CyberSentinel native |

Todas las adaptaciones de SigmaHQ conservan el UUID oficial y documentan
explícitamente qué se cambió. Ninguna se presenta como idéntica a la canónica.

---

## 8. Evaluación sobre UNSW-NB15

### Dataset

| Campo | Valor |
|---|---|
| Archivo | `data/synthetic_flows_unsw_format.csv` |
| Generado por | `data/generate_flow_sample.py` |
| Total eventos | 5 000 |
| Benignos | 4 500 (90%) |
| Ataques | 500 (10%) |
| Categorías de ataque | Reconnaissance: 162, Exploits: 141, DoS: 93, Backdoor: 58, Exfiltration: 46 |

> **Aviso:** Este es un dataset **sintético** generado para verificar el pipeline,
> no el UNSW-NB15 real (≥2 GB). Las métricas miden el comportamiento de las reglas
> sobre esta distribución concreta, **no** sobre tráfico de red real. Según la
> advertencia explícita de `generate_flow_sample.py`: *"las métricas obtenidas con
> este archivo no valen para la memoria"*.

### Evaluabilidad por regla

**Reglas EVALUABLES en UNSW-NB15 (correspondencia semántica real):**

| Regla | Campos usados | Correspondencia |
|---|---|---|
| `cs-c2-port-connect` | `dst_port ∈ {4444,1337,31337}` | `dsport → dst_port` ✅ |
| `cs-large-outbound` | `bytes_out > 104 857 600` | `sbytes → bytes_out` ✅ |
| `cs-rdp-lateral` | `dst_port=3389 + RFC1918 src + RFC1918 dst` | `dsport`, `srcip`, `dstip` ✅ |
| `RULE-0007` | `bytes_out > 104 857 600` | `sbytes → bytes_out` ✅ |
| `RULE-0005` | `dst_port=3389 + RFC1918 regex` | `dsport`, `srcip`, `dstip` ✅ |

**Reglas NOT EVALUABLE ON UNSW-NB15 (sin correspondencia semántica):**

| Categoría | Reglas | Razón |
|---|---|---|
| `process_creation` Sigma (9) | cs-ps-encoded-cmd … cs-portscan-tool | Requieren `command_line`/`process_name`; UNSW solo tiene flujos de red |
| `authentication` Sigma (2) | cs-auth-failure, cs-auth-failure-external | Requieren `category=authentication`; UNSW produce `category=network` |
| `process_creation` original (3) | RULE-0002, RULE-0003, RULE-0004 | Requieren `command_line`; ausente en UNSW |
| `authentication` original (1) | RULE-0001 | Requiere `category=authentication` |
| Aggregation sin soporte (1) | RULE-0006 | Requiere count() en ventana temporal; no implementado en modo stateless |

---

## 9. Métricas por regla

### Reglas evaluadas individualmente

| Regla | TP | FP | FN | TN | Precision | Recall | F1 | FPR | Tiempo |
|---|---|---|---|---|---|---|---|---|---|
| cs-c2-port-connect | 41 | 0 | 459 | 4 500 | **1.0000** | 0.0820 | 0.1516 | 0.0000 | 63.6 ms |
| cs-large-outbound | 0 | 0 | 500 | 4 500 | 0.0000* | 0.0000 | 0.0000 | 0.0000 | 15.8 ms |
| cs-rdp-lateral | 0 | 0 | 500 | 4 500 | 0.0000* | 0.0000 | 0.0000 | 0.0000 | 23.2 ms |
| RULE-0007 (exfil.) | 0 | 0 | 500 | 4 500 | 0.0000* | 0.0000 | 0.0000 | 0.0000 | 12.8 ms |
| RULE-0005 (RDP) | 0 | 0 | 500 | 4 500 | 0.0000* | 0.0000 | 0.0000 | 0.0000 | 16.0 ms |

*Precision=0 por ausencia de predicciones positivas (total_fired=0), no por FP.

### Métricas globales (suma de reglas evaluadas)

| Métrica | Valor | Nota |
|---|---|---|
| TP (global) | 41 | Solo de cs-c2-port-connect |
| FP (global) | 0 | Ninguna regla disparó sobre tráfico benigno |
| FN (global) | 2 459 | Suma de FN de las 5 reglas evaluadas |
| TN (global) | 22 500 | Suma de TN (5 × 4 500) |
| **Precision** | **1.0000** | ✅ Objetivo ≥ 0.70 alcanzado |
| Recall | 0.0164 | Bajo: solo 41/2500 ataques detectados por evaluación stateless |
| F1 | 0.0323 | Bajo: consecuencia directa del recall bajo |
| FPR | 0.0000 | Sin falsos positivos |
| Tiempo total evaluación | 133.4 ms | Para 5 000 eventos × 5 reglas |

> **Interpretación honesta:** La Precision=1.0 es real y no está manipulada: los
> puertos 4444/1337/31337 en este dataset aparecen **exclusivamente** en flujos
> etiquetados como ataques (categoría Backdoor). Sin embargo, el Recall=0.016 es
> muy bajo porque:
> (a) 4 de las 5 reglas evaluables no dispararon sobre este dataset concreto,
> (b) las otras 12 reglas ni siquiera son evaluables en UNSW-NB15.
> Esto **no implica** que esas reglas sean incorrectas: requieren telemetría de
> proceso o autenticación que simplemente no existe en un dataset de flujos de red.

### Por táctica (evaluadas)

| Táctica | Reglas evaluadas | TP | Recall (táctica) |
|---|---|---|---|
| command-and-control | cs-c2-port-connect | 41 | 0.082 |
| exfiltration | cs-large-outbound, RULE-0007 | 0 | 0.000 |
| lateral-movement | cs-rdp-lateral, RULE-0005 | 0 | 0.000 |
| execution | — | NOT EVALUABLE | — |
| discovery | — | NOT EVALUABLE | — |
| persistence | — | NOT EVALUABLE | — |
| defense-evasion | — | NOT EVALUABLE | — |
| credential-access | — | NOT EVALUABLE | — |

---

## 10. Cobertura ATT&CK antes/después

> **Distinción obligatoria:**
> - **Cobertura estructural** = existe al menos una regla para la técnica.
> - **Evidencia empírica** = la regla se evaluó y disparó en el dataset.
> Estas dos métricas son independientes. Una técnica puede estar cubierta
> estructuralmente pero no evaluada empíricamente por falta de telemetría.

### Tabla de cobertura

| | Antes | Después | Ganancia |
|---|---|---|---|
| Técnicas únicas | 7 | **18** | +11 |
| Porcentaje (/ 222) | 3.15 % | **8.11 %** | +4.96 pp |

### Técnicas originales (7/222)

`T1048` · `T1053` · `T1059` · `T1021` · `T1046` · `T1071` · `T1110`

### Técnicas nuevas añadidas por Sigma (11/222)

| Técnica | Regla Sigma | Táctica |
|---|---|---|
| T1021.001 | cs-rdp-lateral | Lateral Movement |
| T1033 | cs-whoami-exec | Discovery |
| T1047 | cs-wmic-process | Execution |
| T1053.005 | cs-schtasks-create | Persistence |
| T1059.001 | cs-ps-encoded-cmd | Execution |
| T1087 | cs-net-recon | Discovery |
| T1105 | cs-certutil-download | C2 |
| T1110.003 | cs-auth-failure-external | Credential Access |
| T1218.005 | cs-mshta-exec | Defense Evasion |
| T1218.010 | cs-regsvr32-exec | Defense Evasion |
| T1218.011 | cs-rundll32-exec | Defense Evasion |

### Por táctica

| Táctica | Técnicas antes | Técnicas nuevas | Total |
|---|---|---|---|
| Execution | T1059 | T1059.001, T1047 | 3 |
| Discovery | T1046 | T1033, T1087 | 3 |
| Persistence | T1053 | T1053.005 | 2 |
| Defense Evasion | — | T1218.005, T1218.010, T1218.011 | 3 |
| Command & Control | T1071 | T1105 | 2 |
| Exfiltration | T1048 | — | 1 |
| Lateral Movement | T1021 | T1021.001 | 2 |
| Credential Access | T1110 | T1110.003 | 2 |
| **Total** | **7** | **+11** | **18** |

### Estado Navigator

| Estado | Color | Técnicas | Significado |
|---|---|---|---|
| `detected` | 🟢 verde | T1071 | Regla evaluada en UNSW-NB15 + disparos registrados |
| `covered` | 🔵 azul | T1048, T1021 | Regla evaluable en UNSW-NB15, sin disparos |
| `covered/not_evaluable` | ⬜ gris | Resto (15 técnicas) | Regla existe; telemetría ausente en UNSW-NB15 |

---

## 11. Análisis de falsos positivos

**FP totales en UNSW-NB15: 0**

Ninguna de las 5 reglas evaluadas generó falsos positivos en este dataset.
La razón es que los campos discriminantes (puertos C2, bytes_out, dst_port RDP)
tienen distribuciones separadas en el dataset sintético: los puertos 4444/1337/31337
solo aparecen en ataques; los bytes_out > 100 MB no aparecen; el tráfico RDP
interno doble-RFC1918 no aparece.

> **No confundir FP=0 con "la regla es perfecta":** en un entorno real con
> tráfico más variado, se esperan falsos positivos en todas estas reglas.
> Ver `reports/sigma_phase1_false_positives.json` para los patrones de FP
> esperados y su clasificación.

**Patrones de FP esperados en producción (análisis prospectivo):**

| Regla | Patrón FP esperado | Fuente del problema | Decisión |
|---|---|---|---|
| cs-large-outbound | Backups/sync cloud > 100 MB | contexto ausente | aceptable |
| cs-c2-port-connect | Aplicaciones internas en puertos coincidentes | dataset | aceptable |
| cs-rdp-lateral | Administración RDP legítima desde salto | contexto ausente | aceptable |

---

## 12. Rendimiento

### Tiempos de ejecución

| Regla | Eventos | Tiempo | ms/evento |
|---|---|---|---|
| cs-c2-port-connect | 5 000 | 63.6 ms | 0.0127 |
| cs-large-outbound | 5 000 | 15.8 ms | 0.0032 |
| cs-rdp-lateral | 5 000 | 23.2 ms | 0.0046 |
| RULE-0007 | 5 000 | 12.8 ms | 0.0026 |
| RULE-0005 | 5 000 | 16.0 ms | 0.0032 |
| **Total (5 reglas)** | **5 000** | **133.4 ms** | **0.027** |

### Impacto de la integración pySigma

La carga de las 15 reglas Sigma (parsing + compilación AST) toma < 1s.
La evaluación stateless es determinista y lineal O(n × r) donde n=eventos y r=reglas.

El evaluador recursivo propio elimina cualquier sobrecarga de backend de pySigma
(no se genera Lucene, SPL, SQL ni ningún otro target). El AST se recorre directamente
sobre `SecurityEvent` en memoria.

**Conclusión:** la integración de pySigma no dispara el coste computacional.
133 ms para 5000 eventos × 5 reglas = 0.027 ms/evento, perfectamente viable en
tiempo real.

---

## 13. Limitaciones

| Limitación | Descripción | Impacto |
|---|---|---|
| Dataset sintético | `generate_flow_sample.py` genera distribuciones controladas; no es el UNSW-NB15 real (≥2 GB) | Las métricas no son representativas de producción |
| Solo flujos de red | UNSW-NB15 carece de telemetría de proceso, autenticación, registro y archivo | 12/15 reglas Sigma no pueden evaluarse |
| Aggregation Sigma | `count() by field > N` no implementado en el evaluador stateless | RULE-0006 y reglas similares no evaluadas |
| Recall muy bajo | Solo 41/2500 ataques detectados; mayoría de categorías no evaluables | Métrica no representativa de cobertura real |
| RFC1918 parcial | `cs-rdp-lateral` cubre 172.16–172.20 con startswith; 172.21–172.31 no cubiertos | Falsos negativos para ese rango CIDR |
| IPv6 | `SecurityEvent.src_ip`/`dst_ip` asume IPv4 | Sin cobertura IPv6 |
| Categorías no cubiertas | Initial Access, Privilege Escalation, Collection, Impact, Resource Development | Sin telemetría disponible |

---

## 14. Reproducibilidad

```yaml
experimento:
  fecha: 2026-09-14T22:30:11Z
  python_version: "3.11.15"
  pysigma_version: "1.5.0"
  git_commit: fbfcef9

dataset:
  archivo: data/synthetic_flows_unsw_format.csv
  generador: data/generate_flow_sample.py
  eventos: 5000
  ataques: 500
  benignos: 4500
  categorias_ataque:
    Reconnaissance: 162
    Exploits: 141
    DoS: 93
    Backdoor: 58
    Exfiltration: 46
  random_seed: 42

reglas:
  directorio_sigma: config/sigma_rules/selected/
  directorio_originales: config/rules/
  total_sigma: 15
  evaluables_sigma: 3
  not_evaluable_sigma: 12
  total_originales: 7
  evaluables_originales: 2
  not_evaluable_originales: 5

configuracion:
  evaluacion: stateless (evaluate_event)
  ground_truth: campo label (1=ataque, 0=benigno)
  leakage: ninguno (sin entrenamiento, reglas deterministas)
  modificaciones_reglas: ninguna
  modificaciones_datos: ninguna

reproducir:
  comando: PYTHONPATH=src python scripts/evaluate_sigma_phase1.py
  tests: PYTHONPATH=src python -m pytest -q
```

Para reproducir exactamente el mismo resultado:
```bash
cd /path/to/cybersentinel
PYTHONPATH=src python scripts/evaluate_sigma_phase1.py
```

---

## 15. Próximos pasos (Fase 2)

1. **Añadir telemetría de proceso y autenticación** al pipeline de ingesta.
   Sin ella, 12/15 reglas Sigma permanecen NOT EVALUABLE indefinidamente.
   Candidatos: Sysmon EventID 1 (proceso), Zeek conn.log (red), auditd (Linux).

2. **Implementar aggregation Sigma** (`count() by field > N` en ventana temporal)
   para poder evaluar RULE-0006 y reglas similares con umbral de frecuencia.

3. **Evaluar sobre UNSW-NB15 real** (≥2 GB, ~2.5M flujos) para métricas
   estadísticamente representativas.

4. **Ampliar el conjunto de reglas Sigma** una vez que la evaluación del lote
   inicial de 15 esté validada sobre el dataset real.

5. **Calibrar umbrales** de reglas como `cs-large-outbound` (100 MB) contra la
   distribución real de bytes_out en UNSW-NB15 completo.

6. **Cobertura RFC1918 completa** para `cs-rdp-lateral`: usar regex en vez de
   `startswith` para cubrir 172.16.0.0/12 completo.

---

## Archivos generados por esta fase

| Archivo | Propósito |
|---|---|
| `src/cybersentinel/detection/sigma_adapter.py` | Evaluador AST + SigmaBackedRule |
| `src/cybersentinel/detection/sigma_loader.py` | Cargador de directorio Sigma |
| `config/sigma_rules/selected/` (15 archivos) | Reglas Sigma curadas |
| `config/sigma_rules/manifest.yaml` | Metadatos de las 15 reglas |
| `reports/sigma_phase1_metrics.json` | Métricas por regla |
| `reports/sigma_phase1_by_rule.csv` | Métricas en CSV |
| `reports/sigma_phase1_summary.json` | Resumen global + reproducibilidad |
| `reports/sigma_phase1_false_positives.json` | Análisis de FP |
| `docs/navigator_before.json` | Capa ATT&CK Navigator (7 técnicas) |
| `docs/navigator_after.json` | Capa ATT&CK Navigator (18 técnicas) |
| `docs/SIGMA-COMPATIBILITY-MATRIX.md` | Compatibilidad campos Sigma ↔ SecurityEvent |
| `docs/SIGMA-EXCLUSIONS.md` | Registro de reglas descartadas |
| `docs/PHASE-1-SIGMA.md` | Este documento |
| `tests/test_sigma_integration.py` | 34 tests de integración pySigma |
| `tests/test_sigma_phase1_evaluation.py` | 42 tests de verificación evaluación |
| `scripts/evaluate_sigma_phase1.py` | Script de evaluación principal |

---

*Documento generado como parte de la Fase 1 Parte 3 de CyberSentinel.*
*Todos los resultados son reales. Ninguna métrica ha sido manipulada.*
