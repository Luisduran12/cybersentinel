# FASE 1.5: BASELINE EXECUTION REPORT

**Fecha:** 2026-10-05
**Tipo:** ejecución real de la suite (sustituye a la versión anterior, que era análisis estático y predictivo)
**Commit evaluado:** `ad622c2` (HEAD de `origin/main` en el momento de la ejecución)
**Rama local activa:** `fix/orphaned-collectors-sysmon-firewall` (sigue a `origin/main`, sin commits propios)

> La versión anterior de este documento estimaba un 26–40 % de tests en verde e
> incluía un log de pytest hipotético ("18 passed, 22 failed"). Ese log no
> provenía de ninguna ejecución. Este informe lo reemplaza con la salida real.

---

## 1. Entorno

| Elemento | Valor |
|---|---|
| Sistema | macOS (Darwin 24.5.0) |
| Python | 3.11.15 (`.venv/` del repositorio) |
| Configuración de pytest | `[tool.pytest.ini_options]` en `pyproject.toml` (sin `addopts`; solo declara el marcador `asyncio`) |
| `nats-py` | **no instalado** (extra opcional `streaming`) |
| Servicios externos | ninguno levantado (sin NATS, sin API keys de AbuseIPDB/OTX/Anthropic) |

### Comando exacto

```bash
cd cybersentinel
PYTHONPATH=src .venv/bin/python -m pytest -q -p no:cacheprovider
```

---

## 2. Resultado

```
677 passed, 1 skipped, 4 warnings in 133.65s (0:02:13)
```

| Métrica | Valor |
|---|---|
| Archivos `tests/test_*.py` | 45 |
| Passed | **677** |
| Failed | **0** |
| Errors | **0** |
| Skipped | 1 |
| Duración | 2 min 13 s |

### Test omitido

```
SKIPPED [1] tests/test_streaming.py:59: requiere un servidor NATS real
(docker-compose up nats); no se ejecuta en la suite estándar de pytest
```

---

## 3. Warnings reales

| # | Origen | Mensaje | Acción |
|---|---|---|---|
| 1 | `src/cybersentinel/rag/vector_store.py:16` | `langchain-community` is being sunset and is no longer actively maintained | Migrar `langchain_community.vectorstores.FAISS` a un paquete de integración independiente |
| 2–3 | `src/cybersentinel/api/app.py:435, 473, 648` (aflora en `test_soc_panel.py::test_la_api_traduce_la_transicion_invalida_a_422` y `::test_veredicto_desconocido_se_rechaza`) | `'HTTP_422_UNPROCESSABLE_ENTITY' is deprecated. Use 'HTTP_422_UNPROCESSABLE_CONTENT'` | Cambio trivial en código propio |
| 4 | `starlette/testclient.py:53` (dependencia) | `anyio.abc.BlockingPortal` alias is deprecated | Ninguna; se resuelve al actualizar Starlette |

No apareció ningún warning de `httpx`.

---

## 4. Puntos que el informe anterior señalaba como críticos

### 4.1 `test_full_pipeline_end_to_end` y `PipelineReport`

**Predicción anterior:** fallo del 65–85 % con
`AttributeError: 'PipelineReport' object has no attribute 'results'` o
`'Evidence' object has no attribute 'hybrid_score'`.

**Resultado real:** **PASA**, tanto en la suite completa como en solitario:

```bash
PYTHONPATH=src .venv/bin/python -m pytest -q tests/test_pipeline.py::test_full_pipeline_end_to_end
# 1 passed, 1 warning in 7.43s
```

- `PipelineReport.results: list[IncidentResult]` existe (`src/cybersentinel/pipeline.py:110`).
- `hybrid_score` es una propiedad de la evidencia híbrida (`src/cybersentinel/detection/hybrid.py:137`) y el pipeline la consume en `pipeline.py:704, 786, 794`.

No hay ningún problema en la estructura de retorno. La "Acción 1 de la Fase 2" del informe anterior (arreglar `PipelineReport`) **no aplica**.

Límite de este test: las aserciones comprueban que el reporte tenga la forma esperada (`hasattr`) y que `total_events > 0`, pero no la calidad de la detección. Que pase demuestra que el pipeline está conectado de extremo a extremo; no demuestra que sea preciso.

### 4.2 `test_streaming.py` y el módulo `nats`

**Predicción anterior:** FAIL/ERROR con `ModuleNotFoundError: No module named 'nats'`.

**Resultado real:** `nats-py` efectivamente **no está instalado**, pero eso **no causa ningún fallo**:

- Los tests unitarios de `test_streaming.py` y `test_high_availability.py` pasan (30 passed).
- La única prueba que necesita un broker real (`test_streaming.py:59`) se **omite de forma explícita**, con un motivo.

Para ejecutarla: `pip install -e ".[streaming]"` y `docker-compose up nats`.

### 4.3 Otras predicciones refutadas

| Predicción anterior | Resultado real |
|---|---|
| `test_api_*`, `test_soc_panel` fallan porque requieren el servidor levantado | Pasan: usan `TestClient` de FastAPI, en el mismo proceso |
| `test_behavioral_analytics`, `test_detection_quality` "LIKELY FAIL" | Pasan |
| `test_sigma_integration` FAIL por campos que no coinciden | Pasa |
| `test_cti_live_feeds` FAIL por falta de API key | Pasa (los clientes HTTP se prueban con transportes simulados) |
| Fixtures UNSW en `fixtures/` | Están en `tests/fixtures/` |

---

## 5. Estado de las ramas

| Rama | HEAD | Comentario |
|---|---|---|
| `origin/main` | `ad622c2` | Incluye los 2 commits de documentación de Copilot |
| `fix/orphaned-collectors-sysmon-firewall` (activa) | `ad622c2` | Sigue a `origin/main`; idéntica a ella antes de este commit |
| `main` (local) | `a469608` | Commit inicial, **31 commits por detrás** de `origin/main`; conviene actualizarla |

---

## 6. Qué demuestra y qué no demuestra esta ejecución

**Demuestra:**
- La suite estándar es reproducible en verde con el comando anterior.
- El pipeline mínimo funciona de extremo a extremo con datos sintéticos.
- La API (JWT + RBAC, ingesta, panel SOC con HITL) responde correctamente con `TestClient`.
- Los 5 colectores (Sysmon, Linux, Firewall, Suricata, Wazuh) pasan sus tests de normalización.

**No demuestra:**
- Comportamiento contra un broker NATS real (test omitido).
- Llamadas reales a AbuseIPDB, OTX o CISA KEV, ni generación real con LLM (sin red ni credenciales).
- Calidad de detección sobre telemetría real de producción.
- Despliegue de la API detrás de un proxy TLS ni bajo carga.

---

## 7. Siguientes pasos recomendados

1. Reemplazar `HTTP_422_UNPROCESSABLE_ENTITY` por `HTTP_422_UNPROCESSABLE_CONTENT` en `api/app.py`.
2. Planificar la migración desde `langchain-community`.
3. Añadir un job de CI que ejecute el comando de la sección 1 y publique el resumen.
4. Documentar cómo ejecutar el test de integración con NATS (extra `streaming` + `docker-compose up nats`).
5. Actualizar la rama `main` local.
