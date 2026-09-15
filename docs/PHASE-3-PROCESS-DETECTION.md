# Phase 3: Process Telemetry Evaluation and ML Base

## Resumen Ejecutivo

En la Fase 3, CyberSentinel ha evolucionado significativamente para evaluar reglas complejas basadas en telemetría de procesos (Sysmon) y establecer una arquitectura fundacional robusta para Machine Learning no supervisado y correlación de ataques.

Esta fase demuestra que el motor de detección determinista es ahora plenamente capaz de operar sobre datos complejos estructurados de forma extensible y correlacionarlos temporalmente, mientras que el módulo de Machine Learning queda completamente desacoplado para experimentación paralela sin romper las garantías del motor principal.

## Logros de la Fase 3

### 1. Detección de Telemetría de Procesos
Se introdujo un conjunto de datos sintético controlado para eventos Sysmon (`data/synthetic_sysmon_eval.json`). Este dataset incluye simulaciones precisas de:
- Ejecución de PowerShell ofuscado (T1059.001)
- Ejecución de Whoami para reconocimiento local (T1033)
- Exploración de dominios con net.exe (T1087)
- Creación de tareas programadas evasivas (T1053.005)
- Descarga de binarios usando certutil (T1105)
- Ejecución vía mshta, wmic, regsvr32 y rundll32 (T1218.xxx y T1047)
- Uso de herramientas de port scanning (T1046)

**Impacto:** 13 de las 15 reglas Sigma controladas ahora han disparado exitosamente con **Precision = 1.0** y **Recall = 1.0** sobre el conjunto de control, demostrando la fiabilidad del adaptador Sigma y el mapa de propiedades del evento.

### 2. Correlación Temporal
Se implementó `TemporalCorrelator`, una abstracción ligera y enfocada (no un framework sobre-ingeniado) que correlaciona de manera determinista secuencias de técnicas ATT&CK.

- Agrupación por entidades (`host`, `user`).
- Soporte estricto de secuencias temporales (`T1059 -> T1071`).
- Timeout de ventana configurable (ej. 5 minutos).
- Generación de `CorrelatedIncident` que captura la narrativa táctica del ataque completo, proporcionando un pre-procesamiento ideal para futuros motores basados en ML o LLM.

### 3. Fundación Modular para Machine Learning
El `AnomalyDetector` se extrajo y adaptó para cumplir con la nueva interfaz `MLModel` dentro del paquete `cybersentinel.ml`.

- **Interoperabilidad:** `MLModel` define métodos estándar (`fit`, `predict`, `predict_proba`, `evaluate`) permitiendo cambiar Isolation Forest por One-Class SVM o Autoencoders sin tocar el código central.
- **Robustez del Feature Extraction:** `FeatureExtractor` fue expandido para soportar y combinar de manera segura características tanto de red (bytes transferidos, asimetría) como de procesos (entropía, comandos especiales). Se gestionan de forma segura los "datos faltantes" mediante campos binarios estructurales (`is_network_event`, `is_process_event`).

### 4. Manteniendo las Garantías
- 231 tests unitarios y de integración están ejecutándose y superando el 100%.
- La filosofía de *No Manipular Métricas* se mantiene. Las reglas de autenticación (T1110, T1110.003) no fueron forzadas a pasar sobre telemetría Sysmon (donde serían imposibles de detectar). Permanecen listas, esperando logs de autenticación (Windows Event Log 4625).
