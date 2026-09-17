# CyberSentinel - Security Model (Fase 8.2)

Este documento detalla el modelo de seguridad implementado en la API y el Motor Cognitivo de CyberSentinel, especificando explícitamente las amenazas cubiertas, los controles técnicos aplicados, y los riesgos residuales delegados a la capa de infraestructura.

## 1. Amenazas Cubiertas y Controles Implementados

### 1.1. Acceso no Autorizado y Evasión de Privilegios
- **Control**: Autenticación estricta con JSON Web Tokens (JWT) y API Keys. Todos los endpoints (excepto liveness/readiness de salud) devuelven `401 Unauthorized` si carecen de token válido.
- **Control (RBAC)**: Autorización granular basada en permisos. Se definen 4 roles con fronteras duras (`403 Forbidden` al infringirse):
  - `COLLECTOR`: Puede ingerir eventos (`POST /api/v1/events`). No tiene permisos de lectura, evitando que el robo de una API key comprometa el historial.
  - `VIEWER`: Acceso "Read-Only" a incidentes, métricas y auditoría.
  - `ANALYST`: `VIEWER` + capacidad de interactuar y emitir veredictos en incidentes (HITL).
  - `ADMIN`: Acceso total, incluyendo creación y revocación de identidades.

### 1.2. Fuerza Bruta, Denegación de Servicio (DoS) y Evasión de Caudal
- **Control**: Rate Limiting por dos ejes (Peticiones por Segundo y Eventos por Segundo). 
  - Las cuotas están diferenciadas por rol (ej. `COLLECTOR` permite grandes ráfagas, mientras `ANALYST` es estricto).
  - Si un token agota el límite, la API retorna `429 Too Many Requests` *antes* de cargar el lote en memoria, protegiendo a los demás inquilinos.
  - La fuerza bruta de login es castigada en un "cubo anónimo" que ahoga por IP (`anonymous` RateLimit).

### 1.3. Inyección de Payloads y Fuga de Información
- **Control**: Input Validation estricta con *Pydantic*. Los payloads maliciosos o malformados se rechazan en frontera con `422 Unprocessable Entity`.
- **Control**: Handler global de excepciones parcheado. Los errores internos inesperados (`500`) retornan un mensaje genérico ("Error interno del servidor") y no filtran el *stack trace* ni el contenido de la excepción.

### 1.4. Filtración de Secretos en Repositorio
- **Control**: Uso de `python-dotenv`. Las contraseñas, *seeds* y llaves criptográficas se extraen de variables de entorno (ej. `.env`) y nunca se *hardcodean* (verificado mediante tests CI).

### 1.5. Subversión del Modelo (Prompt Injection & LLM Jailbreak)
- **Control (RAG Sanitization)**: Antes de suministrar los documentos recuperados de CTI al LLM, CyberSentinel limpia marcadores markdown o pseudo-tags (`<system>`) y elimina cadenas heurísticas diseñadas para sobrescribir reglas.
- **Control (LLM Invariability)**: El LLM actúa en modo estricto *Read-Only*. CyberSentinel no expone métodos para que el LLM ejecute *shell*, ni altera el `hybrid_score`. Un ataque de prompt inyectado exitoso solo podría lograr que el LLM delire texto en el campo `narrative`, pero nunca aprobar una resolución, alterar severidad o cerrar un incidente.

### 1.6. Falta de Trazabilidad y Repudio
- **Control**: Audit Log seguro y no modificable. Se registra automáticamente: login, logout, fallos de autenticación (Authz Denied), activaciones de Rate Limit (429), revocación de claves y decisiones HITL.

---

## 2. Riesgos Residuales (Controles Externos Requeridos)

CyberSentinel no asume responsabilidades que pertenecen arquitectónicamente al proxy o a la red. Las siguientes amenazas deben ser mitigadas por la infraestructura en la que se despliegue:

- **Ataques Volumétricos de Capa 3/4 (DDoS)**: El *Rate Limiter* interno previene el agotamiento de procesos (L7), pero no detendrá inundaciones de red SYN/UDP. Se requiere protección perimetral (ej. Cloudflare, AWS Shield).
- **Terminación TLS**: CyberSentinel exige que el tráfico autenticado provenga de *localhost* o bajo encriptación HTTPS. No obstante, el servicio depende de un proxy reverso (Nginx/Envoy) para gestionar los certificados TLS y establecer los *ciphers* fuertes.
- **Replicación de Tokens (Memoria de Rate Limit)**: En un despliegue multi-instancia, los cubos del *Rate Limiter* viven en la memoria de cada proceso. Para una protección L7 estricta compartida entre réplicas, se requerirá transicionar el limitador a un almacén Redis en la Fase 9.

---
> [!NOTE] 
> Todas las reglas de seguridad estipuladas en este modelo (RBAC, Rate Limiting, Input Validation, Secrets Detection, LLM Safeties) han sido materializadas como casos de prueba automatizados en `test_api_security.py` y `test_explainer_safety.py`. La regresión es prevenida por código.
