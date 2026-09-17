"""
Adaptador OCSF (Open Cybersecurity Schema Framework) para `SecurityEvent`.

Esto es una capa **aditiva**, no un reemplazo. `SecurityEvent` (ver
`schema.py`) sigue siendo el modelo interno: reglas Sigma, ML, correlación
temporal y CTI siguen leyendo `SecurityEvent` exactamente igual que antes. Este
módulo solo traduce hacia/desde OCSF en las fronteras del sistema —al exportar
a un SIEM/EDR externo, o al ingerir un evento que ya viene en OCSF de un
colector de terceros—, precisamente para no repetir el error de "God Object"
señalado en la auditoría arquitectónica: si `SecurityEvent` creciera para
llevar además todos los campos de OCSF, terminaría con decenas de campos
`Optional` que nadie usa a la vez.

Alcance declarado, no escondido:

- Se cubren 4 clases OCSF —las que corresponden a los 4 collectors ya
  existentes—: Process Activity (1007), Authentication (3002), Network
  Activity (4001) y Detection Finding (2004, para alertas IDS). Cualquier otra
  combinación cae en Base Event (class_uid 0), que es una clase válida de
  OCSF para "no clasificado", no un error.
- Es un subconjunto de atributos, no una implementación validada contra el
  JSON Schema oficial de OCSF. Faltan `observables`, `enrichments` y la
  mayoría de los perfiles opcionales. Para validación real contra el esquema
  oficial (JSON Schema descargable de github.com/ocsf/ocsf-schema) haría falta
  vendorizar esos archivos y correr un validador —lo dejamos como trabajo de
  la Fase 1.1, documentado en `docs/PRODUCTION-ARCHITECTURE.md`—.
- El vocabulario de OCSF no siempre tiene una casilla exacta para nuestra
  `action` interna (p.ej. "process_create" vs. `activity_id=1`/"Launch"). Para
  que la conversión de ida y vuelta sea sin pérdidas, la acción y categoría
  originales viajan también en `unmapped.cybersentinel_action` /
  `cybersentinel_category`. Es una decisión deliberada: preferimos un evento
  OCSF con dos campos "de más" a uno que, al volver, ya no es el mismo evento.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ..schema import SecurityEvent

#: Versión de OCSF contra la que se modela este subconjunto. OCSF publica
#: versiones con cambios de atributos entre minors; fijarla explícitamente en
#: cada evento es lo que permite a un consumidor saber qué esperar.
OCSF_VERSION = "1.1.0"

#: category_uid — solo las que de verdad se producen hoy.
CATEGORY_SYSTEM_ACTIVITY = 1
CATEGORY_FINDINGS = 2
CATEGORY_IAM = 3
CATEGORY_NETWORK_ACTIVITY = 4
CATEGORY_UNCATEGORIZED = 0

#: class_uid — idem.
CLASS_BASE_EVENT = 0
CLASS_AUTHENTICATION = 3002
CLASS_DETECTION_FINDING = 2004
CLASS_NETWORK_ACTIVITY = 4001
CLASS_PROCESS_ACTIVITY = 1007

_CLASS_NAMES = {
    CLASS_BASE_EVENT: "Base Event",
    CLASS_AUTHENTICATION: "Authentication",
    CLASS_DETECTION_FINDING: "Detection Finding",
    CLASS_NETWORK_ACTIVITY: "Network Activity",
    CLASS_PROCESS_ACTIVITY: "Process Activity",
}

_CATEGORY_NAMES = {
    CATEGORY_UNCATEGORIZED: "Uncategorized",
    CATEGORY_SYSTEM_ACTIVITY: "System Activity",
    CATEGORY_FINDINGS: "Findings",
    CATEGORY_IAM: "Identity & Access Management",
    CATEGORY_NETWORK_ACTIVITY: "Network Activity",
}

#: outcome de SecurityEvent -> status_id de OCSF (1=Success, 2=Failure).
_STATUS_ID = {"success": 1, "failure": 2}

#: action -> activity_id, por clase. Lo que no está aquí cae en 99 (Other).
_PROCESS_ACTIVITY_ID = {"process_create": 1, "process_terminate": 2, "process_access": 6}
_AUTH_ACTIVITY_ID = {"user_login": 1, "user_logout": 2}
_NETWORK_ACTIVITY_ID = {"network_connection": 1, "network_close": 2, "network_traffic": 6}


def _epoch_ms(ts: datetime) -> int:
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return int(ts.timestamp() * 1000)


def _classify(event: SecurityEvent) -> tuple[int, int]:
    """Deriva (class_uid, category_uid) de la categoría/fuente internas."""
    if event.source == "suricata" and event.category == "alert":
        return CLASS_DETECTION_FINDING, CATEGORY_FINDINGS
    if event.category == "process":
        return CLASS_PROCESS_ACTIVITY, CATEGORY_SYSTEM_ACTIVITY
    if event.category == "authentication":
        return CLASS_AUTHENTICATION, CATEGORY_IAM
    if event.category in ("network", "flow", "dns") or event.source in ("firewall", "netflow"):
        return CLASS_NETWORK_ACTIVITY, CATEGORY_NETWORK_ACTIVITY
    return CLASS_BASE_EVENT, CATEGORY_UNCATEGORIZED


def to_ocsf(event: SecurityEvent) -> dict[str, Any]:
    """
    Traduce un `SecurityEvent` al subconjunto de OCSF descrito en el docstring
    del módulo. No muta `event`.
    """
    class_uid, category_uid = _classify(event)
    activity_id = 99
    if class_uid == CLASS_PROCESS_ACTIVITY:
        activity_id = _PROCESS_ACTIVITY_ID.get(event.action, 99)
    elif class_uid == CLASS_AUTHENTICATION:
        activity_id = _AUTH_ACTIVITY_ID.get(event.action, 99)
    elif class_uid == CLASS_NETWORK_ACTIVITY:
        activity_id = _NETWORK_ACTIVITY_ID.get(event.action, 99)

    documento: dict[str, Any] = {
        "class_uid": class_uid,
        "class_name": _CLASS_NAMES[class_uid],
        "category_uid": category_uid,
        "category_name": _CATEGORY_NAMES[category_uid],
        "activity_id": activity_id,
        "type_uid": class_uid * 100 + activity_id,
        "time": _epoch_ms(event.timestamp),
        "severity_id": 0,   # sin severidad propia a este nivel; la deriva el pipeline aguas abajo
        "status_id": _STATUS_ID.get(event.outcome or "", 0),
        "status": event.outcome,
        "metadata": {
            "version": OCSF_VERSION,
            "product": {"name": "CyberSentinel", "vendor_name": "CyberSentinel"},
            "original_time": event.timestamp.isoformat(),
        },
        "unmapped": {
            **event.properties,
            "cybersentinel_source": event.source,
            "cybersentinel_category": event.category,
            "cybersentinel_action": event.action,
            "cybersentinel_tags": list(event.tags),
        },
    }

    if event.host or event.user:
        documento["actor"] = {"user": {"name": event.user}} if event.user else None
        documento["device"] = {"hostname": event.host} if event.host else None

    if event.process_name or event.command_line or event.parent_process:
        documento["process"] = {
            "name": event.process_name,
            "cmd_line": event.command_line,
            "parent_process": (
                {"name": event.parent_process} if event.parent_process else None
            ),
        }

    if event.src_ip or event.dst_ip or event.src_port or event.dst_port:
        documento["src_endpoint"] = {"ip": event.src_ip, "port": event.src_port}
        documento["dst_endpoint"] = {"ip": event.dst_ip, "port": event.dst_port}

    if event.protocol or event.bytes_in or event.bytes_out:
        documento["connection_info"] = {"protocol_name": event.protocol}
        documento["traffic"] = {"bytes_in": event.bytes_in, "bytes_out": event.bytes_out}

    if class_uid == CLASS_DETECTION_FINDING:
        documento["finding_info"] = {
            "title": event.properties.get("signature"),
            "uid": event.event_id,
        }

    # Ningún valor `None` explícito a nivel superior: un consumidor OCSF
    # externo espera que el campo esté ausente, no presente y nulo.
    return {k: v for k, v in documento.items() if v is not None}


def from_ocsf(documento: dict[str, Any], *, raw: dict[str, Any] | None = None) -> SecurityEvent:
    """
    Traduce un evento OCSF (propio o de un tercero) a `SecurityEvent`.

    Un evento OCSF ajeno no traerá `cybersentinel_action`/`cybersentinel_category`:
    en ese caso se deriva una acción/categoría genérica a partir de
    `class_uid`, igual que un collector nuevo lo haría con un formato que no
    conoce del todo — no se inventa semántica que el dato no trae.
    """
    unmapped = dict(documento.get("unmapped") or {})
    class_uid = documento.get("class_uid", CLASS_BASE_EVENT)

    categoria = unmapped.pop("cybersentinel_category", None)
    accion = unmapped.pop("cybersentinel_action", None)
    fuente = unmapped.pop("cybersentinel_source", None)
    etiquetas = unmapped.pop("cybersentinel_tags", [])

    if categoria is None or accion is None:
        categoria = {
            CLASS_PROCESS_ACTIVITY: "process", CLASS_AUTHENTICATION: "authentication",
            CLASS_NETWORK_ACTIVITY: "network", CLASS_DETECTION_FINDING: "alert",
        }.get(class_uid, "unknown")
        accion = f"ocsf_class_{class_uid}"
    if fuente is None:
        fuente = "ocsf"

    ts_ms = documento.get("time")
    timestamp = (datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
                 if ts_ms is not None else datetime.now(tz=timezone.utc))

    actor = documento.get("actor") or {}
    device = documento.get("device") or {}
    process = documento.get("process") or {}
    parent = process.get("parent_process") or {}
    src_endpoint = documento.get("src_endpoint") or {}
    dst_endpoint = documento.get("dst_endpoint") or {}
    connection = documento.get("connection_info") or {}
    traffic = documento.get("traffic") or {}
    finding = documento.get("finding_info") or {}
    if finding.get("title") is not None:
        unmapped.setdefault("signature", finding["title"])

    event_id = str(finding.get("uid") or documento.get("uid") or "")

    return SecurityEvent(
        event_id=event_id,
        timestamp=timestamp,
        source=fuente,
        category=categoria,
        action=accion,
        host=device.get("hostname"),
        user=(actor.get("user") or {}).get("name"),
        src_ip=src_endpoint.get("ip"),
        dst_ip=dst_endpoint.get("ip"),
        src_port=src_endpoint.get("port"),
        dst_port=dst_endpoint.get("port"),
        protocol=connection.get("protocol_name"),
        bytes_in=traffic.get("bytes_in"),
        bytes_out=traffic.get("bytes_out"),
        process_name=process.get("name"),
        command_line=process.get("cmd_line"),
        parent_process=parent.get("name"),
        outcome=documento.get("status"),
        properties=unmapped,
        raw=raw if raw is not None else documento,
        tags=list(etiquetas),
    )
