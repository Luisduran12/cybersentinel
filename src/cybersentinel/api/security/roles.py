"""
Modelo de autorización: permisos, roles y la matriz que los une.

Dos decisiones que condicionan todo lo demás:

1. **El permiso es la unidad, no el rol.** El código nunca pregunta «¿eres
   analista?», pregunta «¿puedes leer incidentes?». Preguntar por el rol
   esparce la política por todos los manejadores y obliga a tocar veinte
   sitios para añadir un rol; preguntar por el permiso la concentra en esta
   tabla.

2. **Los sensores no son usuarios.** Un colector que envía telemetría tiene un
   único permiso —escribir eventos— y no puede leer ni un incidente. Es la
   diferencia entre que el robo de la credencial de un sensor cueste ruido en
   la cola o cueste la exfiltración del historial de incidentes.

La matriz es deliberadamente pequeña. Un RBAC con treinta permisos que nadie
sabe explicar es indistinguible de no tener autorización.
"""
from __future__ import annotations

from enum import Enum


class Permission(str, Enum):
    """Lo que se puede hacer sobre el servicio, expresado como verbo+objeto."""

    EVENTS_WRITE = "events:write"        # ingerir telemetría
    INCIDENTS_READ = "incidents:read"    # consultar lo que superó el umbral
    INCIDENTS_WRITE = "incidents:write"  # cambiar estado, asignar, cerrar
    METRICS_READ = "metrics:read"        # caudal, latencias, errores
    AUDIT_READ = "audit:read"            # cadena de auditoría
    RESPONSE_APPROVE = "response:approve"  # aprobar acciones de respuesta
    IDENTITY_ADMIN = "identity:admin"    # crear y revocar credenciales

    def __str__(self) -> str:  # para que los mensajes de error se lean
        return self.value


class Role(str, Enum):
    """
    Roles del producto (Fase 8.2 Security).
    """
    COLLECTOR = "collector"
    VIEWER = "viewer"
    ANALYST = "analyst"
    ADMIN = "admin"

    def __str__(self) -> str:
        return self.value


#: Matriz rol → permisos. Única fuente de verdad de la autorización.
ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    # Collector: solo ingesta. No lee nada.
    Role.COLLECTOR: frozenset({Permission.EVENTS_WRITE}),

    # Viewer: solo GET endpoints de lectura.
    Role.VIEWER: frozenset({
        Permission.INCIDENTS_READ,
        Permission.METRICS_READ,
        Permission.AUDIT_READ,
    }),

    # Analyst: ver + triagear incidentes + HITL.
    Role.ANALYST: frozenset({
        Permission.INCIDENTS_READ,
        Permission.METRICS_READ,
        Permission.INCIDENTS_WRITE,
        Permission.RESPONSE_APPROVE,
    }),

    # Admin: todo + configuración + gestión de reglas.
    Role.ADMIN: frozenset({
        Permission.EVENTS_WRITE,
        Permission.INCIDENTS_READ,
        Permission.INCIDENTS_WRITE,
        Permission.METRICS_READ,
        Permission.AUDIT_READ,
        Permission.RESPONSE_APPROVE,
        Permission.IDENTITY_ADMIN,
    }),
}


def permissions_for(role: Role | str) -> frozenset[Permission]:
    """
    Permisos de un rol. Un rol desconocido devuelve el conjunto vacío.

    Devolver vacío —en lugar de lanzar— es deliberado: si un token trae un rol
    que esta versión del servicio no conoce (despliegue escalonado, token
    emitido por una versión posterior), la respuesta segura es no conceder
    nada, no caerse con un 500 que el emisor interpretaría como fallo nuestro.
    """
    try:
        return ROLE_PERMISSIONS[Role(role)]
    except ValueError:
        return frozenset()


def role_matrix() -> dict[str, list[str]]:
    """La matriz en forma serializable, para documentarla y exponerla."""
    return {
        rol.value: sorted(p.value for p in permisos)
        for rol, permisos in ROLE_PERMISSIONS.items()
    }
