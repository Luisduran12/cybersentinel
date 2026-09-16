"""
Capa de servicio: ingestión de telemetría en tiempo real.

Envuelve el pipeline existente sin modificarlo. El núcleo de análisis sigue
siendo el mismo objeto `Pipeline` que usa la CLI.

La frontera —autenticación, autorización y límite de caudal— vive en
`security/` y se aplica en la capa HTTP: el pipeline nunca sabe quién le envió
un evento, y eso es correcto. Un motor de detección que dependa de la identidad
del emisor es un motor que puede ser engañado cambiando de credencial.
"""
from .models import EventBatch, RawEvent  # noqa: F401
from .metrics import IngestMetrics  # noqa: F401
from .queue import IngestQueue, QueueFull  # noqa: F401
from .security import (  # noqa: F401
    IdentityStore, Permission, Principal, RateLimiter, Role, SecurityConfig,
    SecurityGate,
)
from .store import ResultStore  # noqa: F401
