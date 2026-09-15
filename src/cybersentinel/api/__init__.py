"""
Capa de servicio: ingestión de telemetría en tiempo real.

Envuelve el pipeline existente sin modificarlo. El núcleo de análisis sigue
siendo el mismo objeto `Pipeline` que usa la CLI.
"""
from .models import EventBatch, RawEvent  # noqa: F401
from .metrics import IngestMetrics  # noqa: F401
from .queue import IngestQueue, QueueFull  # noqa: F401
from .store import ResultStore  # noqa: F401
