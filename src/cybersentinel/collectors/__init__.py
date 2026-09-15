"""
Collectors de telemetría empresarial.

El contrato con el motor de detección es `SecurityEvent` y **solo** eso: añadir
una fuente no obliga a tocar Sigma, el Isolation Forest, el modelo de Markov ni
la correlación.
"""
from .base import Collector, CollectorResult, MAX_PAYLOAD_BYTES  # noqa: F401
from .firewall import FirewallCollector  # noqa: F401
from .linux import LinuxCollector  # noqa: F401
from .suricata import SuricataCollector  # noqa: F401
from .sysmon import SysmonCollector  # noqa: F401

#: Collectors disponibles por nombre de fuente.
COLLECTORS: dict[str, type[Collector]] = {
    SysmonCollector.source_type: SysmonCollector,
    LinuxCollector.source_type: LinuxCollector,
    FirewallCollector.source_type: FirewallCollector,
    SuricataCollector.source_type: SuricataCollector,
}


def get_collector(source_type: str) -> Collector:
    """Instancia el collector de una fuente. Lanza ValueError si no existe."""
    clave = source_type.strip().lower()
    if clave not in COLLECTORS:
        raise ValueError(
            f"Collector desconocido: {source_type!r}. "
            f"Disponibles: {', '.join(sorted(COLLECTORS))}"
        )
    return COLLECTORS[clave]()
