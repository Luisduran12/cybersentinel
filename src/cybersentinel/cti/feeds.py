"""
Interfaz común de los feeds de threat intelligence en vivo (Fase 4-C).

Esto es intencionadamente distinto de `stix_ingestor.py`/`enrichment.py`
(Fase 5): aquellos cruzan contra un bundle STIX local, sin red. Esto habla
por HTTP con servicios externos reales (AbuseIPDB, OTX AlienVault, CISA KEV).

Contrato de todo `CTIFeed`:

1. **Nunca lanza excepción hacia quien llama.** Un feed caído no debe tumbar
   la ingestión: cualquier fallo de red, HTTP o parseo se captura y se
   traduce a un `FeedResult` con `status="ERROR"`.
2. **Sin credencial configurada, se declara, no se inventa.** Un feed sin
   API key devuelve `status="NOT_CONFIGURED"`, nunca un resultado "limpio"
   falso — decir "no consultado" y decir "consultado y limpio" son cosas
   muy distintas para un analista.
3. **`raw` conserva la respuesta original** para que un analista pueda
   verificar la fuente, igual que con la evidencia de detección.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

#: Estados posibles de una consulta a un feed.
STATUS_OK = "OK"
STATUS_NOT_CONFIGURED = "NOT_CONFIGURED"
STATUS_ERROR = "ERROR"
STATUS_RATE_LIMITED = "RATE_LIMITED"
STATUS_NOT_FOUND = "NOT_FOUND"


@dataclass
class FeedResult:
    """Resultado de consultar un observable contra un feed de CTI."""

    feed: str
    observable: str
    observable_type: str          # "ip" | "domain" | "hash" | "cve"
    status: str
    found: bool = False
    malicious: bool = False
    score: float | None = None    # 0..100, normalizado por feed. None si no aplica.
    categories: list[str] = field(default_factory=list)
    detail: str = ""
    raw: dict[str, Any] = field(default_factory=dict)
    queried_at: str = field(
        default_factory=lambda: datetime.now(tz=timezone.utc).isoformat(timespec="seconds")
    )
    cached: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "feed": self.feed,
            "observable": self.observable,
            "observable_type": self.observable_type,
            "status": self.status,
            "found": self.found,
            "malicious": self.malicious,
            "score": self.score,
            "categories": self.categories,
            "detail": self.detail,
            "queried_at": self.queried_at,
            "cached": self.cached,
        }


class CTIFeed(ABC):
    """Un feed de threat intelligence externo."""

    name: str = "feed"

    @property
    @abstractmethod
    def configured(self) -> bool:
        """Si el feed tiene lo que necesita (API key, etc.) para consultar de verdad."""

    def query_ip(self, ip: str) -> FeedResult:
        return FeedResult(feed=self.name, observable=ip, observable_type="ip",
                          status=STATUS_NOT_FOUND, detail=f"{self.name} no soporta IPs")

    def query_domain(self, domain: str) -> FeedResult:
        return FeedResult(feed=self.name, observable=domain, observable_type="domain",
                          status=STATUS_NOT_FOUND, detail=f"{self.name} no soporta dominios")

    def query_hash(self, file_hash: str) -> FeedResult:
        return FeedResult(feed=self.name, observable=file_hash, observable_type="hash",
                          status=STATUS_NOT_FOUND, detail=f"{self.name} no soporta hashes")
