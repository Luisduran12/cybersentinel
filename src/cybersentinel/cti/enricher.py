"""
Enriquecimiento con feeds CTI en vivo (Fase 4-C, tareas C2/C3).

Distinto de `enrichment.py` (Fase 5, `CTIEnricher`): aquel cruza contra un
bundle STIX local sin red; `LiveCTIEnricher` habla con AbuseIPDB/OTX de
verdad, con caché de 1 hora por observable para no agotar la cuota gratuita.

Solo se consultan IPs públicas: preguntarle a un feed de reputación externo
por 10.0.0.5 no tiene sentido y solo gasta cuota.
"""
from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from typing import Any

from ..schema import SecurityEvent
from .cache import CTICache
from .feeds import STATUS_OK, CTIFeed, FeedResult

logger = logging.getLogger(__name__)


def _es_ip_publica(valor: str | None) -> bool:
    if not valor:
        return False
    try:
        ip = ipaddress.ip_address(valor)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)


@dataclass
class LiveEnrichment:
    """Lo que se sabe de un evento tras consultar los feeds en vivo."""

    results: list[FeedResult] = field(default_factory=list)

    @property
    def malicious_hits(self) -> list[FeedResult]:
        return [r for r in self.results if r.status == STATUS_OK and r.malicious]

    @property
    def narrative(self) -> str:
        """Texto legible por un analista, no solo datos crudos."""
        if not self.malicious_hits:
            return ""
        partes = []
        for r in self.malicious_hits:
            score_txt = f"{r.score:.0f}/100" if r.score is not None else "sin score"
            partes.append(
                f"{r.observable} reportada en {r.feed} (score {score_txt}). {r.detail}"
            )
        return " | ".join(partes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "results": [r.to_dict() for r in self.results],
            "malicious_hits": len(self.malicious_hits),
            "narrative": self.narrative,
        }


class LiveCTIEnricher:
    """Consulta feeds CTI en vivo por cada observable de un evento, con caché."""

    def __init__(self, feeds: list[CTIFeed], cache: CTICache | None = None) -> None:
        self.feeds = feeds
        self.cache = cache or CTICache()

    @property
    def configured_feeds(self) -> list[str]:
        return [f.name for f in self.feeds if f.configured]

    def _query_ip_cached(self, ip: str, feed: CTIFeed) -> FeedResult:
        cacheado = self.cache.get(feed.name, ip)
        if cacheado is not None:
            return cacheado
        resultado = feed.query_ip(ip)
        # Solo se cachean resultados que sí se consultaron de verdad: un
        # NOT_CONFIGURED cacheado impediría notar cuando se agrega la key.
        if resultado.status != "NOT_CONFIGURED":
            self.cache.put(resultado)
        return resultado

    def enrich_event(self, event: SecurityEvent) -> LiveEnrichment:
        ips = {ip for ip in (event.src_ip, event.dst_ip) if _es_ip_publica(ip)}
        resultados: list[FeedResult] = []
        for ip in sorted(ips):
            for feed in self.feeds:
                resultados.append(self._query_ip_cached(ip, feed))
        return LiveEnrichment(results=resultados)
