"""
Cliente real de AlienVault OTX (Fase 4-C, tarea C1).

API gratuita con API key propia (`CYBERSENTINEL_OTX_KEY`). Consulta pulses
(reportes de la comunidad) por IP, dominio o hash. Sin key, `NOT_CONFIGURED`.
"""
from __future__ import annotations

import logging
import os
from typing import Any

import httpx

from .feeds import STATUS_ERROR, STATUS_NOT_CONFIGURED, STATUS_OK, CTIFeed, FeedResult

logger = logging.getLogger(__name__)

BASE_URL = "https://otx.alienvault.com/api/v1/indicators"


class OTXFeed(CTIFeed):
    """Consulta pulses de OTX AlienVault por IP, dominio o hash de archivo."""

    name = "otx"

    def __init__(self, api_key: str | None = None, client: httpx.Client | None = None,
                timeout: float = 5.0) -> None:
        self.api_key = api_key or os.environ.get("CYBERSENTINEL_OTX_KEY")
        self._client = client
        self.timeout = timeout

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def _http(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=self.timeout)
        return self._client

    def _query(self, path: str, observable: str, observable_type: str) -> FeedResult:
        if not self.configured:
            return FeedResult(
                feed=self.name, observable=observable, observable_type=observable_type,
                status=STATUS_NOT_CONFIGURED,
                detail="Falta CYBERSENTINEL_OTX_KEY: feed no consultado.",
            )
        try:
            respuesta = self._http().get(
                f"{BASE_URL}/{path}/general",
                headers={"X-OTX-API-KEY": self.api_key},
            )
        except httpx.HTTPError as exc:
            logger.warning("OTX: error de red consultando %s: %s", observable, exc)
            return FeedResult(feed=self.name, observable=observable, observable_type=observable_type,
                              status=STATUS_ERROR, detail=str(exc))

        if respuesta.status_code != 200:
            return FeedResult(feed=self.name, observable=observable, observable_type=observable_type,
                              status=STATUS_ERROR,
                              detail=f"HTTP {respuesta.status_code}: {respuesta.text[:200]}")

        try:
            datos: dict[str, Any] = respuesta.json()
        except ValueError as exc:
            return FeedResult(feed=self.name, observable=observable, observable_type=observable_type,
                              status=STATUS_ERROR, detail=f"respuesta inesperada: {exc}")

        pulse_info = datos.get("pulse_info", {}) or {}
        n_pulses = pulse_info.get("count", 0)
        nombres = [p.get("name", "") for p in pulse_info.get("pulses", [])[:5]]
        # OTX no da un score numérico como AbuseIPDB; se deriva uno propio de
        # cuántos analistas de la comunidad ya lo reportaron como IOC, con
        # techo en 100 para que sea comparable con los demás feeds.
        score = min(float(n_pulses) * 10.0, 100.0) if n_pulses else 0.0

        return FeedResult(
            feed=self.name, observable=observable, observable_type=observable_type,
            status=STATUS_OK, found=n_pulses > 0, malicious=n_pulses > 0, score=score,
            categories=nombres,
            detail=f"{n_pulses} pulse(s) de la comunidad" if n_pulses else "sin pulses",
            raw=datos,
        )

    def query_ip(self, ip: str) -> FeedResult:
        return self._query(f"IPv4/{ip}", ip, "ip")

    def query_domain(self, domain: str) -> FeedResult:
        return self._query(f"domain/{domain}", domain, "domain")

    def query_hash(self, file_hash: str) -> FeedResult:
        return self._query(f"file/{file_hash}", file_hash, "hash")
