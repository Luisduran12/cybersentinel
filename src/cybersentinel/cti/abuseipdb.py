"""
Cliente real de AbuseIPDB (Fase 4-C, tarea C1).

API gratuita, 1.000 consultas/día. Requiere una API key propia
(`CYBERSENTINEL_ABUSEIPDB_KEY`); sin ella el feed se declara
`NOT_CONFIGURED` — no se inventa un resultado limpio.
"""
from __future__ import annotations

import logging
import os
from typing import Any

import httpx

from .feeds import (
    STATUS_ERROR, STATUS_NOT_CONFIGURED, STATUS_OK, STATUS_RATE_LIMITED,
    CTIFeed, FeedResult,
)

logger = logging.getLogger(__name__)

BASE_URL = "https://api.abuseipdb.com/api/v2/check"

#: A partir de qué abuseConfidenceScore (0-100) se considera malicioso.
#: AbuseIPDB documenta 25 como el umbral que ellos mismos recomiendan para
#: "probable actividad abusiva" sin generar demasiados falsos positivos.
MALICIOUS_THRESHOLD = 25


class AbuseIPDBFeed(CTIFeed):
    """Consulta reputación de IP contra AbuseIPDB."""

    name = "abuseipdb"

    def __init__(self, api_key: str | None = None, client: httpx.Client | None = None,
                timeout: float = 5.0) -> None:
        self.api_key = api_key or os.environ.get("CYBERSENTINEL_ABUSEIPDB_KEY")
        self._client = client
        self.timeout = timeout

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def _http(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=self.timeout)
        return self._client

    def query_ip(self, ip: str) -> FeedResult:
        if not self.configured:
            return FeedResult(
                feed=self.name, observable=ip, observable_type="ip",
                status=STATUS_NOT_CONFIGURED,
                detail="Falta CYBERSENTINEL_ABUSEIPDB_KEY: feed no consultado, no se inventa un resultado.",
            )
        try:
            respuesta = self._http().get(
                BASE_URL,
                headers={"Key": self.api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
            )
        except httpx.HTTPError as exc:
            logger.warning("AbuseIPDB: error de red consultando %s: %s", ip, exc)
            return FeedResult(feed=self.name, observable=ip, observable_type="ip",
                              status=STATUS_ERROR, detail=str(exc))

        if respuesta.status_code == 429:
            return FeedResult(feed=self.name, observable=ip, observable_type="ip",
                              status=STATUS_RATE_LIMITED,
                              detail="AbuseIPDB devolvió 429 (cuota diaria agotada).")
        if respuesta.status_code != 200:
            return FeedResult(feed=self.name, observable=ip, observable_type="ip",
                              status=STATUS_ERROR,
                              detail=f"HTTP {respuesta.status_code}: {respuesta.text[:200]}")

        try:
            datos: dict[str, Any] = respuesta.json()["data"]
        except (ValueError, KeyError) as exc:
            return FeedResult(feed=self.name, observable=ip, observable_type="ip",
                              status=STATUS_ERROR, detail=f"respuesta inesperada: {exc}")

        score = float(datos.get("abuseConfidenceScore", 0))
        return FeedResult(
            feed=self.name, observable=ip, observable_type="ip", status=STATUS_OK,
            found=datos.get("totalReports", 0) > 0,
            malicious=score >= MALICIOUS_THRESHOLD,
            score=score,
            categories=["c2"] if score >= 75 else (["suspicious"] if score >= MALICIOUS_THRESHOLD else []),
            detail=(
                f"abuseConfidenceScore={score:.0f}, "
                f"{datos.get('totalReports', 0)} reporte(s), "
                f"país={datos.get('countryCode', '?')}"
            ),
            raw=datos,
        )
