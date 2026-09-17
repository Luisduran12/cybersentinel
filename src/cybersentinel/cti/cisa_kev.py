"""
Cliente real del catálogo CISA KEV (Fase 4-C, tarea C1).

Known Exploited Vulnerabilities: JSON público, sin API key. A diferencia de
AbuseIPDB/OTX (una consulta HTTP por observable), KEV se descarga completo
una vez y se consulta localmente — es un catálogo de unos pocos miles de
CVEs, no un servicio de lookup por IP.

LIMITACIÓN HONESTA: ningún collector actual (Sysmon, Linux, Firewall,
Suricata) normaliza un CVE o una versión de software identificable en
`SecurityEvent`. Este cliente es real y funcional (se puede preguntar
"¿está el CVE-2021-44228 explotado activamente?" y la respuesta es real,
no simulada), pero la correlación automática con "software detectado" que
pide el prompt no tiene, hoy, un campo de origen del que partir. Ver
docs/AGENT-CAPABILITIES.md, Bloque C.
"""
from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

#: Cuánto se conserva el catálogo antes de refrescarlo. CISA lo actualiza a
#: lo sumo a diario; refrescar cada hora sería puro desperdicio de ancho de
#: banda sin ningún dato nuevo que ganar.
REFRESH_INTERVAL = timedelta(hours=12)


class CisaKevFeed:
    """Catálogo de vulnerabilidades explotadas activamente, cacheado localmente."""

    def __init__(self, cache_path: str | Path | None = None,
                client: httpx.Client | None = None, timeout: float = 10.0) -> None:
        self.cache_path = Path(cache_path) if cache_path else None
        self._client = client
        self.timeout = timeout
        self._by_cve: dict[str, dict[str, Any]] = {}
        self._loaded_at: datetime | None = None
        self._lock = threading.Lock()
        if self.cache_path and self.cache_path.exists():
            self._load_from_disk()

    @property
    def loaded(self) -> bool:
        return bool(self._by_cve)

    def _http(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=self.timeout)
        return self._client

    def refresh(self, force: bool = False) -> str:
        """
        Descarga el catálogo si no está cargado o si venció el refresco.

        Devuelve un status en el mismo vocabulario que `feeds.FeedResult`
        (OK/ERROR), aunque esta clase no hereda de `CTIFeed`: no consulta un
        observable, consulta (y cachea) un catálogo entero.
        """
        with self._lock:
            si_vigente = (
                self._loaded_at is not None
                and datetime.now(tz=timezone.utc) - self._loaded_at < REFRESH_INTERVAL
            )
            if si_vigente and not force:
                return "OK"

        try:
            respuesta = self._http().get(KEV_URL)
            respuesta.raise_for_status()
            datos = respuesta.json()
        except (httpx.HTTPError, ValueError) as exc:
            logger.warning("CISA KEV: no se pudo refrescar el catálogo: %s", exc)
            return "ERROR"

        with self._lock:
            self._by_cve = {
                v["cveID"]: v for v in datos.get("vulnerabilities", [])
            }
            self._loaded_at = datetime.now(tz=timezone.utc)
        if self.cache_path:
            self._save_to_disk()
        logger.info("CISA KEV: %d CVEs cargados", len(self._by_cve))
        return "OK"

    def is_known_exploited(self, cve_id: str) -> bool:
        return cve_id.upper() in self._by_cve

    def detail_for(self, cve_id: str) -> dict[str, Any] | None:
        return self._by_cve.get(cve_id.upper())

    # --- Persistencia local ---------------------------------------------
    def _save_to_disk(self) -> None:
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self.cache_path.write_text(json.dumps({
            "loaded_at": self._loaded_at.isoformat(),
            "vulnerabilities": self._by_cve,
        }, ensure_ascii=False), encoding="utf-8")

    def _load_from_disk(self) -> None:
        try:
            datos = json.loads(self.cache_path.read_text(encoding="utf-8"))
            self._by_cve = datos.get("vulnerabilities", {})
            self._loaded_at = datetime.fromisoformat(datos["loaded_at"])
        except (json.JSONDecodeError, OSError, KeyError, ValueError):
            self._by_cve = {}
            self._loaded_at = None
