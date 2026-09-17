"""
Caché local de consultas CTI (Fase 4-C, tarea C2).

AbuseIPDB da 1.000 consultas gratuitas al día; OTX tiene su propio límite no
documentado con exactitud. Sin caché, un incidente con la misma IP repetida
en 50 eventos (un beacon, por ejemplo) consumiría 50 consultas por sí solo.
La regla del prompt es explícita: no repetir una consulta a la misma IP en
menos de una hora.

Se persiste a disco (JSON) para que la caché sobreviva un reinicio del
servicio — perderla en cada reinicio derrotaría el propósito en un proceso
de larga duración como la API de ingestión.
"""
from __future__ import annotations

import json
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .feeds import FeedResult

DEFAULT_TTL_SECONDS = 3600     # 1 hora, tal como pide el prompt.


class CTICache:
    """Caché con expiración por entrada, clave = (feed, observable)."""

    def __init__(self, ttl_seconds: int = DEFAULT_TTL_SECONDS,
                path: str | Path | None = None) -> None:
        self.ttl = timedelta(seconds=ttl_seconds)
        self.path = Path(path) if path else None
        self._lock = threading.Lock()
        self._store: dict[str, tuple[str, dict[str, Any]]] = {}   # key -> (expires_at_iso, result_dict)
        self.hits = 0
        self.misses = 0
        if self.path:
            self._load()

    @staticmethod
    def _key(feed: str, observable: str) -> str:
        return f"{feed}:{observable.lower()}"

    def get(self, feed: str, observable: str) -> FeedResult | None:
        clave = self._key(feed, observable)
        with self._lock:
            entrada = self._store.get(clave)
            if entrada is None:
                self.misses += 1
                return None
            expira_en, datos = entrada
            if datetime.fromisoformat(expira_en) < datetime.now(tz=timezone.utc):
                del self._store[clave]
                self.misses += 1
                return None
            self.hits += 1
            resultado = FeedResult(**{**datos, "cached": True})
            return resultado

    def put(self, resultado: FeedResult) -> None:
        clave = self._key(resultado.feed, resultado.observable)
        expira_en = (datetime.now(tz=timezone.utc) + self.ttl).isoformat()
        with self._lock:
            self._store[clave] = (expira_en, resultado.to_dict() | {"raw": resultado.raw})
        if self.path:
            self._save()

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {"entries": len(self._store), "hits": self.hits, "misses": self.misses}

    # --- Persistencia -------------------------------------------------------
    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            datos = json.loads(self.path.read_text(encoding="utf-8"))
            self._store = {k: tuple(v) for k, v in datos.items()}
        except (json.JSONDecodeError, OSError, ValueError):
            self._store = {}

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            self.path.write_text(json.dumps(self._store, ensure_ascii=False), encoding="utf-8")
