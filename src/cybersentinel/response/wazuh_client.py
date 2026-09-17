"""
Envío de respuesta a Wazuh (Fase 4-E, tarea E2: CyberSentinel → Wazuh).

Complementa a `collectors/wazuh.py` (Wazuh → CyberSentinel). Habla con la
API REST del Wazuh Manager (`PUT /active-response`, autenticación Bearer),
que es como Wazuh expone la ejecución de una respuesta activa sobre un
agente — el mismo mecanismo que usaría cualquier integración de terceros.

Mismo contrato que los feeds CTI y las integraciones de respuesta: real,
pero `NOT_CONFIGURED` sin URL/token, y `DRY_RUN` no manda nada.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any

import httpx

logger = logging.getLogger(__name__)

STATUS_OK = "OK"
STATUS_DRY_RUN = "DRY_RUN"
STATUS_NOT_CONFIGURED = "NOT_CONFIGURED"
STATUS_ERROR = "ERROR"


def _ahora() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class WazuhResponseClient:
    """Dispara una respuesta activa de Wazuh sobre un agente."""

    def __init__(self, base_url: str | None = None, token: str | None = None,
                client: httpx.Client | None = None, timeout: float = 5.0,
                verify_tls: bool = True) -> None:
        self.base_url = (base_url or os.environ.get("CYBERSENTINEL_WAZUH_URL") or "").rstrip("/")
        self.token = token or os.environ.get("CYBERSENTINEL_WAZUH_TOKEN")
        self._client = client
        self.timeout = timeout
        self.verify_tls = verify_tls

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.token)

    def _http(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=self.timeout, verify=self.verify_tls)
        return self._client

    def send_active_response(self, agent_id: str, command: str,
                             arguments: list[str] | None = None,
                             dry_run: bool = True) -> dict[str, Any]:
        """
        Ejecuta un comando de respuesta activa Wazuh sobre `agent_id`.

        `command` es el nombre del script de active-response ya desplegado
        en los agentes Wazuh (p.ej. `firewall-drop`, `disable-account`);
        CyberSentinel no lo inventa ni lo sube, solo lo invoca.
        """
        cuerpo = {
            "command": command, "arguments": arguments or [],
            "custom": True, "alert": {"data": {"srcip": None}},
        }
        if dry_run:
            return {"status": STATUS_DRY_RUN,
                    "detail": "Respuesta activa Wazuh no enviada (dry_run).",
                    "would_send": {"agent_id": agent_id, **cuerpo}, "at": _ahora()}
        if not self.configured:
            return {"status": STATUS_NOT_CONFIGURED,
                    "detail": "Falta CYBERSENTINEL_WAZUH_URL/CYBERSENTINEL_WAZUH_TOKEN.",
                    "at": _ahora()}
        try:
            respuesta = self._http().put(
                f"{self.base_url}/active-response",
                params={"agents_list": agent_id},
                json=cuerpo,
                headers={"Authorization": f"Bearer {self.token}"},
            )
            if respuesta.status_code >= 400:
                return {"status": STATUS_ERROR,
                        "detail": f"HTTP {respuesta.status_code}: {respuesta.text[:200]}",
                        "at": _ahora()}
            return {"status": STATUS_OK, "detail": "Respuesta activa enviada a Wazuh.",
                    "raw": respuesta.json() if respuesta.content else {}, "at": _ahora()}
        except httpx.HTTPError as exc:
            logger.warning("WazuhResponseClient: error de red: %s", exc)
            return {"status": STATUS_ERROR, "detail": str(exc), "at": _ahora()}
