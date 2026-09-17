"""
Integraciones reales de respuesta Nivel 1 (Fase 4-E, tarea E1).

Cuatro acciones automáticas, sin aprobación humana, cada una con un cliente
real (no `ExternalIntegrationMock`):

- `WebhookNotifier`  → POST real a un webhook de Slack/Teams.
- `EmailNotifier`    → envío real por SMTP.
- `TicketWriter`     → escribe un JSON real, compatible con Jira/ServiceNow,
  a disco (no hay API de terceros que llamar sin credenciales de un
  proyecto real; el artefacto en sí es el entregable).
- `IOCBlocklist`      → añade a una lista local real de bloqueo, sin
  necesitar ninguna credencial externa.

Todas respetan `dry_run` de la misma manera: con `dry_run=True` (el default
en todo el sistema, `CYBERSENTINEL_DRY_RUN`), **no se ejecuta nada real**
— ni una petición HTTP, ni un correo, ni una escritura a disco — y se
devuelve una descripción de lo que se habría hecho. Es la interpretación
más estricta de "DRY_RUN=true siempre por defecto": no es que el efecto sea
reversible, es que no hay efecto.

Sin `dry_run`, cada integración sigue el mismo contrato que los feeds CTI
(Fase 4-C): sin credencial configurada, `NOT_CONFIGURED`, nunca un éxito
fingido.
"""
from __future__ import annotations

import json
import logging
import os
import smtplib
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger(__name__)

STATUS_OK = "OK"
STATUS_DRY_RUN = "DRY_RUN"
STATUS_NOT_CONFIGURED = "NOT_CONFIGURED"
STATUS_ERROR = "ERROR"


def _ahora() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class WebhookNotifier:
    """Webhook de Slack/Teams real (POST de un JSON con `text`)."""

    def __init__(self, webhook_url: str | None = None, client: httpx.Client | None = None,
                timeout: float = 5.0) -> None:
        self.webhook_url = webhook_url or os.environ.get("CYBERSENTINEL_SLACK_WEBHOOK_URL")
        self._client = client
        self.timeout = timeout

    def _http(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=self.timeout)
        return self._client

    def send(self, text: str, dry_run: bool = True) -> dict[str, Any]:
        if dry_run:
            return {"status": STATUS_DRY_RUN, "detail": "Webhook no enviado (dry_run).",
                    "would_send": {"text": text}, "at": _ahora()}
        if not self.webhook_url:
            return {"status": STATUS_NOT_CONFIGURED,
                    "detail": "Falta CYBERSENTINEL_SLACK_WEBHOOK_URL.", "at": _ahora()}
        try:
            respuesta = self._http().post(self.webhook_url, json={"text": text})
            if respuesta.status_code >= 400:
                return {"status": STATUS_ERROR,
                        "detail": f"HTTP {respuesta.status_code}: {respuesta.text[:200]}",
                        "at": _ahora()}
            return {"status": STATUS_OK, "detail": "Webhook enviado.", "at": _ahora()}
        except httpx.HTTPError as exc:
            logger.warning("WebhookNotifier: error de red: %s", exc)
            return {"status": STATUS_ERROR, "detail": str(exc), "at": _ahora()}


class EmailNotifier:
    """Envío real por SMTP."""

    def __init__(self, host: str | None = None, port: int | None = None,
                username: str | None = None, password: str | None = None,
                sender: str | None = None, recipient: str | None = None,
                smtp_client: Any | None = None, timeout: float = 5.0) -> None:
        self.host = host or os.environ.get("CYBERSENTINEL_SMTP_HOST")
        self.port = port or int(os.environ.get("CYBERSENTINEL_SMTP_PORT", "587"))
        self.username = username or os.environ.get("CYBERSENTINEL_SMTP_USER")
        self.password = password or os.environ.get("CYBERSENTINEL_SMTP_PASSWORD")
        self.sender = sender or os.environ.get("CYBERSENTINEL_SMTP_FROM")
        self.recipient = recipient or os.environ.get("CYBERSENTINEL_SMTP_TO")
        #: Inyectable para pruebas: un objeto con la misma interfaz que
        #: `smtplib.SMTP` (`starttls`, `login`, `send_message`, uso como
        #: context manager). Sin esto, se crea un `smtplib.SMTP` real.
        self._smtp_client = smtp_client
        self.timeout = timeout

    @property
    def configured(self) -> bool:
        return bool(self.host and self.sender and self.recipient)

    def send(self, subject: str, body: str, dry_run: bool = True) -> dict[str, Any]:
        if dry_run:
            return {"status": STATUS_DRY_RUN, "detail": "Correo no enviado (dry_run).",
                    "would_send": {"subject": subject, "to": self.recipient}, "at": _ahora()}
        if not self.configured:
            return {"status": STATUS_NOT_CONFIGURED,
                    "detail": "Falta CYBERSENTINEL_SMTP_HOST/FROM/TO.", "at": _ahora()}
        mensaje = EmailMessage()
        mensaje["Subject"] = subject
        mensaje["From"] = self.sender
        mensaje["To"] = self.recipient
        mensaje.set_content(body)
        try:
            if self._smtp_client is not None:
                cliente = self._smtp_client
                cliente.send_message(mensaje)
            else:
                with smtplib.SMTP(self.host, self.port, timeout=self.timeout) as cliente:
                    cliente.starttls()
                    if self.username and self.password:
                        cliente.login(self.username, self.password)
                    cliente.send_message(mensaje)
            return {"status": STATUS_OK, "detail": "Correo enviado.", "at": _ahora()}
        except (smtplib.SMTPException, OSError) as exc:
            logger.warning("EmailNotifier: error enviando correo: %s", exc)
            return {"status": STATUS_ERROR, "detail": str(exc), "at": _ahora()}


class TicketWriter:
    """
    Escribe un ticket real (JSON compatible con la API de Jira/ServiceNow)
    a disco. No hay integración de terceros que llamar sin un proyecto real
    y credenciales propias; el archivo generado es el entregable de esta
    fase, y consumirlo desde Jira/ServiceNow es cambiar el destino de una
    escritura, no reescribir esta clase.
    """

    def __init__(self, output_dir: str | Path | None = None) -> None:
        self.output_dir = Path(output_dir) if output_dir else None

    def create(self, ticket: dict[str, Any], dry_run: bool = True) -> dict[str, Any]:
        if dry_run:
            return {"status": STATUS_DRY_RUN, "detail": "Ticket no creado (dry_run).",
                    "would_create": ticket, "at": _ahora()}
        if not self.output_dir:
            return {"status": STATUS_NOT_CONFIGURED,
                    "detail": "Falta directorio de salida para tickets.", "at": _ahora()}
        self.output_dir.mkdir(parents=True, exist_ok=True)
        ruta = self.output_dir / f"ticket-{ticket.get('action_id', _ahora())}.json"
        ruta.write_text(json.dumps(ticket, indent=2, ensure_ascii=False), encoding="utf-8")
        return {"status": STATUS_OK, "detail": f"Ticket escrito en {ruta}",
                "path": str(ruta), "at": _ahora()}


class IOCBlocklist:
    """Lista local de IOCs bloqueados. Real, local, sin credencial externa."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None

    def _leer(self) -> list[dict[str, Any]]:
        if not self.path or not self.path.exists():
            return []
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return []

    def add(self, ioc_type: str, value: str, reason: str,
           dry_run: bool = True) -> dict[str, Any]:
        entrada = {"type": ioc_type, "value": value, "reason": reason, "added_at": _ahora()}
        if dry_run:
            return {"status": STATUS_DRY_RUN, "detail": "IOC no registrado (dry_run).",
                    "would_add": entrada, "at": _ahora()}
        if not self.path:
            return {"status": STATUS_NOT_CONFIGURED,
                    "detail": "Falta ruta de la lista de bloqueo.", "at": _ahora()}
        actuales = self._leer()
        if any(e["type"] == ioc_type and e["value"] == value for e in actuales):
            return {"status": STATUS_OK, "detail": "IOC ya estaba en la lista (idempotente).",
                    "at": _ahora()}
        actuales.append(entrada)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(actuales, indent=2, ensure_ascii=False), encoding="utf-8")
        return {"status": STATUS_OK, "detail": f"IOC {ioc_type}:{value} registrado.",
                "path": str(self.path), "at": _ahora()}

    def contains(self, ioc_type: str, value: str) -> bool:
        return any(e["type"] == ioc_type and e["value"] == value for e in self._leer())
