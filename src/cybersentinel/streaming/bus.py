"""
Cliente delgado sobre NATS JetStream.

Por qué NATS y no Kafka para este prototipo: un solo binario sin ZooKeeper/
KRaft, persistencia real vía JetStream (no es "fire and forget"), cliente
Python oficial y async-nativo, y huella de memoria compatible con correrlo en
un portátil de desarrollo. Kafka sigue siendo la opción correcta si el volumen
o el ecosistema de consumidores (Kafka Connect, Flink) ya lo exige — ver
`docs/PRODUCTION-ARCHITECTURE.md` para el criterio de cuándo migrar.

`nats-py` es una dependencia opcional (`pip install cybersentinel[streaming]`):
importar este módulo nunca falla por su ausencia, solo instanciar `EventBus` y
llamar a `connect()`.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Awaitable, Callable

logger = logging.getLogger(__name__)

#: Subject donde los collectors publican telemetría cruda, por fuente.
RAW_SUBJECT_FMT = "cybersentinel.raw.{source}"
#: Subject donde el normalizador publica el mismo evento ya en OCSF.
OCSF_SUBJECT_FMT = "cybersentinel.ocsf.{source}"
#: Nombre del stream de JetStream que persiste ambos subjects.
STREAM_NAME = "CYBERSENTINEL"
STREAM_SUBJECTS = ["cybersentinel.raw.*", "cybersentinel.ocsf.*"]


class EventBus:
    """
    Conexión a JetStream. Sin conectar, es inerte: no abre sockets en
    `__init__`, solo en `connect()`, para que construir uno en un test no
    requiera un servidor.
    """

    def __init__(self, url: str = "nats://127.0.0.1:4222") -> None:
        self.url = url
        self._nc: Any = None
        self._js: Any = None

    async def connect(self) -> None:
        try:
            import nats  # import perezoso: opcional a propósito
        except ImportError as exc:
            raise RuntimeError(
                "falta nats-py: instala con `pip install cybersentinel[streaming]`"
            ) from exc

        self._nc = await nats.connect(self.url)
        self._js = self._nc.jetstream()
        try:
            await self._js.add_stream(name=STREAM_NAME, subjects=STREAM_SUBJECTS)
        except Exception:
            # El stream ya existe: `add_stream` es idempotente en la práctica,
            # pero distintas versiones del servidor difieren en si lanzan o no.
            logger.debug("Stream %s ya existía o no se pudo crear de nuevo.", STREAM_NAME)

    async def close(self) -> None:
        if self._nc is not None:
            await self._nc.drain()
            self._nc = None
            self._js = None

    async def publish(self, subject: str, payload: dict[str, Any]) -> None:
        if self._js is None:
            raise RuntimeError("EventBus no conectado: llama a connect() primero")
        cuerpo = json.dumps(payload, default=str, ensure_ascii=False).encode("utf-8")
        await self._js.publish(subject, cuerpo)

    async def subscribe(
        self, subject: str, durable: str,
        callback: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        """
        Suscripción durable con ack manual: si `callback` lanza, el mensaje NO
        se confirma y JetStream lo reentrega. Perder un evento en silencio por
        una excepción del consumidor es exactamente lo que este diseño evita.
        """
        if self._js is None:
            raise RuntimeError("EventBus no conectado: llama a connect() primero")

        sub = await self._js.pull_subscribe(subject, durable=durable)
        while True:
            mensajes = await sub.fetch(1, timeout=5)
            for msg in mensajes:
                try:
                    datos = json.loads(msg.data.decode("utf-8"))
                    await callback(datos)
                except Exception:
                    logger.exception("Fallo procesando mensaje de %s; no se confirma.", subject)
                else:
                    await msg.ack()
