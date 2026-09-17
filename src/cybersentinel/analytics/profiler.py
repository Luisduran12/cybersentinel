"""
Perfil de comportamiento por entidad (Fase 4-B, tarea B1).

Traduce un `SecurityEvent` normalizado a observaciones sobre el usuario y el
host implicados, y decide cuándo persistir el aprendizaje. Es la única
puerta de entrada al `BaselineStore`: nada más en el proyecto debe escribir
baselines directamente, para que "qué cuenta como observación" esté en un
solo lugar.
"""
from __future__ import annotations

from pathlib import Path

from ..schema import SecurityEvent
from .baseline import BaselineStore, EntityBaseline


class EntityProfiler:
    """Aprende el perfil normal de usuarios y hosts a partir de eventos reales."""

    def __init__(self, store: BaselineStore | None = None,
                path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None
        self.store = store or (BaselineStore.load(self.path) if self.path else BaselineStore())

    def profile_user(self, username: str) -> EntityBaseline | None:
        return self.store.user(username)

    def profile_host(self, hostname: str) -> EntityBaseline | None:
        return self.store.host(hostname)

    def observe(self, event: SecurityEvent) -> None:
        """
        Actualiza el baseline del usuario y del host del evento, si los trae.

        Se llama **después** de calcular las desviaciones sobre el baseline
        anterior (ver `pipeline.py`): un evento no debe compararse contra un
        baseline que él mismo acaba de modificar, o la primera vez que algo
        raro ocurre ya seria "normal" para la comparación de ese mismo evento.
        """
        hora = event.timestamp.hour
        if event.user:
            self.store.learn_user(
                event.user, hour=hora, ip=event.src_ip, process=event.process_name,
                bytes_out=event.bytes_out, when=event.timestamp,
            )
        if event.host:
            self.store.learn_host(
                event.host, hour=hora, ip=event.dst_ip, process=event.process_name,
                bytes_out=event.bytes_out, when=event.timestamp,
            )

    def save(self) -> None:
        if self.path:
            self.store.save(self.path)
