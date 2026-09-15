"""
Contrato de entrada de la API de ingestión.

La validación es deliberadamente **estricta en la forma y permisiva en el
contenido**: se exige lo mínimo que el normalizador necesita para enrutar el
evento (`source`) y se acepta cualquier otro campo, porque cada fuente de
telemetría trae los suyos y rechazarlos obligaría a modificar la API cada vez
que se añade un sensor.

Lo que NO se hace: inventar datos. Si falta el `event_id` se genera uno y se
deja constancia; si el `timestamp` no se reconoce, el evento se rechaza en vez
de sustituirlo por la hora actual, porque una marca de tiempo falsa contamina la
correlación temporal.
"""
from __future__ import annotations

import uuid
from typing import Any

from pydantic import BaseModel, Field, field_validator

from ..schema import SecurityEvent

#: Fuentes con parser dedicado. Otras se aceptan, pero el evento queda
#: etiquetado por el normalizador como `fuente_desconocida`.
KNOWN_SOURCES = {"sysmon", "auth", "firewall", "netflow", "web"}


class RawEvent(BaseModel):
    """Un evento de telemetría tal y como llega del sensor."""

    model_config = {"extra": "allow"}

    source: str = Field(..., min_length=1, max_length=64,
                        description="Origen de la telemetría (sysmon, auth, firewall...)")
    event_id: str | None = Field(default=None, max_length=256)
    timestamp: Any | None = Field(default=None,
                                  description="ISO-8601 o epoch Unix. Si falta, se usa la hora de recepción.")

    @field_validator("source")
    @classmethod
    def _source_limpia(cls, v: str) -> str:
        limpia = v.strip().lower()
        if not limpia:
            raise ValueError("source no puede estar vacío")
        return limpia

    @field_validator("timestamp")
    @classmethod
    def _timestamp_reconocible(cls, v: Any) -> Any:
        """
        Un timestamp presente pero ilegible es un error del emisor, no algo que
        el sistema deba adivinar: se rechaza el evento.
        """
        if v is None:
            return v
        if SecurityEvent.try_parse_timestamp(v) is None:
            raise ValueError(f"timestamp no reconocido: {v!r}")
        return v

    def to_record(self) -> tuple[dict[str, Any], list[str]]:
        """
        Convierte a un registro crudo para el normalizador.

        Devuelve también las anotaciones sobre lo que se completó, para que
        nada se rellene en silencio.
        """
        record = self.model_dump(exclude_none=True)
        anotaciones: list[str] = []

        if not record.get("event_id"):
            record["event_id"] = f"api-{uuid.uuid4().hex[:16]}"
            anotaciones.append("event_id_generado")
        if "timestamp" not in record:
            anotaciones.append("timestamp_de_recepcion")
        if record["source"] not in KNOWN_SOURCES:
            anotaciones.append("fuente_sin_parser_dedicado")
        return record, anotaciones


class EventBatch(BaseModel):
    """Lote de eventos. La API acepta uno o varios en la misma petición."""

    events: list[RawEvent] = Field(..., min_length=1, max_length=10_000)


class IngestResponse(BaseModel):
    """Respuesta de la ingestión: qué se aceptó y qué no, siempre explícito."""

    accepted: int
    rejected: int
    queued: int
    annotations: dict[str, int] = Field(default_factory=dict)
    errors: list[dict[str, Any]] = Field(default_factory=list)
