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


# --- Contratos de la frontera de seguridad -------------------------------
class TokenRequest(BaseModel):
    """
    Petición de token de sesión.

    Las credenciales van en el cuerpo, no en la URL: una contraseña en la
    cadena de consulta acaba en los logs del proxy, en el historial del
    navegador y en la cabecera `Referer`.
    """

    username: str = Field(..., min_length=1, max_length=128)
    password: str = Field(..., min_length=1, max_length=512)


class TokenResponse(BaseModel):
    """Token emitido, con lo que el cliente necesita para usarlo y renovarlo."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int
    role: str
    permissions: list[str] = Field(default_factory=list)


class CreateKeyRequest(BaseModel):
    """Alta de una credencial de máquina."""

    label: str = Field(..., min_length=1, max_length=128,
                       description="Para qué sensor es. Aparece en la auditoría.")
    role: str = Field(default="sensor", max_length=32)
    expires_in_days: int | None = Field(default=365, ge=1, le=3650)


class CreatedKeyResponse(BaseModel):
    """
    Respuesta del alta. `api_key` es lo único que no se vuelve a mostrar:
    el almacén guarda solo su hash.
    """

    key_id: str
    api_key: str
    role: str
    label: str
    expires_at: str | None
    note: str = ("Guarda la clave ahora: no se puede recuperar. "
                 "Si se pierde, revócala y emite otra.")


# --- Contratos del panel SOC ---------------------------------------------
class IncidentPatch(BaseModel):
    """
    Cambio sobre un incidente. Todos los campos son opcionales y se aplican
    juntos: asignar y pasar a «en curso» es una sola acción del analista y debe
    ser una sola entrada coherente en la cronología, no dos peticiones que
    pueden quedarse a medias.
    """

    state: str | None = Field(default=None, description="new | triaged | in_progress | closed")
    owner: str | None = Field(default=None, max_length=128)
    severity: str | None = Field(default=None, description="low | medium | high | critical")
    resolution: str | None = Field(
        default=None,
        description="Obligatoria al cerrar: true_positive | false_positive | benign | duplicate")
    note: str = Field(default="", max_length=4000)
    clear_owner: bool = Field(default=False, description="Quitar el propietario actual.")


class NoteRequest(BaseModel):
    """Una anotación de la investigación. Se añade, nunca se sobrescribe."""

    text: str = Field(..., min_length=1, max_length=4000)


class DecisionRequest(BaseModel):
    """
    Veredicto del analista sobre el incidente (human-in-the-loop).

    Alimenta el mismo almacén de decisiones que la CLI `cybersentinel decide`:
    el panel no crea un circuito paralelo de etiquetado, porque dos fuentes de
    verdad sobre lo que un humano decidió son cero fuentes de verdad.
    """

    decision: str = Field(..., description="TRUE_POSITIVE | FALSE_POSITIVE | BENIGN | UNCERTAIN")
    reason: str = Field(default="", max_length=2000)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    close: bool = Field(default=True,
                        description="Cerrar el incidente con la resolución equivalente.")
