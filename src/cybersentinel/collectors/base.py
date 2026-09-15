"""
Contrato común de los collectors.

Un collector traduce un formato de telemetría concreto a `SecurityEvent`. Ese es
**todo** el contrato: el motor de detección —Sigma, Isolation Forest, Markov,
correlación— no sabe ni debe saber de dónde vino el evento. Añadir una fuente
nueva no puede obligar a tocar ninguno de ellos.

Cuatro políticas que todos comparten, porque todas nacen del mismo principio:
**un dato problemático se procesa y se marca, nunca se descarta en silencio ni
se inventa**.

1. **Campo ausente** → `None`. Nunca una excepción, nunca un valor de relleno.
2. **Timestamp inválido** → hora de ingesta, con la etiqueta
   `timestamp_invalido` para que el analista sepa que esa hora no es del dato.
3. **Payload excesivo** → se rechaza con registro, no se trunca a medias ni
   tumba el proceso.
4. **Evento crudo** → se conserva íntegro en `event.raw`.
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ..schema import SecurityEvent

logger = logging.getLogger(__name__)

#: Tamaño máximo de un evento crudo. Un solo registro de varios MB suele ser un
#: error del emisor o un intento de agotar memoria, no telemetría legítima.
MAX_PAYLOAD_BYTES = 1_048_576          # 1 MiB

#: Longitud máxima de un campo de texto dentro del evento (línea de comandos,
#: mensaje). Se recorta y se marca, para no perder el resto del evento.
MAX_FIELD_CHARS = 8_192

TAG_INVALID_TIMESTAMP = "timestamp_invalido"
TAG_TRUNCATED_FIELD = "campo_truncado"
TAG_OVERSIZED = "payload_excesivo"


@dataclass
class CollectorResult:
    """
    Resultado de procesar un registro crudo.

    Se devuelve un resultado incluso cuando falla: quien llama necesita saber
    *qué* pasó, y un `None` a secas no lo dice.
    """

    event: SecurityEvent | None = None
    errors: list[str] = field(default_factory=list)
    annotations: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.event is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "errors": self.errors,
            "annotations": self.annotations,
            "event_id": self.event.event_id if self.event else None,
        }


class Collector(ABC):
    """Base de todos los collectors."""

    #: Identificador de la fuente. Viaja en `event.source` y en las etiquetas,
    #: de modo que el origen de cualquier detección es siempre reconstruible.
    source_type: str = "desconocida"

    def __init__(self, max_payload_bytes: int = MAX_PAYLOAD_BYTES) -> None:
        self.max_payload_bytes = max_payload_bytes
        self.stats: dict[str, int] = {
            "processed": 0, "failed": 0, "oversized": 0,
            "invalid_timestamp": 0, "truncated": 0,
        }

    # --- API pública ------------------------------------------------------
    def collect(self, raw: Any) -> CollectorResult:
        """
        Procesa un registro crudo. **Nunca lanza excepción.**

        Un collector que puede tumbar el proceso con un registro malformado no
        sirve para ingestión: basta un emisor defectuoso para detener la
        vigilancia de toda la organización.
        """
        try:
            exceso = self._check_size(raw)
            if exceso:
                self.stats["oversized"] += 1
                logger.warning("%s: %s", self.source_type, exceso)
                return CollectorResult(errors=[exceso], annotations=[TAG_OVERSIZED])

            resultado = self.parse(raw)
            if resultado.ok:
                self.stats["processed"] += 1
                if TAG_INVALID_TIMESTAMP in resultado.annotations:
                    self.stats["invalid_timestamp"] += 1
                if TAG_TRUNCATED_FIELD in resultado.annotations:
                    self.stats["truncated"] += 1
                # La procedencia se marca siempre, sin excepción.
                resultado.event.tags.append(f"collector:{self.source_type}")
                resultado.event.properties.setdefault("source_type", self.source_type)
            else:
                self.stats["failed"] += 1
            return resultado

        except Exception as exc:
            self.stats["failed"] += 1
            motivo = f"{type(exc).__name__}: {exc}"
            logger.error("%s: registro ilegible (%s)", self.source_type, motivo)
            return CollectorResult(errors=[motivo])

    def collect_many(self, registros: list[Any]) -> tuple[list[SecurityEvent], list[CollectorResult]]:
        """Procesa un lote. Devuelve los eventos válidos y todos los resultados."""
        resultados = [self.collect(r) for r in registros]
        return [r.event for r in resultados if r.ok], resultados

    @abstractmethod
    def parse(self, raw: Any) -> CollectorResult:
        """Traduce un registro de este formato concreto a `SecurityEvent`."""

    # --- Utilidades compartidas -------------------------------------------
    def _check_size(self, raw: Any) -> str | None:
        """Comprueba el tamaño antes de intentar interpretar nada."""
        if isinstance(raw, (bytes, bytearray)):
            tam = len(raw)
        elif isinstance(raw, str):
            tam = len(raw.encode("utf-8", errors="replace"))
        else:
            try:
                import json
                tam = len(json.dumps(raw, default=str).encode("utf-8"))
            except (TypeError, ValueError):
                return None
        if tam > self.max_payload_bytes:
            return (f"payload de {tam:,} bytes supera el maximo de "
                    f"{self.max_payload_bytes:,}; se rechaza el evento")
        return None

    @staticmethod
    def resolve_timestamp(valor: Any) -> tuple[datetime, list[str]]:
        """
        Resuelve la marca de tiempo del evento.

        Si no se reconoce se usa la hora de ingesta **y se etiqueta**: sin esa
        etiqueta, un reloj roto en el emisor desplazaría eventos dentro de la
        ventana de correlación sin que nadie lo notara.
        """
        if valor is not None:
            parseado = SecurityEvent.try_parse_timestamp(valor)
            if parseado is not None:
                return parseado, []
            logger.warning("Timestamp no reconocido (%r); se usa la hora de ingesta.", valor)
            return datetime.now(tz=timezone.utc), [TAG_INVALID_TIMESTAMP]
        return datetime.now(tz=timezone.utc), []

    @staticmethod
    def trim(texto: Any, limite: int = MAX_FIELD_CHARS) -> tuple[Any, list[str]]:
        """Recorta un campo de texto desmedido conservando el resto del evento."""
        if not isinstance(texto, str) or len(texto) <= limite:
            return texto, []
        return texto[:limite], [TAG_TRUNCATED_FIELD]

    @staticmethod
    def first(origen: dict[str, Any], *claves: str, default: Any = None) -> Any:
        """Primer valor no vacío entre varias claves candidatas."""
        for clave in claves:
            valor = origen.get(clave)
            if isinstance(valor, str):
                valor = valor.strip()
            if valor not in (None, "", "-"):
                return valor
        return default

    @staticmethod
    def to_int(valor: Any) -> int | None:
        try:
            return int(str(valor).strip())
        except (TypeError, ValueError):
            return None
