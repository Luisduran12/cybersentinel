"""
Módulo de Observabilidad.

Proporciona trazabilidad y rastreo de latencia por componente, de modo que
cualquier resultado del agente pueda reconstruirse hasta el evento que lo
originó.

Dos responsabilidades, deliberadamente separadas:

- **Latencia** por etapa, para el benchmark.
- **Estado** por etapa: qué se ejecutó, qué se saltó, qué falló y si se usó un
  mecanismo de respaldo. Sin esto, un componente que falla en silencio es
  indistinguible de uno que funciona, que es exactamente la clase de problema
  que un agente defensivo no puede permitirse.

El `run_id` identifica la ejecución completa; el `event_ref` identifica el evento
concreto dentro de ella. Juntos permiten responder "¿de dónde salió esta
conclusión?" sobre cualquier salida del sistema.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class StageStatus(str, Enum):
    """Resultado de ejecutar una etapa del pipeline."""

    OK = "OK"                      # se ejecutó y produjo resultado
    NO_DATA = "NO_DATA"            # se ejecutó, no había nada que aportar
    DISABLED = "DISABLED"          # apagada por configuración (ablation)
    UNAVAILABLE = "UNAVAILABLE"    # el recurso externo no está disponible
    ERROR = "ERROR"                # falló de forma inesperada


@dataclass
class StageRecord:
    """Lo que ocurrió en una etapa concreta, para un evento concreto."""

    name: str
    status: StageStatus = StageStatus.OK
    latency_ms: float = 0.0
    detail: str = ""
    fallback_used: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage": self.name,
            "status": self.status.value,
            "latency_ms": round(self.latency_ms, 4),
            "fallback_used": self.fallback_used,
            "detail": self.detail,
        }


def new_run_id() -> str:
    """Identificador único de una ejecución del agente."""
    return str(uuid.uuid4())


@dataclass
class TraceContext:
    """
    Traza de un evento a lo largo del pipeline.

    Mantiene los atributos `<etapa>_ms` que usaba el benchmark anterior, para no
    romper lo que ya dependía de ellos, y añade el registro de estado por etapa.
    """

    event_id: str
    run_id: str = field(default_factory=new_run_id)
    #: Huella estable del evento. `event_id` puede repetirse entre eventos
    #: (la telemetría Sysmon comparte el identificador de tipo); la huella no.
    event_ref: str = ""
    started_at: str = field(
        default_factory=lambda: datetime.now(tz=timezone.utc).isoformat(timespec="milliseconds")
    )

    # Latencias fraccionadas en milisegundos (compatibilidad hacia atrás)
    normalization_ms: float = 0.0
    sigma_ms: float = 0.0
    ml_ms: float = 0.0
    temporal_ms: float = 0.0
    cti_ms: float = 0.0
    rag_ms: float = 0.0
    llm_ms: float = 0.0

    stages: list[StageRecord] = field(default_factory=list)
    _start_times: dict[str, float] = field(default_factory=dict, repr=False)

    def start(self, component: str) -> None:
        """Inicia el cronómetro para un componente."""
        self._start_times[component] = time.perf_counter()

    def end(
        self,
        component: str,
        status: StageStatus = StageStatus.OK,
        detail: str = "",
        fallback_used: bool = False,
    ) -> StageRecord:
        """
        Detiene el cronómetro y registra qué ocurrió en la etapa.

        El estado es obligatorio en la práctica: una etapa que termina sin decir
        si produjo algo deja un hueco en la trazabilidad.
        """
        elapsed_ms = 0.0
        if component in self._start_times:
            elapsed_ms = (time.perf_counter() - self._start_times.pop(component)) * 1000.0
        if hasattr(self, f"{component}_ms"):
            setattr(self, f"{component}_ms", elapsed_ms)

        record = StageRecord(
            name=component, status=status, latency_ms=elapsed_ms,
            detail=detail, fallback_used=fallback_used,
        )
        self.stages.append(record)
        return record

    def skipped(self, component: str, reason: str = "deshabilitado por configuración") -> StageRecord:
        """Registra una etapa que no se ejecutó, en vez de omitirla del registro."""
        record = StageRecord(name=component, status=StageStatus.DISABLED, detail=reason)
        self.stages.append(record)
        return record

    def stage(self, name: str) -> StageRecord | None:
        """Devuelve el registro de una etapa, si se registró."""
        for record in self.stages:
            if record.name == name:
                return record
        return None

    def status_of(self, name: str) -> StageStatus | None:
        record = self.stage(name)
        return record.status if record else None

    @property
    def used_fallback(self) -> bool:
        """¿Alguna etapa tuvo que recurrir a un mecanismo de respaldo?"""
        return any(s.fallback_used for s in self.stages)

    @property
    def total_core_ms(self) -> float:
        """Latencia del pipeline central de detección (sin contexto)."""
        return self.normalization_ms + self.sigma_ms + self.ml_ms + self.temporal_ms + self.cti_ms

    @property
    def total_context_ms(self) -> float:
        """Latencia de las capas de contexto y explicación."""
        return self.rag_ms + self.llm_ms

    @property
    def total_ms(self) -> float:
        return self.total_core_ms + self.total_context_ms

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "event_id": self.event_id,
            "event_ref": self.event_ref,
            "started_at": self.started_at,
            "used_fallback": self.used_fallback,
            "stages": [s.to_dict() for s in self.stages],
            "latencies_ms": {
                "normalization": round(self.normalization_ms, 4),
                "sigma": round(self.sigma_ms, 4),
                "ml": round(self.ml_ms, 4),
                "temporal": round(self.temporal_ms, 4),
                "cti": round(self.cti_ms, 4),
                "rag": round(self.rag_ms, 4),
                "llm": round(self.llm_ms, 4),
                "total_core": round(self.total_core_ms, 4),
                "total_context": round(self.total_context_ms, 4),
                "total": round(self.total_ms, 4),
            },
        }
