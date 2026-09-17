"""
Detección de desviaciones de comportamiento (Fase 4-B, tareas B2/B3).

Compara un evento contra el `EntityBaseline` de su usuario y de su host, y
produce `Deviation`s explicables: cada una dice qué se esperaba, qué pasó y
con cuánta confianza lo dice. No decide sola si algo es un incidente — eso lo
decide `DetectionEvidence.hybrid_score` en el pipeline, exactamente igual que
con una regla Sigma o una anomalía de ML.
"""
from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from typing import Any

from ..schema import SecurityEvent
from .baseline import EntityBaseline
from .profiler import EntityProfiler

#: Por debajo de esto, un baseline no tiene suficiente historia como para que
#: "nunca visto" signifique algo. Con 3 eventos, absolutamente todo es "nunca
#: visto"; eso no es una desviación, es la ausencia de datos.
MIN_OBSERVATIONS_FOR_ALERT = 10

#: Umbral de z-score para volumen de datos. 3 desviaciones estándar es el
#: punto de corte clásico para "estadísticamente inusual" sin generar ruido
#: constante en distribuciones con cola larga (el tráfico de red la tiene).
VOLUME_ZSCORE_THRESHOLD = 3.0


@dataclass
class Deviation:
    """Una desviación de comportamiento detectada, con su explicación."""

    entity: str
    entity_type: str                # "user" | "host"
    kind: str                       # unusual_hour | unknown_ip | unknown_process | unusual_volume
    score: float                    # 0..100
    confidence: float                # confianza del baseline que respalda la desviación (0..1)
    explanation: str
    mitre_technique: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity": self.entity,
            "entity_type": self.entity_type,
            "kind": self.kind,
            "score": round(self.score, 1),
            "confidence": round(self.confidence, 3),
            "explanation": self.explanation,
            "mitre_technique": self.mitre_technique,
        }


class DeviationDetector:
    """Evalúa un evento contra los baselines de su usuario y de su host."""

    def evaluate(self, event: SecurityEvent, profiler: EntityProfiler) -> list[Deviation]:
        desviaciones: list[Deviation] = []

        if event.user:
            baseline = profiler.profile_user(event.user)
            if baseline and baseline.n_events >= MIN_OBSERVATIONS_FOR_ALERT:
                hora = self._check_unusual_hour(event, baseline)
                if hora:
                    desviaciones.append(hora)
                ip = self._check_unknown_ip(event, baseline, campo=event.src_ip)
                if ip:
                    desviaciones.append(ip)

        if event.host:
            baseline = profiler.profile_host(event.host)
            if baseline and baseline.n_events >= MIN_OBSERVATIONS_FOR_ALERT:
                proc = self._check_unknown_process(event, baseline)
                if proc:
                    desviaciones.append(proc)
                vol = self._check_unusual_volume(event, baseline)
                if vol:
                    desviaciones.append(vol)

        return desviaciones

    # ------------------------------------------------------------------
    def _check_unusual_hour(self, event: SecurityEvent, baseline: EntityBaseline) -> Deviation | None:
        hora = event.timestamp.hour
        if hora in baseline.typical_hours:
            return None
        rango = self._describe_hours(baseline.typical_hours)
        return Deviation(
            entity=event.user, entity_type="user", kind="unusual_hour",
            score=70.0, confidence=baseline.confidence,
            explanation=(
                f"El usuario '{event.user}' normalmente está activo en horas "
                f"{rango}; este evento ocurrió a las {hora:02d}:xx."
            ),
            mitre_technique="T1078",
        )

    def _check_unknown_ip(self, event: SecurityEvent, baseline: EntityBaseline,
                          campo: str | None) -> Deviation | None:
        if not campo or campo in baseline.ips_seen:
            return None
        return Deviation(
            entity=event.user, entity_type="user", kind="unknown_ip",
            score=65.0, confidence=baseline.confidence,
            explanation=(
                f"El usuario '{event.user}' nunca se había conectado desde "
                f"{campo} en las {baseline.n_events} observaciones registradas."
            ),
            mitre_technique="T1078",
        )

    def _check_unknown_process(self, event: SecurityEvent, baseline: EntityBaseline) -> Deviation | None:
        if not event.process_name or event.process_name in baseline.processes_seen:
            return None
        return Deviation(
            entity=event.host, entity_type="host", kind="unknown_process",
            score=55.0, confidence=baseline.confidence,
            explanation=(
                f"El proceso '{event.process_name}' nunca se había visto en el "
                f"host '{event.host}' en las {baseline.n_events} observaciones registradas."
            ),
            mitre_technique=None,
        )

    def _check_unusual_volume(self, event: SecurityEvent, baseline: EntityBaseline) -> Deviation | None:
        if event.bytes_out is None:
            return None
        stats = baseline.bytes_out_mean_std
        if stats is None:
            return None
        media, desv = stats
        if desv <= 0:
            return None
        zscore = (event.bytes_out - media) / desv
        if zscore < VOLUME_ZSCORE_THRESHOLD:
            return None
        score = min(50.0 + (zscore - VOLUME_ZSCORE_THRESHOLD) * 10.0, 100.0)
        return Deviation(
            entity=event.host, entity_type="host", kind="unusual_volume",
            score=score, confidence=baseline.confidence,
            explanation=(
                f"El host '{event.host}' transfirió {event.bytes_out:,.0f} bytes; "
                f"su volumen típico es {media:,.0f} ± {desv:,.0f} bytes "
                f"({zscore:.1f} desviaciones estándar por encima)."
            ),
            mitre_technique=None,
        )

    @staticmethod
    def _describe_hours(horas: set[int]) -> str:
        if not horas:
            return "sin patrón horario claro"
        ordenadas = sorted(horas)
        return "{" + ", ".join(f"{h:02d}:00" for h in ordenadas) + "}"
