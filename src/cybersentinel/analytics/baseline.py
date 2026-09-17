"""
Baseline de comportamiento por entidad (Fase 4-B, tarea B1).

Aprende, de forma incremental y en línea (no en un lote separado), qué es
"normal" para un usuario o un host: horas de actividad, IPs de origen,
procesos ejecutados y volumen de datos. Cada `EntityBaseline` lleva su propio
contador de observaciones porque una desviación calculada sobre 3 eventos no
significa lo mismo que una calculada sobre 3.000 — `confidence` es lo que le
permite a `DeviationDetector` (deviation.py) decidir si el baseline es lo
bastante sólido como para fiarse de él.

Nada aquí puntúa una desviación: eso es trabajo de `deviation.py`. Este
módulo solo observa y recuerda.
"""
from __future__ import annotations

import json
import statistics
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

#: Observaciones a partir de las cuales el baseline se considera plenamente
#: confiable. Por debajo, `confidence` escala linealmente: un baseline con 3
#: eventos puede decir "nunca visto", pero no debería disparar una alerta con
#: la misma fuerza que uno con 300.
MIN_OBSERVATIONS_FULL_CONFIDENCE = 50

#: Cuántas muestras de volumen (bytes_out) se conservan para el cálculo de
#: media/desviación estándar. Una ventana acotada, no todo el historial: el
#: comportamiento "normal" de hace seis meses no debería pesar igual que el de
#: ayer, y guardar todo el historial sin límite es una fuga de memoria.
VOLUME_WINDOW = 500


@dataclass
class EntityBaseline:
    """Lo que se sabe del comportamiento normal de una entidad (usuario u host)."""

    entity: str
    entity_type: str                      # "user" | "host"
    n_events: int = 0
    hours_seen: Counter[int] = field(default_factory=Counter)
    ips_seen: set[str] = field(default_factory=set)
    processes_seen: set[str] = field(default_factory=set)
    bytes_out_samples: deque[float] = field(
        default_factory=lambda: deque(maxlen=VOLUME_WINDOW))
    first_seen: str | None = None
    last_seen: str | None = None

    @property
    def confidence(self) -> float:
        """
        Qué tan fiable es este baseline, en [0, 1].

        No es una probabilidad: es una medida de cuántos datos lo respaldan,
        para que una alerta pueda decir "con solo 4 observaciones" en vez de
        presentar la misma certeza que un baseline de meses.
        """
        return min(self.n_events / MIN_OBSERVATIONS_FULL_CONFIDENCE, 1.0)

    @property
    def typical_hours(self) -> set[int]:
        """Horas en las que la entidad tiene actividad no anecdótica."""
        if not self.hours_seen:
            return set()
        total = sum(self.hours_seen.values())
        # Una hora con menos del 2% de la actividad total es ruido, no un
        # patrón: dos eventos de madrugada en seis meses no hacen que
        # "3am" sea una hora típica.
        umbral = max(total * 0.02, 1)
        return {h for h, n in self.hours_seen.items() if n >= umbral}

    @property
    def bytes_out_mean_std(self) -> tuple[float, float] | None:
        if len(self.bytes_out_samples) < 5:
            return None
        media = statistics.mean(self.bytes_out_samples)
        desv = statistics.pstdev(self.bytes_out_samples) if len(self.bytes_out_samples) > 1 else 0.0
        return media, desv

    def observe(self, *, hour: int | None, ip: str | None, process: str | None,
               bytes_out: float | None, when: datetime) -> None:
        self.n_events += 1
        if hour is not None:
            self.hours_seen[hour] += 1
        if ip:
            self.ips_seen.add(ip)
        if process:
            self.processes_seen.add(process)
        if bytes_out is not None:
            self.bytes_out_samples.append(float(bytes_out))
        ts = when.isoformat()
        if self.first_seen is None:
            self.first_seen = ts
        self.last_seen = ts

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity": self.entity,
            "entity_type": self.entity_type,
            "n_events": self.n_events,
            "hours_seen": dict(self.hours_seen),
            "ips_seen": sorted(self.ips_seen),
            "processes_seen": sorted(self.processes_seen),
            "bytes_out_samples": list(self.bytes_out_samples),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "EntityBaseline":
        b = cls(entity=d["entity"], entity_type=d["entity_type"])
        b.n_events = d.get("n_events", 0)
        b.hours_seen = Counter({int(k): v for k, v in d.get("hours_seen", {}).items()})
        b.ips_seen = set(d.get("ips_seen", []))
        b.processes_seen = set(d.get("processes_seen", []))
        b.bytes_out_samples = deque(d.get("bytes_out_samples", []), maxlen=VOLUME_WINDOW)
        b.first_seen = d.get("first_seen")
        b.last_seen = d.get("last_seen")
        return b


class BaselineStore:
    """
    Contenedor de baselines, separado por usuario y por host.

    Un mismo nombre puede existir en ambos mapas sin colisionar (un host
    llamado igual que un usuario es infrecuente pero no imposible), porque
    "normal para el usuario ana" y "normal para el host ana" son preguntas
    distintas.
    """

    def __init__(self) -> None:
        self.by_user: dict[str, EntityBaseline] = {}
        self.by_host: dict[str, EntityBaseline] = {}

    def _get_or_create(self, mapa: dict[str, EntityBaseline], entity: str,
                       entity_type: str) -> EntityBaseline:
        baseline = mapa.get(entity)
        if baseline is None:
            baseline = EntityBaseline(entity=entity, entity_type=entity_type)
            mapa[entity] = baseline
        return baseline

    def user(self, username: str) -> EntityBaseline | None:
        return self.by_user.get(username)

    def host(self, hostname: str) -> EntityBaseline | None:
        return self.by_host.get(hostname)

    def learn_user(self, username: str, *, hour: int | None, ip: str | None,
                   process: str | None, bytes_out: float | None,
                   when: datetime) -> EntityBaseline:
        b = self._get_or_create(self.by_user, username, "user")
        b.observe(hour=hour, ip=ip, process=process, bytes_out=bytes_out, when=when)
        return b

    def learn_host(self, hostname: str, *, hour: int | None, ip: str | None,
                   process: str | None, bytes_out: float | None,
                   when: datetime) -> EntityBaseline:
        b = self._get_or_create(self.by_host, hostname, "host")
        b.observe(hour=hour, ip=ip, process=process, bytes_out=bytes_out, when=when)
        return b

    def to_dict(self) -> dict[str, Any]:
        return {
            "by_user": {k: v.to_dict() for k, v in self.by_user.items()},
            "by_host": {k: v.to_dict() for k, v in self.by_host.items()},
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "BaselineStore":
        store = cls()
        store.by_user = {k: EntityBaseline.from_dict(v) for k, v in d.get("by_user", {}).items()}
        store.by_host = {k: EntityBaseline.from_dict(v) for k, v in d.get("by_host", {}).items()}
        return store

    def save(self, path: str | Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        return path

    @classmethod
    def load(cls, path: str | Path) -> "BaselineStore":
        p = Path(path)
        if not p.exists():
            return cls()
        return cls.from_dict(json.loads(p.read_text(encoding="utf-8")))
