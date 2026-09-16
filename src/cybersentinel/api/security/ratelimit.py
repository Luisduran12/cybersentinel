"""
Límite de caudal por cliente (cubo de fichas).

**Por qué hace falta si ya hay contrapresión en la cola.** La cola protege al
*servicio*: cuando se llena, devuelve 429 a todo el mundo. Eso significa que un
sensor mal configurado que envía en bucle deja sin servicio a los otros
cuarenta. El límite por cliente protege a los *clientes entre sí*: el que se
desmanda agota su propio cubo y nadie más lo nota. Son defensas distintas y
hacen falta las dos.

**Por qué cubo de fichas y no ventana fija.** Una ventana fija de 60 s permite
enviar el doble del límite en dos segundos, a caballo entre dos ventanas. El
cubo acota el ritmo *y* la ráfaga por separado: `rate` es lo sostenido,
`burst` lo que se tolera de golpe.

**Dos dimensiones, no una.** Se limitan peticiones por segundo y **eventos** por
segundo. Solo con peticiones, un cliente envía diez lotes de 10 000 eventos y
cumple el límite mientras entrega 100 000 eventos; solo con eventos, mil
peticiones vacías siguen costando mil validaciones.

**Límite declarado.** Los cubos viven en memoria del proceso. Con varias
réplicas, cada una aplica su propio límite y el efectivo es N veces el
configurado. Es correcto para un despliegue de un proceso y es una de las cosas
que la alta disponibilidad tendrá que mover a un almacén compartido; hasta
entonces, está dicho aquí y en la documentación en vez de ser una sorpresa.
"""
from __future__ import annotations

import os
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any

from .roles import Role

#: Tope de cubos vivos. Un diccionario indexado por IP sin tope es un vector de
#: agotamiento de memoria: basta con pedir desde muchas IPs falsificadas.
MAX_BUCKETS = int(os.environ.get("CYBERSENTINEL_RATELIMIT_MAX_BUCKETS", "50000"))


@dataclass
class LimitPolicy:
    """Lo que un cliente puede gastar: ritmo sostenido y ráfaga, en dos ejes."""

    requests_per_second: float
    request_burst: int
    events_per_second: float
    event_burst: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "requests_per_second": self.requests_per_second,
            "request_burst": self.request_burst,
            "events_per_second": self.events_per_second,
            "event_burst": self.event_burst,
        }


def _num(nombre: str, defecto: float) -> float:
    try:
        return float(os.environ.get(nombre, defecto))
    except ValueError:
        return defecto


#: Política por rol. Un sensor entrega telemetría a caudal industrial; una
#: persona pulsa botones. Darles el mismo límite obliga a elegir entre ahogar
#: al sensor o dejar barra libre al navegador comprometido de un analista.
DEFAULT_POLICIES: dict[str, LimitPolicy] = {
    Role.SENSOR.value: LimitPolicy(
        requests_per_second=_num("CYBERSENTINEL_RL_SENSOR_RPS", 50),
        request_burst=int(_num("CYBERSENTINEL_RL_SENSOR_BURST", 100)),
        events_per_second=_num("CYBERSENTINEL_RL_SENSOR_EPS", 20_000),
        event_burst=int(_num("CYBERSENTINEL_RL_SENSOR_EPS_BURST", 40_000)),
    ),
    Role.ANALYST.value: LimitPolicy(10, 20, 1_000, 2_000),
    Role.RESPONDER.value: LimitPolicy(10, 20, 1_000, 2_000),
    Role.AUDITOR.value: LimitPolicy(10, 20, 1_000, 2_000),
    Role.ADMIN.value: LimitPolicy(20, 40, 1_000, 2_000),
    # Sin autenticar: solo se llega a `/auth/token` y a las sondas de salud.
    # El límite es bajo a propósito —es lo que frena la fuerza bruta sobre
    # contraseñas antes incluso de que el bloqueo por cuenta entre en juego—.
    "anonymous": LimitPolicy(
        requests_per_second=_num("CYBERSENTINEL_RL_ANON_RPS", 1),
        request_burst=int(_num("CYBERSENTINEL_RL_ANON_BURST", 10)),
        events_per_second=0, event_burst=0,
    ),
}


@dataclass
class Decision:
    """Resultado de pedir permiso al limitador."""

    allowed: bool
    limit: float
    remaining: float
    retry_after: float
    scope: str  # "requests" | "events" | "-"

    def headers(self) -> dict[str, str]:
        """Cabeceras estándar para que el cliente se autorregule."""
        h = {
            "X-RateLimit-Limit": f"{self.limit:g}",
            "X-RateLimit-Remaining": f"{max(self.remaining, 0):.0f}",
        }
        if not self.allowed:
            h["Retry-After"] = f"{max(1, int(self.retry_after + 0.999))}"
        return h


class _Bucket:
    """Cubo de fichas. No usa candado propio: el del limitador ya lo protege."""

    __slots__ = ("tokens", "updated")

    def __init__(self, capacidad: float) -> None:
        self.tokens = float(capacidad)
        self.updated = time.monotonic()

    def take(self, coste: float, rate: float, capacidad: float) -> tuple[bool, float, float]:
        ahora = time.monotonic()
        self.tokens = min(capacidad, self.tokens + (ahora - self.updated) * rate)
        self.updated = ahora
        if coste <= self.tokens:
            self.tokens -= coste
            return True, self.tokens, 0.0
        faltan = coste - self.tokens
        espera = faltan / rate if rate > 0 else float("inf")
        return False, self.tokens, espera


class RateLimiter:
    """Cubos por (cliente, eje), con política por rol y memoria acotada."""

    def __init__(self, policies: dict[str, LimitPolicy] | None = None,
                 max_buckets: int = MAX_BUCKETS) -> None:
        self.policies = dict(policies or DEFAULT_POLICIES)
        self.max_buckets = max_buckets
        self._buckets: OrderedDict[str, _Bucket] = OrderedDict()
        self._lock = threading.Lock()
        self.blocked = 0
        self.allowed = 0

    def policy_for(self, role: str) -> LimitPolicy:
        return self.policies.get(role, self.policies["anonymous"])

    def _bucket(self, clave: str, capacidad: float) -> _Bucket:
        cubo = self._buckets.get(clave)
        if cubo is None:
            if len(self._buckets) >= self.max_buckets:
                # Se descarta el menos usado recientemente. Perder su estado
                # solo puede ser generoso con él, nunca restrictivo.
                self._buckets.popitem(last=False)
            cubo = _Bucket(capacidad)
            self._buckets[clave] = cubo
        else:
            self._buckets.move_to_end(clave)
        return cubo

    def check(self, client_id: str, role: str, *, events: int = 0) -> Decision:
        """
        ¿Puede este cliente hacer esta petición?

        Se cobra primero la petición y solo después los eventos: si la petición
        no cabe, no se gastan fichas de evento que el cliente no llegó a usar.
        """
        politica = self.policy_for(role)
        with self._lock:
            cubo = self._bucket(f"{client_id}|req", politica.request_burst)
            ok, restan, espera = cubo.take(
                1.0, politica.requests_per_second, politica.request_burst)
            if not ok:
                self.blocked += 1
                return Decision(False, politica.requests_per_second, restan,
                                espera, "requests")

            if events > 0 and politica.events_per_second > 0:
                cubo_ev = self._bucket(f"{client_id}|ev", politica.event_burst)
                ok_ev, restan_ev, espera_ev = cubo_ev.take(
                    float(events), politica.events_per_second, politica.event_burst)
                if not ok_ev:
                    self.blocked += 1
                    return Decision(False, politica.events_per_second, restan_ev,
                                    espera_ev, "events")
                self.allowed += 1
                return Decision(True, politica.events_per_second, restan_ev, 0.0, "events")

            if events > 0 and politica.events_per_second <= 0:
                # El rol no puede ingerir eventos. Lo decide la autorización,
                # no el limitador; aquí solo se declara que no se cobra nada.
                pass

            self.allowed += 1
            return Decision(True, politica.requests_per_second, restan, 0.0, "requests")

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "allowed": self.allowed,
                "blocked": self.blocked,
                "live_buckets": len(self._buckets),
                "max_buckets": self.max_buckets,
                "policies": {r: p.to_dict() for r, p in self.policies.items()},
                "scope_note": (
                    "los cubos son por proceso; con varias réplicas el límite "
                    "efectivo se multiplica por el número de réplicas"
                ),
            }

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()
            self.blocked = 0
            self.allowed = 0
