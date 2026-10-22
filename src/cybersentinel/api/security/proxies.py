"""
Qué proxies pueden contarnos la IP y el esquema reales del cliente.

`X-Forwarded-For` es una lista que **cada salto alarga por la derecha**: el
cliente puede escribir lo que quiera a la izquierda, y solo los últimos valores
los añadieron proxies propios. Leer el primero —lo que se hacía antes— regala
al atacante su propia IP de origen y, con ella, el límite anónimo por IP.

Reglas:

1. Las cabeceras reenviadas solo se miran si están activadas
   (`CYBERSENTINEL_TRUST_FORWARDED_FOR`) **y** la conexión TCP llega desde un
   proxy declarado (`CYBERSENTINEL_TRUSTED_PROXIES`, IPs o CIDR; por defecto,
   solo el bucle local).
2. Se toma el valor añadido por el proxy más externo de confianza: con
   `CYBERSENTINEL_TRUSTED_PROXY_HOPS=N` (por defecto 1), el N-ésimo empezando
   por la derecha.
3. Un valor que no es una IP válida se descarta y se usa la del par TCP.
"""
from __future__ import annotations

import ipaddress
import logging
import os
from collections.abc import Iterable
from dataclasses import dataclass

logger = logging.getLogger(__name__)

TRUST_ENV = "CYBERSENTINEL_TRUST_FORWARDED_FOR"
PROXIES_ENV = "CYBERSENTINEL_TRUSTED_PROXIES"
HOPS_ENV = "CYBERSENTINEL_TRUSTED_PROXY_HOPS"
DEFAULT_PROXIES = ("127.0.0.1/32", "::1/128")

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def _flag(nombre: str) -> bool:
    return os.environ.get(nombre, "").lower() in {"1", "true", "yes", "si", "sí"}


def _ip(valor: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        ip = ipaddress.ip_address(valor.strip())
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


@dataclass(frozen=True)
class ProxyTrust:
    """Política de confianza en cabeceras reenviadas."""

    enabled: bool = False
    networks: tuple[Network, ...] = ()
    hops: int = 1

    @classmethod
    def build(cls, enabled: bool, proxies: Iterable[str] | None = None,
              hops: int = 1) -> ProxyTrust:
        if hops < 1:
            raise ValueError("los saltos de proxy de confianza deben ser >= 1")
        redes = tuple(ipaddress.ip_network(p.strip(), strict=False)
                      for p in (DEFAULT_PROXIES if proxies is None else proxies) if p.strip())
        return cls(enabled=enabled, networks=redes, hops=hops)

    @classmethod
    def from_env(cls) -> ProxyTrust:
        activo = _flag(TRUST_ENV)
        crudo = os.environ.get(PROXIES_ENV)
        proxies = crudo.split(",") if crudo is not None else None
        politica = cls.build(activo, proxies, int(os.environ.get(HOPS_ENV, "1")))
        if activo and crudo is None:
            logger.warning(
                "%s está activo sin %s: solo se aceptarán cabeceras reenviadas "
                "desde el bucle local.", TRUST_ENV, PROXIES_ENV)
        return politica

    def trusts_peer(self, peer: str) -> bool:
        ip = _ip(peer)
        return ip is not None and any(ip in red for red in self.networks)

    def _pick(self, peer: str, cabecera: str) -> str | None:
        if not self.enabled or not cabecera or not self.trusts_peer(peer):
            return None
        valores = [v.strip() for v in cabecera.split(",") if v.strip()]
        if not valores:
            return None
        return valores[max(len(valores) - self.hops, 0)]

    def client_ip(self, peer: str, x_forwarded_for: str) -> str:
        """IP del cliente: la reenviada si viene de un proxy de confianza, si no la del par."""
        valor = self._pick(peer, x_forwarded_for)
        ip = _ip(valor) if valor else None
        return str(ip) if ip is not None else peer

    def forwarded_proto(self, peer: str, x_forwarded_proto: str) -> str | None:
        valor = self._pick(peer, x_forwarded_proto)
        return valor.lower() if valor else None

    def status(self) -> dict[str, object]:
        return {"enabled": self.enabled, "hops": self.hops,
                "trusted_proxies": [str(r) for r in self.networks]}
