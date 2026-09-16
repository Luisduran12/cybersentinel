"""
Cifrado en tránsito: qué conexiones se aceptan y cuáles no.

Con autenticación real pero sin TLS, todo lo de `guard.py` es decorado: la
contraseña del analista y la clave del sensor viajan legibles por la red, y
quien las capture no necesita romper nada. Por eso la política aquí **falla
cerrada**, y no con un aviso en el log que nadie lee.

La regla es una sola y no necesita configuración:

> El texto en claro solo se acepta desde la propia máquina.

- Desde **bucle local** (`127.0.0.1`, `::1`) se permite HTTP: es el caso de
  desarrollo, y ahí no hay red que escuchar.
- Desde **cualquier otro origen** se exige TLS, ya sea terminado por el propio
  servicio (`uvicorn --ssl-keyfile`) o por un proxy de confianza que lo declare
  en `X-Forwarded-Proto`.
- Si no hay ninguna de las dos cosas, la petición se rechaza con **403** y un
  cuerpo que explica qué falta.

**Por qué no un aviso en vez de un rechazo.** Un despliegue que funciona sin
TLS se queda sin TLS: el aviso se pierde entre los mensajes de arranque y nadie
vuelve a mirarlo. Un 403 en la primera petición se arregla el primer día.

**La escotilla y su precio.** `CYBERSENTINEL_ALLOW_PLAINTEXT=1` desactiva la
comprobación, para el caso real de un terminador TLS que no añade cabeceras de
reenvío. Queda declarado en el arranque y en `/api/v1/ready`, para que nadie
pueda decir después que no lo sabía.

**Lo que esto NO hace.** No cifra nada por sí mismo: comprueba que alguien lo
haya hecho. El cifrado lo pone uvicorn con un certificado o el proxy de delante.
Y no valida el certificado del cliente: no hay mTLS.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

#: Direcciones desde las que se tolera texto en claro. No hay red que espiar
#: entre un proceso y sí mismo.
LOOPBACK = {"127.0.0.1", "::1", "localhost", "::ffff:127.0.0.1"}

#: Vida de la política HSTS que se anuncia cuando la conexión ya es segura.
#: Un año es lo que recomienda la lista de precarga; menos convierte el
#: encabezado en un gesto.
HSTS_MAX_AGE = 31_536_000


def _flag(nombre: str) -> bool:
    return os.environ.get(nombre, "").lower() in {"1", "true", "yes", "si", "sí"}


@dataclass
class TransportPolicy:
    """Decide si una conexión puede llevar credenciales."""

    allow_plaintext: bool = False
    trust_forwarded: bool = False

    @classmethod
    def from_env(cls) -> TransportPolicy:
        politica = cls(
            allow_plaintext=_flag("CYBERSENTINEL_ALLOW_PLAINTEXT"),
            trust_forwarded=_flag("CYBERSENTINEL_TRUST_FORWARDED_FOR"),
        )
        if politica.allow_plaintext:
            logger.warning(
                "CYBERSENTINEL_ALLOW_PLAINTEXT está activo: se aceptarán "
                "credenciales por HTTP desde cualquier origen. Solo es correcto "
                "si hay un terminador TLS delante que no añade X-Forwarded-Proto."
            )
        return politica

    # --- Clasificación de la conexión ------------------------------------
    @staticmethod
    def client_host(request: Any) -> str:
        return request.client.host if request.client else ""

    def is_local(self, request: Any) -> bool:
        return self.client_host(request) in LOOPBACK

    def is_secure(self, request: Any) -> bool:
        """
        ¿La conexión llega cifrada?

        `X-Forwarded-Proto` solo se mira si hay un proxy declarado como de
        confianza: sin esa condición, cualquiera se declara seguro añadiendo
        una cabecera y la comprobación no sirve de nada.
        """
        if request.url.scheme == "https":
            return True
        if self.trust_forwarded:
            reenviado = request.headers.get("x-forwarded-proto", "")
            return reenviado.split(",")[0].strip().lower() == "https"
        return False

    # --- Veredicto --------------------------------------------------------
    def refusal_reason(self, request: Any) -> str | None:
        """`None` si la petición puede seguir; si no, por qué se rechaza."""
        if self.is_secure(request) or self.is_local(request) or self.allow_plaintext:
            return None
        return (
            "esta API exige TLS desde orígenes remotos: las credenciales "
            "viajarían en claro. Termina TLS en el servicio "
            "(uvicorn --ssl-certfile --ssl-keyfile) o en un proxy que declare "
            "X-Forwarded-Proto y activa CYBERSENTINEL_TRUST_FORWARDED_FOR."
        )

    def response_headers(self, request: Any) -> dict[str, str]:
        """
        HSTS, **solo** sobre una conexión ya segura.

        Anunciarlo por HTTP no protege de nada —el atacante que puede leer la
        respuesta puede quitarlo— y puede dejar inaccesible un despliegue de
        laboratorio que luego no tenga certificado.
        """
        if self.is_secure(request):
            return {"Strict-Transport-Security":
                    f"max-age={HSTS_MAX_AGE}; includeSubDomains"}
        return {}

    def status(self) -> dict[str, Any]:
        """Lo que `/ready` publica sobre el transporte."""
        return {
            "plaintext_allowed_from": "solo bucle local" if not self.allow_plaintext
                                      else "cualquier origen (ALLOW_PLAINTEXT activo)",
            "trusts_forwarded_proto": self.trust_forwarded,
            "warning": (
                "CYBERSENTINEL_ALLOW_PLAINTEXT está activo: se aceptan "
                "credenciales sin cifrar desde cualquier origen"
            ) if self.allow_plaintext else None,
        }
