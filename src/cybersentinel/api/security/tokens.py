"""
Emisión y verificación de tokens de sesión (JWT HS256).

**Por qué escrito a mano y no con una biblioteca.** El proyecto sostiene una
regla: ninguna dependencia nueva que no aporte algo que la biblioteca estándar
no dé. Un JWT HS256 es base64url de dos objetos JSON y un HMAC-SHA256 —todo en
`hashlib`, `hmac`, `base64` y `json`—. Lo que sí hace falta es implementar las
defensas que las bibliotecas traen de serie, y aquí están explícitas:

- **Algoritmo fijado.** Se exige `alg == "HS256"` *antes* de verificar nada. Sin
  esto aparece la confusión de algoritmos: un atacante cambia la cabecera a
  `"none"` y el token pasa sin firma.
- **Comparación en tiempo constante** (`hmac.compare_digest`) para no filtrar la
  firma byte a byte por el tiempo de respuesta.
- **Caducidad obligatoria.** Un token sin `exp` se rechaza; no se le asigna una
  por defecto, porque un token eterno emitido por error no se distingue de uno
  legítimo.
- **Margen de reloj acotado** (`LEEWAY_S`). Sin margen, una desviación de dos
  segundos entre nodos invalida tokens recién emitidos; con margen ilimitado,
  la caducidad no significa nada.

**Lo que esto NO es.** No es OIDC. No hay claves asimétricas, ni rotación por
`kid`, ni proveedor externo. Para integrarse con el directorio corporativo hay
que sustituir `verify()` por la validación RS256 contra el JWKS del proveedor;
el resto del sistema —roles, permisos, límites— no cambia, porque solo consume
el `Principal` que sale de aquí.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
import uuid
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

#: Variable de entorno de la que se lee el secreto de firma.
JWT_SECRET_ENV = "CYBERSENTINEL_JWT_SECRET"

#: Longitud mínima del secreto. 32 bytes es el tamaño del bloque de SHA-256:
#: por debajo, la clave aporta menos entropía que la propia función hash.
MIN_SECRET_BYTES = 32

#: Margen de desviación de reloj aceptado al validar `exp`/`nbf`, en segundos.
LEEWAY_S = 30

#: Vida por defecto de un token de sesión. Corta a propósito: un token robado
#: sirve como mucho una hora, y renovar es barato.
DEFAULT_TTL_S = int(os.environ.get("CYBERSENTINEL_TOKEN_TTL", "3600"))

ISSUER = "cybersentinel"
ALGORITHM = "HS256"


class TokenError(Exception):
    """El token no es válido. El motivo va en el mensaje, para la auditoría."""


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    relleno = "=" * (-len(data) % 4)
    try:
        return base64.urlsafe_b64decode(data + relleno)
    except (binascii.Error, ValueError) as exc:
        raise TokenError("codificación base64url inválida") from exc


@dataclass(frozen=True)
class SecretSource:
    """De dónde salió el secreto de firma. Se expone en `/ready`."""

    key: bytes
    source: str          # "env" | "ephemeral"
    warning: str | None  # texto a mostrar si la configuración no es apta

    @property
    def is_persistent(self) -> bool:
        return self.source == "env"


def load_secret(explicit: str | bytes | None = None) -> SecretSource:
    """
    Carga el secreto de firma.

    Si no hay ninguno configurado se genera uno **efímero** y se declara: el
    servicio arranca (si no, no habría forma de probarlo en local), pero todos
    los tokens mueren al reiniciar y `/ready` lo dice. La alternativa —un
    secreto por defecto en el código— convierte cualquier despliegue que olvide
    configurarlo en un sistema donde cualquiera puede firmarse un token de
    admin. Eso no es un modo degradado, es una puerta trasera.
    """
    bruto = explicit if explicit is not None else os.environ.get(JWT_SECRET_ENV)
    if bruto:
        key = bruto.encode() if isinstance(bruto, str) else bruto
        if len(key) < MIN_SECRET_BYTES:
            raise ValueError(
                f"{JWT_SECRET_ENV} debe tener al menos {MIN_SECRET_BYTES} bytes "
                f"(tiene {len(key)}). Genera uno con: openssl rand -hex 32"
            )
        return SecretSource(key=key, source="env", warning=None)

    aviso = (
        f"No hay {JWT_SECRET_ENV}: se firma con un secreto efímero. Los tokens "
        "se invalidan al reiniciar y NO son válidos entre réplicas. No apto "
        "para producción."
    )
    logger.warning(aviso)
    return SecretSource(key=secrets.token_bytes(48), source="ephemeral", warning=aviso)


class TokenSigner:
    """Emite y verifica tokens de sesión con un secreto simétrico."""

    def __init__(self, secret: SecretSource | str | bytes | None = None,
                 ttl_s: int = DEFAULT_TTL_S) -> None:
        self.secret = secret if isinstance(secret, SecretSource) else load_secret(secret)
        self.ttl_s = ttl_s

    @property
    def source(self) -> str:
        return self.secret.source

    def _sign(self, mensaje: bytes) -> bytes:
        return hmac.new(self.secret.key, mensaje, hashlib.sha256).digest()

    def issue(self, subject: str, role: str, ttl_s: int | None = None,
              **extra: Any) -> tuple[str, dict[str, Any]]:
        """
        Emite un token para `subject` con el rol dado.

        Devuelve el token y sus reclamaciones, para que quien lo emita pueda
        registrar en la auditoría exactamente qué concedió —incluido el `jti`,
        que es lo que permite revocar un token concreto más adelante.
        """
        ahora = int(time.time())
        vida = ttl_s if ttl_s is not None else self.ttl_s
        claims: dict[str, Any] = {
            "iss": ISSUER,
            "sub": subject,
            "role": role,
            "iat": ahora,
            "nbf": ahora,
            "exp": ahora + vida,
            "jti": uuid.uuid4().hex,
            **extra,
        }
        cabecera = {"alg": ALGORITHM, "typ": "JWT"}
        partes = [
            _b64url_encode(json.dumps(cabecera, separators=(",", ":"), sort_keys=True).encode()),
            _b64url_encode(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode()),
        ]
        firmable = ".".join(partes).encode("ascii")
        partes.append(_b64url_encode(self._sign(firmable)))
        return ".".join(partes), claims

    def verify(self, token: str) -> dict[str, Any]:
        """
        Verifica firma, algoritmo y ventana temporal. Lanza `TokenError`.

        El orden importa: se comprueba la estructura y el algoritmo declarado
        antes de tocar la firma, y la firma antes de leer las reclamaciones.
        Leer `role` de un token no verificado y decidir con él es el error
        clásico que convierte un JWT en un campo de texto que el cliente
        controla.
        """
        if not token or token.count(".") != 2:
            raise TokenError("formato: se esperaban tres segmentos")

        cabecera_b64, cuerpo_b64, firma_b64 = token.split(".")

        try:
            cabecera = json.loads(_b64url_decode(cabecera_b64))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise TokenError("cabecera ilegible") from exc
        if not isinstance(cabecera, dict) or cabecera.get("alg") != ALGORITHM:
            raise TokenError(f"algoritmo no admitido: {cabecera.get('alg') if isinstance(cabecera, dict) else '?'!r}")

        esperada = self._sign(f"{cabecera_b64}.{cuerpo_b64}".encode("ascii"))
        if not hmac.compare_digest(esperada, _b64url_decode(firma_b64)):
            raise TokenError("firma inválida")

        try:
            claims = json.loads(_b64url_decode(cuerpo_b64))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise TokenError("reclamaciones ilegibles") from exc
        if not isinstance(claims, dict):
            raise TokenError("reclamaciones ilegibles")

        if claims.get("iss") != ISSUER:
            raise TokenError("emisor desconocido")

        ahora = time.time()
        exp = claims.get("exp")
        if not isinstance(exp, (int, float)):
            raise TokenError("sin caducidad (exp)")
        if ahora > exp + LEEWAY_S:
            raise TokenError("token caducado")

        nbf = claims.get("nbf")
        if isinstance(nbf, (int, float)) and ahora + LEEWAY_S < nbf:
            raise TokenError("token aún no válido (nbf)")

        if not claims.get("sub") or not claims.get("role"):
            raise TokenError("faltan sub o role")

        return claims
