"""
Frontera del servicio: quién entra, cuánto puede pedir y qué puede hacer.

Cuatro piezas independientes que el resto del sistema consume por un único
objeto —`Principal`— y una única dependencia —`requires(permiso)`—:

- `roles`     — permisos, roles y la matriz que los une.
- `identity`  — personas (scrypt) y sensores (clave de API), en SQLite.
- `tokens`    — emisión y verificación de JWT HS256 con la biblioteca estándar.
- `ratelimit` — cubo de fichas por cliente, en dos ejes (peticiones y eventos).
- `transport` — exige TLS a todo lo que no venga de la propia máquina.
- `guard`     — los une y deja constancia en la auditoría.

Sustituir la autenticación por OIDC corporativo significa reemplazar `tokens`
y la resolución del `Principal`; ni los roles, ni los límites, ni un solo
manejador de la API cambian.
"""
from .guard import SecurityConfig, SecurityGate, charge_events, limit_anonymous, requires  # noqa: F401
from .identity import AuthError, IdentityStore, IssuedKey, Principal  # noqa: F401
from .ratelimit import Decision, LimitPolicy, RateLimiter  # noqa: F401
from .roles import Permission, Role, permissions_for, role_matrix  # noqa: F401
from .tokens import TokenError, TokenSigner, load_secret  # noqa: F401
from .transport import TransportPolicy  # noqa: F401

__all__ = [
    "AuthError", "Decision", "IdentityStore", "IssuedKey", "LimitPolicy",
    "Permission", "Principal", "RateLimiter", "Role", "SecurityConfig",
    "SecurityGate", "TokenError", "TokenSigner", "charge_events",
    "limit_anonymous", "load_secret", "permissions_for", "requires", "role_matrix",
    "TransportPolicy",
]
