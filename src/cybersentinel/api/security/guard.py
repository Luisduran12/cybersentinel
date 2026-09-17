"""
La puerta: autentica, limita el caudal, autoriza y deja constancia.

Las tres comprobaciones van juntas y **en este orden**, porque el orden es la
defensa:

1. **Autenticar.** ¿Quién eres? Sin respuesta válida no se sigue.
2. **Limitar.** ¿Has gastado ya tu cuota? El limitador se aplica al *principal*
   cuando la credencial es válida y a la *IP* cuando no lo es. Así, quien prueba
   contraseñas agota el cubo anónimo de su origen y no toca el de nadie más.
3. **Autorizar.** ¿Te corresponde este permiso? Se pregunta por permiso, nunca
   por rol (ver `roles.py`).

Un detalle que cambia el resultado: el endpoint de emisión de tokens aplica el
límite **antes** de comprobar la contraseña. Verificar una contraseña cuesta
~100 ms de scrypt a propósito; si el límite se aplicase después, mil peticiones
por segundo con contraseñas falsas tumbarían el servicio sin necesidad de
acertar ninguna.

Lo que se registra en la auditoría y lo que no: se registran las emisiones de
token, los fallos de autenticación, las denegaciones de permiso y los bloqueos
por caudal. **No** se registra cada ingesta correcta —serían millones de
entradas al día en una cadena HMAC que se verifica entera— porque para eso ya
están las métricas y el almacén de eventos.
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from fastapi import HTTPException, Request, status

from .identity import AuthError, IdentityStore, Principal
from .ratelimit import RateLimiter
from .roles import Permission, Role, permissions_for, role_matrix
from .tokens import TokenError, TokenSigner

logger = logging.getLogger(__name__)

#: Cabeceras admitidas. Dos, porque son dos tipos de cliente (ver `identity.py`).
HEADER_API_KEY = "X-API-Key"
HEADER_AUTH = "Authorization"

#: Si el servicio está detrás de un proxy de confianza, la IP real viaja en
#: `X-Forwarded-For`. Confiar en esa cabecera **sin** un proxy delante permite
#: a cualquiera falsificar su origen y saltarse el límite por IP: por eso está
#: desactivado por defecto y hay que activarlo a conciencia.
TRUST_FORWARDED = os.environ.get("CYBERSENTINEL_TRUST_FORWARDED_FOR", "").lower() in {"1", "true", "yes"}

#: Cada cuánto se vuelve a auditar el fallo de un mismo cliente. Sin esta
#: ventana, un atacante que dispara credenciales falsas escribe él mismo el
#: tamaño del log de auditoría.
AUDIT_FAILURE_WINDOW_S = 60.0


@dataclass
class SecurityConfig:
    """Configuración de la frontera del servicio."""

    identity_db: str | Path
    jwt_secret: str | bytes | None = None
    token_ttl_s: int | None = None
    audit_log: Any = None            # governance.AuditLog, opcional
    rate_limiter: RateLimiter | None = None


@dataclass
class _FailureCounter:
    last_audited: float = 0.0
    since: int = 0


class SecurityGate:
    """Autenticación, límite de caudal y autorización del servicio."""

    def __init__(self, config: SecurityConfig) -> None:
        self.store = IdentityStore(config.identity_db)
        kwargs = {"secret": config.jwt_secret}
        if config.token_ttl_s is not None:
            kwargs["ttl_s"] = config.token_ttl_s
        self.signer = TokenSigner(**kwargs)
        self.limiter = config.rate_limiter or RateLimiter()
        self.audit = config.audit_log
        self._failures: dict[str, _FailureCounter] = {}
        # Las revocaciones ya no viven aquí: están en el almacén, para que
        # cerrar sesión valga en todas las réplicas y sobreviva a un reinicio.
        self.store.purge_revoked_tokens()

        if self.store.is_empty():
            logger.warning(
                "El almacén de identidades está vacío: nadie puede autenticarse. "
                "Crea credenciales con `cybersentinel auth create-user` o "
                "`cybersentinel auth create-key`."
            )

    # --- Auditoría --------------------------------------------------------
    def _record(self, actor: str, action: str, detail: dict[str, Any]) -> None:
        if self.audit is None:
            return
        try:
            self.audit.record(actor=actor, action=action, detail=detail)
        except Exception:  # la auditoría nunca debe tumbar la petición
            logger.exception("No se pudo registrar en la auditoría: %s", action)

    def _record_failure(self, cliente: str, motivo: str, ruta: str) -> None:
        """Audita el fallo, agregando repeticiones dentro de la ventana."""
        cont = self._failures.setdefault(cliente, _FailureCounter())
        cont.since += 1
        ahora = time.monotonic()
        if ahora - cont.last_audited < AUDIT_FAILURE_WINDOW_S:
            return
        self._record(
            actor=f"anonymous:{cliente}", action="auth_failed",
            detail={"reason": motivo, "path": ruta,
                    "failures_since_last_entry": cont.since},
        )
        cont.last_audited = ahora
        cont.since = 0

    # --- Identificación del origen ---------------------------------------
    @staticmethod
    def client_ip(request: Request) -> str:
        if TRUST_FORWARDED:
            reenviada = request.headers.get("x-forwarded-for", "")
            if reenviada:
                return reenviada.split(",")[0].strip()
        return request.client.host if request.client else "desconocida"

    # --- Autenticación ----------------------------------------------------
    def authenticate(self, request: Request) -> Principal:
        """
        Resuelve el `Principal` a partir de las cabeceras. Lanza `AuthError`.

        Se admite una credencial, no dos: presentar clave de API *y* token a la
        vez se rechaza en lugar de elegir una. Dejar que el servidor escoja es
        cómo se cuelan escaladas de privilegio por confusión de credencial.
        """
        api_key = request.headers.get(HEADER_API_KEY)
        cabecera = request.headers.get(HEADER_AUTH, "")
        bearer = cabecera[7:].strip() if cabecera[:7].lower() == "bearer " else None

        if api_key and bearer:
            raise AuthError("presenta una sola credencial, no dos")
        if api_key:
            return self.store.verify_api_key(api_key)
        if bearer:
            try:
                claims = self.signer.verify(bearer)
            except TokenError as exc:
                raise AuthError(f"token inválido: {exc}") from exc
            if self.store.is_token_revoked(claims.get("jti", "")):
                raise AuthError("token revocado")
            rol = Role(claims["role"]) if claims["role"] in Role._value2member_map_ else None
            if rol is None:
                raise AuthError(f"rol desconocido en el token: {claims['role']!r}")
            return Principal(
                id=f"user:{claims['sub']}", display=str(claims["sub"]), role=rol,
                permissions=permissions_for(rol), kind="user",
                token_id=claims.get("jti"), claims=claims,
            )
        raise AuthError("falta credencial: usa Authorization: Bearer o X-API-Key")

    def revoke_token(self, jti: str, expires_at: int = 0, subject: str = "") -> None:
        """
        Invalida un token concreto antes de que caduque, en el almacén.

        Persistido y compartido: sobrevive al reinicio y vale para todas las
        réplicas que compartan la base de identidades. Sin `expires_at` se
        asume la vida máxima configurada, para que la entrada se pueda limpiar
        algún día en lugar de quedarse ahí para siempre.
        """
        if not jti:
            return
        caduca = expires_at or int(time.time() + self.signer.ttl_s)
        self.store.revoke_token(jti, caduca, subject)
        self._record(
            actor=subject or f"token:{jti[:8]}", 
            action="token_revoked", 
            detail={"jti": jti, "expires_at": caduca}
        )

    # --- Emisión de tokens ------------------------------------------------
    def issue_token(self, username: str, password: str, request: Request) -> dict[str, Any]:
        """Verifica la contraseña y emite un token de sesión."""
        ip = self.client_ip(request)
        try:
            principal = self.store.verify_password(username, password)
        except AuthError as exc:
            self._record_failure(ip, exc.motivo, str(request.url.path))
            raise

        token, claims = self.signer.issue(principal.display, principal.role.value)
        self._record(
            actor=principal.id, action="token_issued",
            detail={"role": principal.role.value, "jti": claims["jti"],
                    "expires_at": claims["exp"], "client_ip": ip,
                    "secret_source": self.signer.source},
        )
        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": claims["exp"] - claims["iat"],
            "role": principal.role.value,
            "permissions": sorted(p.value for p in principal.permissions),
        }

    # --- Estado -----------------------------------------------------------
    def status(self) -> dict[str, Any]:
        """Lo que `/ready` publica sobre la frontera. Sin secretos."""
        return {
            "enabled": True,
            "token_secret_source": self.signer.source,
            "token_secret_warning": self.signer.secret.warning,
            "identities": self.store.summary(),
            "rate_limit": self.limiter.stats(),
            "roles": role_matrix(),
        }


# --- Dependencias de FastAPI ---------------------------------------------
def _gate(request: Request) -> SecurityGate:
    puerta = getattr(request.app.state, "gate", None)
    if puerta is None:
        # Sin puerta no se sirve. Fallar cerrado: un error de configuración no
        # puede traducirse en «entonces pasa todo el mundo».
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="la capa de seguridad no está inicializada",
        )
    return puerta


def _401(motivo: str, retry_after: int | None = None) -> HTTPException:
    cabeceras = {"WWW-Authenticate": 'Bearer realm="cybersentinel"'}
    if retry_after:
        cabeceras["Retry-After"] = str(retry_after)
    return HTTPException(status.HTTP_401_UNAUTHORIZED,
                         detail={"error": "no_autenticado", "reason": motivo},
                         headers=cabeceras)


def limit_anonymous(request: Request) -> None:
    """
    Límite por IP para lo que se sirve sin credencial.

    Va como dependencia del endpoint de emisión de tokens para que el cubo se
    cobre **antes** de derivar la contraseña con scrypt.
    """
    puerta = _gate(request)
    ip = puerta.client_ip(request)
    decision = puerta.limiter.check(f"ip:{ip}", "anonymous")
    if not decision.allowed:
        puerta._record(
            actor=f"anonymous:{ip}", action="rate_limited",
            detail={"path": str(request.url.path), "scope": decision.scope},
        )
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"error": "demasiadas_peticiones",
                    "reason": f"límite por IP en {decision.scope}"},
            headers=decision.headers(),
        )


def charge_events(request: Request, principal: Principal, eventos: int) -> None:
    """
    Cobra el caudal de eventos una vez conocido el tamaño del lote.

    Va aparte de `requires` porque el cuerpo de la petición todavía no está
    validado cuando corren las dependencias: cobrar por petición trataría igual
    un lote de 1 evento y uno de 10 000. El endpoint llama a esto en cuanto
    tiene el lote y **antes** de normalizar y encolar nada, para que un cliente
    fuera de cuota no consuma trabajo del pipeline.
    """
    puerta = _gate(request)
    decision = puerta.limiter.check(principal.id, principal.role.value, events=eventos)
    if decision.allowed:
        return
    puerta._record(
        actor=principal.id, action="rate_limited",
        detail={"path": str(request.url.path), "scope": decision.scope,
                "role": principal.role.value, "events": eventos},
    )
    raise HTTPException(
        status.HTTP_429_TOO_MANY_REQUESTS,
        detail={"error": "demasiadas_peticiones",
                "reason": f"límite de {decision.scope} para el rol "
                          f"{principal.role.value}",
                "events_in_batch": eventos},
        headers=decision.headers(),
    )


def requires(*permisos: Permission) -> Callable[..., Any]:
    """Construye la dependencia que protege un endpoint: autentica, limita y autoriza."""

    async def dependencia(request: Request) -> Principal:
        puerta = _gate(request)
        ip = puerta.client_ip(request)

        # 1. Autenticar.
        try:
            principal = puerta.authenticate(request)
        except AuthError as exc:
            # El intento fallido se cobra del cubo anónimo del origen.
            puerta.limiter.check(f"ip:{ip}", "anonymous")
            puerta._record_failure(ip, exc.motivo, str(request.url.path))
            raise _401(exc.motivo, exc.retry_after) from exc

        # 2. Limitar, ya como cliente identificado. Aquí solo se cobra la
        # petición; el coste por evento lo aplica `charge_events` cuando el
        # lote ya está validado.
        decision = puerta.limiter.check(principal.id, principal.role.value)
        if not decision.allowed:
            puerta._record(
                actor=principal.id, action="rate_limited",
                detail={"path": str(request.url.path), "scope": decision.scope,
                        "role": principal.role.value},
            )
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                detail={"error": "demasiadas_peticiones",
                        "reason": f"límite de {decision.scope} para el rol "
                                  f"{principal.role.value}"},
                headers=decision.headers(),
            )

        # 3. Autorizar.
        faltan = [p for p in permisos if not principal.can(p)]
        if faltan:
            puerta._record(
                actor=principal.id, action="authz_denied",
                detail={"path": str(request.url.path), "role": principal.role.value,
                        "missing": [str(p) for p in faltan]},
            )
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail={"error": "sin_permiso",
                        "reason": f"el rol {principal.role.value} no tiene "
                                  f"{', '.join(str(p) for p in faltan)}",
                        "required": [str(p) for p in permisos]},
            )

        request.state.principal = principal
        return principal

    return dependencia
