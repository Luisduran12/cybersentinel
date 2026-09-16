"""
Almacén de identidades: personas con contraseña y sensores con clave de API.

Dos tipos de credencial porque hay dos tipos de cliente, y tratarlos igual
rompe uno de los dos:

| | Persona | Sensor |
|---|---|---|
| Secreto | contraseña elegida por humano (poca entropía) | 256 bits de CSPRNG |
| Uso | una vez por sesión | miles de veces por segundo |
| Derivación | **scrypt** (lenta a propósito) | **SHA-256** (una pasada) |

**Por qué SHA-256 basta para la clave de API y no para la contraseña.** El
derivado lento existe para encarecer el ataque por diccionario sobre secretos
que las personas eligen y reutilizan. Una clave de 32 bytes aleatorios no tiene
diccionario: probarla exige recorrer 2^256. Aplicarle scrypt costaría ~100 ms
por petición y hundiría el caudal medido (528 ev/s en el pipeline completo)
antes de llegar al análisis. Lo que sí hace falta, y está: comparación en tiempo
constante y no guardar nunca el secreto en claro.

La clave se muestra **una sola vez**, al crearla. Si se pierde, se revoca y se
emite otra: un almacén del que se puede recuperar el secreto es un almacén del
que se puede robar el secreto.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
import threading
import time
from contextlib import closing
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .roles import Permission, Role, permissions_for

#: Parámetros de scrypt. n=2^15 y r=8 es la recomendación de la RFC 7914 para
#: uso interactivo: ~100 ms y 32 MB por derivación en hardware de 2024.
SCRYPT_N = 1 << 15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32

#: Prefijo visible de la clave de API. Permite reconocerla en un log o en un
#: repositorio —y que los buscadores de secretos la detecten— sin revelarla.
KEY_PREFIX = "cs"
KEY_ID_CHARS = 12

#: Tras este número de intentos fallidos consecutivos, la cuenta se bloquea
#: temporalmente. Sin esto, la contraseña de un analista se adivina por fuerza
#: bruta a la velocidad que dé la red.
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_S = 300

#: Cada cuánto se vuelca a disco el contador de usos de las claves. Ver
#: `IdentityStore._touch_key` para la medición que justifica el número.
USAGE_FLUSH_S = 5.0

ESQUEMA = """
CREATE TABLE IF NOT EXISTS users (
    username       TEXT PRIMARY KEY,
    role           TEXT NOT NULL,
    password_hash  TEXT NOT NULL,   -- hex del derivado scrypt
    salt           TEXT NOT NULL,   -- hex, 16 bytes por usuario
    kdf            TEXT NOT NULL,   -- "scrypt:n=32768,r=8,p=1"
    created_at     TEXT NOT NULL,
    disabled       INTEGER NOT NULL DEFAULT 0,
    last_login_at  TEXT,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until   TEXT
);
CREATE TABLE IF NOT EXISTS api_keys (
    key_id      TEXT PRIMARY KEY,   -- parte pública, viaja en claro
    secret_hash TEXT NOT NULL,      -- sha256 del secreto, hex
    role        TEXT NOT NULL,
    label       TEXT NOT NULL,      -- para qué sensor es
    created_at  TEXT NOT NULL,
    created_by  TEXT NOT NULL,
    expires_at  TEXT,               -- NULL = sin caducidad (desaconsejado)
    revoked_at  TEXT,
    last_used_at TEXT,
    uses        INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_keys_role ON api_keys(role);
"""


def _ahora() -> str:
    return datetime.now(tz=timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True)
class Principal:
    """
    Quién está haciendo la petición, ya autenticado.

    Es lo único que ve el resto del servicio: ni contraseñas, ni claves, ni
    tokens. Cualquier proveedor de identidad futuro (OIDC, mTLS) solo tiene que
    producir uno de estos.
    """

    id: str                      # "user:ana" | "key:9f3c1a2b4d5e"
    display: str                 # nombre legible para la auditoría
    role: Role
    permissions: frozenset[Permission]
    kind: str                    # "user" | "api_key"
    token_id: str | None = None  # jti, para revocar una sesión concreta
    claims: dict[str, Any] = field(default_factory=dict)

    def can(self, permiso: Permission) -> bool:
        return permiso in self.permissions

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "display": self.display,
            "role": self.role.value,
            "kind": self.kind,
            "permissions": sorted(p.value for p in self.permissions),
        }


class AuthError(Exception):
    """Credencial ausente, mal formada, inválida, revocada o caducada."""

    def __init__(self, motivo: str, *, retry_after: int | None = None) -> None:
        super().__init__(motivo)
        self.motivo = motivo
        self.retry_after = retry_after


@dataclass(frozen=True)
class IssuedKey:
    """Una clave recién creada. `secret` es lo único que no se vuelve a ver."""

    key_id: str
    secret: str
    role: Role
    label: str
    expires_at: str | None

    @property
    def token(self) -> str:
        """La cadena que el sensor pone en la cabecera `X-API-Key`."""
        return f"{KEY_PREFIX}_{self.key_id}_{self.secret}"


class IdentityStore:
    """Personas y sensores, en SQLite. Sin dependencias nuevas."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._usage_lock = threading.Lock()
        self._local = threading.local()
        self._usage_pendiente: dict[str, tuple[int, str]] = {}
        self._usage_ultimo_volcado = time.monotonic()
        with closing(self._connect()) as con:
            con.executescript(ESQUEMA)
            con.commit()

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.path, timeout=30)
        con.row_factory = sqlite3.Row
        return con

    def _reader(self) -> sqlite3.Connection:
        """
        Conexión de **solo lectura** reutilizada por hilo.

        Abrir una conexión nueva por petición costaba ~350 µs —medido con
        `scripts/benchmark_security.py`—, que era lo que quedaba del coste de
        verificar una clave una vez diferido el contador de usos. Reutilizarla
        lo baja a decenas de microsegundos.

        Es por hilo, no compartida: un objeto `Connection` de SQLite no es
        seguro entre hilos, y compartirlo produce corrupción intermitente que
        aparece bajo carga y no en las pruebas.
        """
        con = getattr(self._local, "con", None)
        if con is None:
            con = self._connect()
            self._local.con = con
        return con

    # --- Contraseñas ------------------------------------------------------
    @staticmethod
    def _derive(password: str, salt: bytes) -> str:
        return hashlib.scrypt(
            password.encode("utf-8"), salt=salt,
            n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=SCRYPT_DKLEN,
            maxmem=64 * 1024 * 1024,
        ).hex()

    def create_user(self, username: str, password: str, role: Role | str,
                    *, replace: bool = False) -> dict[str, Any]:
        """Alta de una persona. La contraseña nunca se guarda en claro."""
        username = username.strip().lower()
        if not username:
            raise ValueError("el nombre de usuario no puede estar vacío")
        if len(password) < 12:
            # 12 caracteres no es una política de contraseñas: es el suelo por
            # debajo del cual el bloqueo por intentos fallidos ya no compensa.
            raise ValueError("la contraseña debe tener al menos 12 caracteres")
        rol = Role(role)

        salt = secrets.token_bytes(16)
        fila = (
            username, rol.value, self._derive(password, salt), salt.hex(),
            f"scrypt:n={SCRYPT_N},r={SCRYPT_R},p={SCRYPT_P}", _ahora(), 0, None, 0, None,
        )
        verbo = "INSERT OR REPLACE INTO" if replace else "INSERT INTO"
        with self._lock, closing(self._connect()) as con:
            try:
                con.execute(f"{verbo} users VALUES (?,?,?,?,?,?,?,?,?,?)", fila)
            except sqlite3.IntegrityError as exc:
                raise ValueError(f"el usuario {username!r} ya existe") from exc
            con.commit()
        return {"username": username, "role": rol.value, "created_at": fila[5]}

    def verify_password(self, username: str, password: str) -> Principal:
        """
        Comprueba la contraseña y devuelve el `Principal`.

        Cuenta los fallos y bloquea temporalmente. El mensaje de error es el
        mismo para «usuario inexistente» y «contraseña incorrecta»: distinguirlos
        convierte el formulario en un enumerador de usuarios válidos.
        """
        username = (username or "").strip().lower()
        fila = self._reader().execute(
            "SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if fila is None:
            # Se deriva igualmente contra una sal descartable para que el
            # tiempo de respuesta no revele si el usuario existe.
            self._derive(password or "", b"0" * 16)
            raise AuthError("credenciales inválidas")

        if fila["disabled"]:
            raise AuthError("cuenta deshabilitada")

        if fila["locked_until"]:
            hasta = datetime.fromisoformat(fila["locked_until"])
            restante = (hasta - datetime.now(tz=timezone.utc)).total_seconds()
            if restante > 0:
                raise AuthError(
                    f"cuenta bloqueada tras {MAX_FAILED_ATTEMPTS} intentos fallidos",
                    retry_after=int(restante) + 1,
                )

        esperado = fila["password_hash"]
        obtenido = self._derive(password or "", bytes.fromhex(fila["salt"]))
        if not hmac.compare_digest(esperado, obtenido):
            self._record_failure(username, fila["failed_attempts"] + 1)
            raise AuthError("credenciales inválidas")

        with self._lock, closing(self._connect()) as con:
            con.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = NULL, "
                "last_login_at = ? WHERE username = ?", (_ahora(), username),
            )
            con.commit()

        rol = Role(fila["role"])
        return Principal(
            id=f"user:{username}", display=username, role=rol,
            permissions=permissions_for(rol), kind="user",
        )

    def _record_failure(self, username: str, intentos: int) -> None:
        bloqueo = None
        if intentos >= MAX_FAILED_ATTEMPTS:
            bloqueo = (datetime.now(tz=timezone.utc)
                       + timedelta(seconds=LOCKOUT_S)).isoformat(timespec="seconds")
        with self._lock, closing(self._connect()) as con:
            con.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE username = ?",
                (intentos, bloqueo, username),
            )
            con.commit()

    def set_disabled(self, username: str, disabled: bool = True) -> bool:
        with self._lock, closing(self._connect()) as con:
            cur = con.execute("UPDATE users SET disabled = ? WHERE username = ?",
                              (int(disabled), username.strip().lower()))
            con.commit()
        return cur.rowcount > 0

    def list_users(self) -> list[dict[str, Any]]:
        with closing(self._connect()) as con:
            filas = con.execute(
                "SELECT username, role, created_at, disabled, last_login_at, "
                "failed_attempts, locked_until FROM users ORDER BY username"
            ).fetchall()
        return [dict(f) for f in filas]

    # --- Claves de API ----------------------------------------------------
    def create_api_key(self, label: str, role: Role | str = Role.SENSOR,
                       *, created_by: str = "cli", expires_in_days: int | None = 365,
                       ) -> IssuedKey:
        """
        Emite una clave. El secreto se devuelve aquí y **no se guarda**.

        Caduca en un año por defecto: una credencial de máquina sin caducidad
        sobrevive al sensor que la usaba, al equipo que la creó y a la política
        que la justificaba.
        """
        rol = Role(role)
        key_id = secrets.token_hex(KEY_ID_CHARS // 2)
        secreto = secrets.token_urlsafe(32)
        caduca = None
        if expires_in_days:
            caduca = (datetime.now(tz=timezone.utc)
                      + timedelta(days=expires_in_days)).isoformat(timespec="seconds")

        with self._lock, closing(self._connect()) as con:
            con.execute(
                "INSERT INTO api_keys (key_id, secret_hash, role, label, created_at, "
                "created_by, expires_at, revoked_at, last_used_at, uses) "
                "VALUES (?,?,?,?,?,?,?,NULL,NULL,0)",
                (key_id, hashlib.sha256(secreto.encode()).hexdigest(), rol.value,
                 label, _ahora(), created_by, caduca),
            )
            con.commit()
        return IssuedKey(key_id=key_id, secret=secreto, role=rol, label=label,
                         expires_at=caduca)

    def verify_api_key(self, presentada: str) -> Principal:
        """Valida `cs_<key_id>_<secreto>` y devuelve el `Principal`."""
        partes = (presentada or "").split("_", 2)
        if len(partes) != 3 or partes[0] != KEY_PREFIX:
            raise AuthError("clave de API mal formada")
        _, key_id, secreto = partes

        fila = self._reader().execute(
            "SELECT * FROM api_keys WHERE key_id = ?", (key_id,)).fetchone()
        if fila is None:
            raise AuthError("clave de API desconocida")
        if fila["revoked_at"]:
            raise AuthError("clave de API revocada")
        if fila["expires_at"] and datetime.fromisoformat(fila["expires_at"]) < datetime.now(tz=timezone.utc):
            raise AuthError("clave de API caducada")

        calculado = hashlib.sha256(secreto.encode()).hexdigest()
        if not hmac.compare_digest(fila["secret_hash"], calculado):
            raise AuthError("clave de API inválida")

        self._touch_key(key_id)
        rol = Role(fila["role"])
        return Principal(
            id=f"key:{key_id}", display=f"{fila['label']} ({key_id})", role=rol,
            permissions=permissions_for(rol), kind="api_key",
        )

    def _touch_key(self, key_id: str) -> None:
        """
        Anota el uso de la clave **en memoria** y vuelca cada `USAGE_FLUSH_S`.

        La primera versión escribía y confirmaba en SQLite en cada petición.
        Medido con `scripts/benchmark_security.py`, eso dejaba la verificación
        en **508 op/s**: el `commit` —con su sincronización a disco— costaba
        ~2 ms y era, con diferencia, la operación más cara de toda la frontera.
        Un servicio de ingestión no puede tener su techo en el contador de usos
        de una credencial.

        Lo que **no** se difiere es la comprobación de revocación: esa se lee de
        la base de datos en cada petición. Diferir una estadística retrasa un
        dato de inventario; diferir una revocación deja entrar a quien ya no
        debería. El precio de este cambio está acotado y dicho: si el proceso
        muere de golpe, se pierden hasta `USAGE_FLUSH_S` segundos de contador
        de usos. Nada más.
        """
        with self._usage_lock:
            n, _ = self._usage_pendiente.get(key_id, (0, ""))
            self._usage_pendiente[key_id] = (n + 1, _ahora())
            if time.monotonic() - self._usage_ultimo_volcado < USAGE_FLUSH_S:
                return
            pendiente = self._usage_pendiente
            self._usage_pendiente = {}
            self._usage_ultimo_volcado = time.monotonic()

        self._flush_usage(pendiente)

    def _flush_usage(self, pendiente: dict[str, tuple[int, str]]) -> None:
        if not pendiente:
            return
        with self._lock, closing(self._connect()) as con:
            con.executemany(
                "UPDATE api_keys SET last_used_at = ?, uses = uses + ? WHERE key_id = ?",
                [(cuando, n, key_id) for key_id, (n, cuando) in pendiente.items()],
            )
            con.commit()

    def flush_usage(self) -> int:
        """
        Vuelca ya lo pendiente. La llaman el apagado ordenado y las consultas de
        inventario, para que `list_api_keys` no muestre un contador atrasado.
        """
        with self._usage_lock:
            pendiente = self._usage_pendiente
            self._usage_pendiente = {}
            self._usage_ultimo_volcado = time.monotonic()
        self._flush_usage(pendiente)
        return len(pendiente)

    def revoke_api_key(self, key_id: str) -> bool:
        with self._lock, closing(self._connect()) as con:
            cur = con.execute(
                "UPDATE api_keys SET revoked_at = ? WHERE key_id = ? AND revoked_at IS NULL",
                (_ahora(), key_id),
            )
            con.commit()
        return cur.rowcount > 0

    def list_api_keys(self, include_revoked: bool = False) -> list[dict[str, Any]]:
        self.flush_usage()  # que el inventario no muestre un contador atrasado
        consulta = ("SELECT key_id, role, label, created_at, created_by, expires_at, "
                    "revoked_at, last_used_at, uses FROM api_keys")
        if not include_revoked:
            consulta += " WHERE revoked_at IS NULL"
        consulta += " ORDER BY created_at DESC"
        with closing(self._connect()) as con:
            return [dict(f) for f in con.execute(consulta).fetchall()]

    # --- Estado -----------------------------------------------------------
    def summary(self) -> dict[str, Any]:
        with closing(self._connect()) as con:
            usuarios = con.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            por_rol = dict(con.execute(
                "SELECT role, COUNT(*) FROM users GROUP BY role").fetchall())
            claves = con.execute(
                "SELECT COUNT(*) FROM api_keys WHERE revoked_at IS NULL").fetchone()[0]
        return {
            "users": usuarios,
            "users_by_role": por_rol,
            "active_api_keys": claves,
            "db_path": str(self.path),
        }

    def is_empty(self) -> bool:
        """
        ¿No hay ninguna credencial?

        El servicio lo consulta al arrancar para avisar de que está autenticando
        contra un almacén vacío: nadie puede entrar, y eso es un fallo de
        despliegue que conviene ver en el arranque y no en la primera petición.
        """
        with closing(self._connect()) as con:
            u = con.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            k = con.execute(
                "SELECT COUNT(*) FROM api_keys WHERE revoked_at IS NULL").fetchone()[0]
        return (u + k) == 0
