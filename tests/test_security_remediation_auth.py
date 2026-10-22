"""
Regresión de la auditoría (SEC-01, SEC-02).

- SEC-01: la IP y el esquema del cliente no se pueden falsificar con
  `X-Forwarded-For` / `X-Forwarded-Proto` desde fuera de los proxies declarados,
  ni anteponiendo valores a la lista.
- SEC-02: las peticiones concurrentes no pueden evaluar más contraseñas que
  `MAX_FAILED_ATTEMPTS` antes de que la cuenta quede bloqueada.

Todo es determinista: la concurrencia se fuerza con una barrera en `_derive`,
no con `sleep`.
"""
from __future__ import annotations

import sqlite3
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cybersentinel.api.app import IngestService, create_app
from cybersentinel.api.security import (
    AuthError,
    IdentityStore,
    LimitPolicy,
    ProxyTrust,
    RateLimiter,
    Role,
    SecurityConfig,
    SecurityGate,
    TransportPolicy,
)
from cybersentinel.api.security.identity import MAX_FAILED_ATTEMPTS

RULES = ROOT / "config" / "rules"
SECRETO = "s" * 48
CLAVE = "contraseña-de-prueba-larga"
REAL = "203.0.113.7"


# --- SEC-01: unidad ----------------------------------------------------------
@pytest.fixture
def proxy() -> ProxyTrust:
    return ProxyTrust.build(True, ["10.0.0.0/8"], hops=1)


def test_xff_se_lee_por_la_derecha_y_no_por_la_izquierda(proxy):
    assert proxy.client_ip("10.0.0.5", f"6.6.6.6, {REAL}") == REAL


def test_xff_se_ignora_si_el_par_no_es_un_proxy_declarado(proxy):
    assert proxy.client_ip("198.51.100.20", REAL) == "198.51.100.20"


def test_xff_se_ignora_si_la_confianza_esta_desactivada():
    apagado = ProxyTrust.build(False, ["10.0.0.0/8"])
    assert apagado.client_ip("10.0.0.5", REAL) == "10.0.0.5"


def test_varios_saltos_de_confianza():
    dos = ProxyTrust.build(True, ["10.0.0.0/8"], hops=2)
    assert dos.client_ip("10.0.0.5", f"6.6.6.6, {REAL}, 10.0.0.9") == REAL
    # Menos valores que saltos: todos los añadió la cadena de confianza.
    assert dos.client_ip("10.0.0.5", REAL) == REAL


@pytest.mark.parametrize("cabecera", ["", " , ", "no-es-una-ip", "6.6.6.6, basura"])
def test_valores_invalidos_vuelven_a_la_ip_del_par(proxy, cabecera):
    assert proxy.client_ip("10.0.0.5", cabecera) == "10.0.0.5"


def test_ipv6_y_ipv4_mapeada():
    p = ProxyTrust.build(True, ["::1/128", "127.0.0.1/32"])
    assert p.client_ip("::1", "2001:db8::1") == "2001:db8::1"
    assert p.client_ip("::ffff:127.0.0.1", REAL) == REAL


def test_por_defecto_solo_se_confia_en_el_bucle_local(monkeypatch):
    monkeypatch.setenv("CYBERSENTINEL_TRUST_FORWARDED_FOR", "1")
    monkeypatch.delenv("CYBERSENTINEL_TRUSTED_PROXIES", raising=False)
    monkeypatch.delenv("CYBERSENTINEL_TRUSTED_PROXY_HOPS", raising=False)
    p = ProxyTrust.from_env()
    assert p.trusts_peer("127.0.0.1") and not p.trusts_peer("10.0.0.5")


def test_saltos_invalidos_se_rechazan():
    with pytest.raises(ValueError):
        ProxyTrust.build(True, ["10.0.0.0/8"], hops=0)


def test_x_forwarded_proto_por_la_derecha_y_solo_desde_proxy():
    pol = TransportPolicy(trust_forwarded=True, trusted_proxies=("10.0.0.0/8",))
    assert pol.proxies.forwarded_proto("10.0.0.5", "http, https") == "https"
    assert pol.proxies.forwarded_proto("10.0.0.5", "https, http") == "http"
    assert pol.proxies.forwarded_proto("198.51.100.20", "https") is None


# --- SEC-01: extremo a extremo ----------------------------------------------
@pytest.fixture(scope="module")
def app_proxy(tmp_path_factory):
    d = tmp_path_factory.mktemp("proxy")
    IdentityStore(d / "id.db")
    limitador = RateLimiter({r.value: LimitPolicy(1000, 2000, 1e6, 2e6) for r in Role}
                            | {"anonymous": LimitPolicy(0.001, 3, 0, 0)})
    puerta = SecurityGate(SecurityConfig(
        identity_db=d / "id.db", jwt_secret=SECRETO, rate_limiter=limitador,
        proxy_trust=ProxyTrust.build(True, ["10.0.0.0/8"], hops=1)))
    svc = IngestService(rules_dir=RULES, db_path=d / "e.db", incidents_path=d / "i.db",
                        audit_path=None, wal_dir=d / "wal", enable_rag=False, enable_llm=False)
    app = create_app(svc, gate=puerta, transport=TransportPolicy(allow_plaintext=True))
    with TestClient(app, base_url="https://testserver") as vivo:
        yield {"app": app, "limiter": limitador, "vivo": vivo}


def _logins(app_proxy, origen, cabeceras) -> list[int]:
    app_proxy["limiter"].reset()
    c = TestClient(app_proxy["app"], base_url="https://testserver", client=origen)
    return [c.post("/api/v1/auth/token", json={"username": "nadie", "password": "x"},
                   headers=cabeceras(i)).status_code for i in range(8)]


def test_rotar_xff_por_la_izquierda_no_evita_el_limite(app_proxy):
    codigos = _logins(app_proxy, ("10.0.0.5", 4000),
                      lambda i: {"X-Forwarded-For": f"10.9.{i}.1, {REAL}"})
    assert codigos[:3] == [401, 401, 401]
    assert set(codigos[3:]) == {429}


def test_xff_desde_origen_no_declarado_no_cambia_la_ip(app_proxy):
    codigos = _logins(app_proxy, ("198.51.100.20", 4000),
                      lambda i: {"X-Forwarded-For": f"10.9.{i}.1"})
    assert set(codigos[3:]) == {429}


def test_clientes_distintos_tras_el_proxy_tienen_cubos_distintos(app_proxy):
    app_proxy["limiter"].reset()
    c = TestClient(app_proxy["app"], base_url="https://testserver", client=("10.0.0.5", 1))
    for ip in ("203.0.113.1", "203.0.113.2"):
        r = [c.post("/api/v1/auth/token", json={"username": "n", "password": "x"},
                    headers={"X-Forwarded-For": ip}).status_code for _ in range(3)]
        assert r == [401, 401, 401]


# --- SEC-02 ------------------------------------------------------------------
def _intentos_concurrentes(store: IdentityStore, monkeypatch, n: int, password: str):
    """
    Lanza `n` intentos a la vez y retiene a los que llegan a derivar hasta que
    todos han llegado a `_derive` o han sido rechazados antes. Con la carrera
    antigua, los `n` llegaban a derivar.
    """
    original = store._derive
    liberar = threading.Event()
    entrados = []
    candado = threading.Lock()

    def derivar_retenido(pw, salt):
        with candado:
            entrados.append(1)
        assert liberar.wait(10), "la barrera no se liberó"
        return original(pw, salt)

    monkeypatch.setattr(store, "_derive", derivar_retenido)
    terminados_pronto = []

    def intento(_):
        try:
            store.verify_password("victima", password)
            return "ok"
        except AuthError as exc:
            if not liberar.is_set():
                terminados_pronto.append(1)
            return exc.motivo

    with ThreadPoolExecutor(n) as ex:
        futuros = [ex.submit(intento, i) for i in range(n)]
        limite = time.time() + 10
        while len(entrados) + len(terminados_pronto) < n and time.time() < limite:
            time.sleep(0.005)
        liberar.set()
        return len(entrados), [f.result() for f in futuros]


@pytest.fixture
def store(tmp_path) -> IdentityStore:
    s = IdentityStore(tmp_path / "id.db")
    s.create_user("victima", CLAVE, Role.ANALYST)
    return s


def _fila(store):
    con = sqlite3.connect(store.path)
    try:
        return con.execute("SELECT failed_attempts, locked_until FROM users "
                           "WHERE username='victima'").fetchone()
    finally:
        con.close()


def test_intentos_concurrentes_no_evaden_el_bloqueo(store, monkeypatch):
    evaluadas, motivos = _intentos_concurrentes(store, monkeypatch, 20, "incorrecta-123456")
    assert evaluadas == MAX_FAILED_ATTEMPTS
    assert motivos.count("credenciales inválidas") == MAX_FAILED_ATTEMPTS
    assert sum("bloqueada" in m for m in motivos) == 20 - MAX_FAILED_ATTEMPTS
    fallos, bloqueo = _fila(store)
    assert fallos == MAX_FAILED_ATTEMPTS and bloqueo is not None


def test_bloqueo_secuencial_y_contraseña_buena_durante_el_bloqueo(store):
    for _ in range(MAX_FAILED_ATTEMPTS):
        with pytest.raises(AuthError, match="credenciales inválidas"):
            store.verify_password("victima", "incorrecta-123456")
    with pytest.raises(AuthError, match="bloqueada") as exc:
        store.verify_password("victima", CLAVE)
    assert exc.value.retry_after and exc.value.retry_after > 0


def test_un_acierto_reinicia_el_contador(store):
    for _ in range(MAX_FAILED_ATTEMPTS - 1):
        with pytest.raises(AuthError):
            store.verify_password("victima", "incorrecta-123456")
    assert store.verify_password("victima", CLAVE).display == "victima"
    assert _fila(store) == (0, None)


def test_dos_instancias_sobre_el_mismo_archivo_comparten_el_contador(store, tmp_path):
    otra = IdentityStore(store.path)
    for i in range(MAX_FAILED_ATTEMPTS):
        with pytest.raises(AuthError):
            (store if i % 2 else otra).verify_password("victima", "incorrecta-123456")
    with pytest.raises(AuthError, match="bloqueada"):
        otra.verify_password("victima", CLAVE)
