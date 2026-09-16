"""
Pruebas de la frontera del servicio: autenticación, RBAC y límite de caudal.

Lo que se comprueba aquí no es que el código «tenga seguridad», sino que los
ataques concretos que esta capa dice frenar **fallan de verdad**: un token con
el algoritmo cambiado, una firma manipulada, una clave revocada que sigue
intentándolo, un rol leyendo lo que no le toca y un cliente desbocado.

Cada prueba nombra el ataque que representa. Una suite de seguridad que solo
comprueba el camino feliz no prueba nada: el camino feliz ya lo cubre la suite
de ingestión.
"""
from __future__ import annotations

import base64
import json
import sqlite3
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cybersentinel.api.app import IngestService, create_app  # noqa: E402
from cybersentinel.api.security import (  # noqa: E402
    AuthError, IdentityStore, LimitPolicy, Permission, RateLimiter, Role,
    SecurityConfig, SecurityGate, TokenError, TokenSigner, TransportPolicy,
    permissions_for,
)
from cybersentinel.api.security.tokens import load_secret  # noqa: E402
from cybersentinel.governance import AuditLog  # noqa: E402

RULES = ROOT / "config" / "rules"
SECRETO = "0123456789abcdef0123456789abcdef0123456789abcdef"  # 48 bytes
CLAVE = "contraseña-de-prueba-larga"


def _evento(n: int = 0) -> dict:
    return {"source": "sysmon", "action": "process_create", "host": "SRV-APP",
            "user": "admin", "command_line": f"chrome.exe --tab {n}",
            "outcome": "success"}


# --------------------------------------------------------------------------
@pytest.fixture(scope="module")
def entorno(tmp_path_factory):
    """
    Servicio real con la puerta real.

    El pipeline corre de verdad (sin RAG ni LLM, solo por tiempo): lo que se
    prueba es que la frontera se aplica **antes** de que el pipeline vea nada.
    """
    directorio = tmp_path_factory.mktemp("seguridad")

    almacen = IdentityStore(directorio / "identities.db")
    almacen.create_user("ana", CLAVE, Role.ANALYST)
    almacen.create_user("rosa", CLAVE, Role.RESPONDER)
    almacen.create_user("aitor", CLAVE, Role.AUDITOR)
    almacen.create_user("admina", CLAVE, Role.ADMIN)
    sensor = almacen.create_api_key("sysmon-SRV-APP", Role.SENSOR)

    # Límites holgados salvo en la prueba que los estrecha a propósito.
    limitador = RateLimiter({
        Role.SENSOR.value: LimitPolicy(1000, 2000, 1_000_000, 2_000_000),
        Role.ANALYST.value: LimitPolicy(1000, 2000, 0, 0),
        Role.RESPONDER.value: LimitPolicy(1000, 2000, 0, 0),
        Role.AUDITOR.value: LimitPolicy(1000, 2000, 0, 0),
        Role.ADMIN.value: LimitPolicy(1000, 2000, 0, 0),
        "anonymous": LimitPolicy(1000, 2000, 0, 0),
    })

    auditoria = AuditLog(directorio / "audit_seguridad.jsonl", secret_key="clave-de-prueba")
    puerta = SecurityGate(SecurityConfig(
        identity_db=directorio / "identities.db", jwt_secret=SECRETO,
        audit_log=auditoria, rate_limiter=limitador,
    ))

    svc = IngestService(
        rules_dir=RULES, db_path=directorio / "events.db",
        audit_path=directorio / "audit.jsonl", queue_maxsize=2000, batch_size=200,
        enable_rag=False, enable_llm=False,
    )
    with TestClient(create_app(svc, gate=puerta),
                    base_url="https://testserver") as cliente:
        yield {"cliente": cliente, "puerta": puerta, "almacen": almacen,
               "sensor": sensor, "auditoria": auditoria, "dir": directorio,
               "limitador": limitador}


def _token(cliente, usuario: str, clave: str = CLAVE) -> str:
    r = cliente.post("/api/v1/auth/token",
                     json={"username": usuario, "password": clave})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def _bearer(cliente, usuario: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {_token(cliente, usuario)}"}


# ----------------------------- sin credencial -------------------------------
@pytest.mark.parametrize("metodo,ruta", [
    ("post", "/api/v1/events"),
    ("get", "/api/v1/metrics"),
    ("get", "/api/v1/incidents"),
    ("get", "/api/v1/identities"),
    ("get", "/api/v1/auth/whoami"),
])
def test_sin_credencial_no_se_pasa(entorno, metodo, ruta):
    """Ataque: llegar a la API desde la red sin presentar nada."""
    cliente = entorno["cliente"]
    r = (cliente.post(ruta, json={"events": [_evento()]}) if metodo == "post"
         else cliente.get(ruta))
    assert r.status_code == 401
    assert r.headers.get("WWW-Authenticate", "").startswith("Bearer")


def test_las_sondas_de_salud_siguen_abiertas(entorno):
    """
    Un orquestador no presenta credenciales: si `/health` exigiera una, mataría
    el proceso creyéndolo muerto.
    """
    r = entorno["cliente"].get("/api/v1/health")
    assert r.status_code == 200
    assert r.json()["status"] == "alive"
    # Y no revela nada más.
    assert set(r.json()) == {"status", "service"}


def test_ready_sin_credencial_no_revela_el_interior(entorno):
    """Fuga de información: el estado de componentes es reconocimiento útil."""
    cliente = entorno["cliente"]
    anonimo = cliente.get("/api/v1/ready").json()
    assert set(anonimo) == {"ready"}

    detalle = cliente.get("/api/v1/ready", headers=_bearer(cliente, "ana")).json()
    assert "components" in detalle and "security" in detalle
    assert "token_secret_warning" in detalle["security"]


# ----------------------------- credenciales ---------------------------------
def test_la_clave_de_api_ingiere(entorno):
    r = entorno["cliente"].post(
        "/api/v1/events", json={"events": [_evento(1)]},
        headers={"X-API-Key": entorno["sensor"].token})
    assert r.status_code == 202
    assert r.json()["accepted"] == 1


def test_clave_de_api_mal_formada(entorno):
    for mala in ("", "basura", "cs_soloalgo", "xx_1234_secreto"):
        r = entorno["cliente"].post("/api/v1/events", json={"events": [_evento()]},
                                    headers={"X-API-Key": mala})
        assert r.status_code == 401, mala


def test_dos_credenciales_a_la_vez_se_rechazan(entorno):
    """
    Confusión de credencial: presentar dos y dejar que el servidor elija es
    cómo se cuela una escalada de privilegio.
    """
    cliente = entorno["cliente"]
    r = cliente.post("/api/v1/events", json={"events": [_evento()]},
                     headers={"X-API-Key": entorno["sensor"].token,
                              **_bearer(cliente, "admina")})
    assert r.status_code == 401
    assert "una sola credencial" in r.text


def test_clave_revocada_deja_de_valer(entorno):
    """Ataque: seguir usando una credencial retirada."""
    almacen, cliente = entorno["almacen"], entorno["cliente"]
    efimera = almacen.create_api_key("sensor-temporal", Role.SENSOR)
    cabecera = {"X-API-Key": efimera.token}
    assert cliente.post("/api/v1/events", json={"events": [_evento(2)]},
                        headers=cabecera).status_code == 202

    assert almacen.revoke_api_key(efimera.key_id) is True
    r = cliente.post("/api/v1/events", json={"events": [_evento(3)]}, headers=cabecera)
    assert r.status_code == 401
    assert "revocada" in r.text


def test_clave_caducada_no_vale(entorno, tmp_path):
    almacen = IdentityStore(tmp_path / "caducadas.db")
    clave = almacen.create_api_key("vieja", Role.SENSOR, expires_in_days=1)
    with sqlite3.connect(tmp_path / "caducadas.db") as con:
        con.execute("UPDATE api_keys SET expires_at = '2020-01-01T00:00:00+00:00'")
        con.commit()
    with pytest.raises(AuthError, match="caducada"):
        almacen.verify_api_key(clave.token)


def test_el_secreto_no_se_guarda_en_claro(entorno):
    """Si el almacén se filtra, las credenciales no deben viajar con él."""
    ruta = entorno["dir"] / "identities.db"
    crudo = ruta.read_bytes()
    assert entorno["sensor"].secret.encode() not in crudo
    assert CLAVE.encode() not in crudo


def test_usuario_inexistente_y_contrasena_mala_dan_el_mismo_error(entorno):
    """
    Enumeración de usuarios: si los mensajes difieren, el formulario dice
    quién existe.
    """
    cliente = entorno["cliente"]
    a = cliente.post("/api/v1/auth/token", json={"username": "ana", "password": "mala-mala-mala"})
    b = cliente.post("/api/v1/auth/token", json={"username": "noexiste", "password": "mala-mala-mala"})
    assert a.status_code == b.status_code == 401
    assert a.json()["reason"] == b.json()["reason"] == "credenciales inválidas"


def test_bloqueo_por_intentos_fallidos(entorno, tmp_path):
    """Fuerza bruta sobre la contraseña de un analista."""
    almacen = IdentityStore(tmp_path / "bloqueo.db")
    almacen.create_user("victima", CLAVE, Role.ANALYST)
    for _ in range(5):
        with pytest.raises(AuthError):
            almacen.verify_password("victima", "incorrecta-incorrecta")
    # A partir de aquí, ni siquiera la contraseña correcta entra.
    with pytest.raises(AuthError, match="bloqueada") as exc:
        almacen.verify_password("victima", CLAVE)
    assert exc.value.retry_after and exc.value.retry_after > 0


def test_usuario_deshabilitado_no_entra(entorno, tmp_path):
    almacen = IdentityStore(tmp_path / "deshabilitado.db")
    almacen.create_user("saliente", CLAVE, Role.ANALYST)
    assert almacen.set_disabled("saliente") is True
    with pytest.raises(AuthError, match="deshabilitada"):
        almacen.verify_password("saliente", CLAVE)


def test_contrasena_corta_se_rechaza(tmp_path):
    almacen = IdentityStore(tmp_path / "cortas.db")
    with pytest.raises(ValueError, match="12 caracteres"):
        almacen.create_user("flojo", "corta", Role.ANALYST)


# -------------------------------- tokens ------------------------------------
def test_token_alg_none_se_rechaza():
    """
    Confusión de algoritmos: la cabecera la escribe el cliente. Aceptar `none`
    convierte el JWT en un campo de texto que el atacante controla.
    """
    firmante = TokenSigner(SECRETO)
    token, _ = firmante.issue("ana", "analyst")
    cabecera, cuerpo, _ = token.split(".")

    def b64(d: dict) -> str:
        return base64.urlsafe_b64encode(
            json.dumps(d, separators=(",", ":")).encode()).rstrip(b"=").decode()

    falso = f"{b64({'alg': 'none', 'typ': 'JWT'})}.{cuerpo}."
    with pytest.raises(TokenError, match="algoritmo"):
        firmante.verify(falso)


def test_token_manipulado_se_rechaza():
    """Escalada de privilegio: cambiar `role` a admin y volver a enviarlo."""
    firmante = TokenSigner(SECRETO)
    token, _ = firmante.issue("ana", "analyst")
    cabecera, cuerpo, firma = token.split(".")

    claims = json.loads(base64.urlsafe_b64decode(cuerpo + "=" * (-len(cuerpo) % 4)))
    claims["role"] = "admin"
    nuevo = base64.urlsafe_b64encode(
        json.dumps(claims, separators=(",", ":")).encode()).rstrip(b"=").decode()

    with pytest.raises(TokenError, match="firma"):
        firmante.verify(f"{cabecera}.{nuevo}.{firma}")


def test_token_de_otro_secreto_se_rechaza():
    """Un token firmado por otra instalación no vale en esta."""
    emitido, _ = TokenSigner("f" * 48).issue("ana", "admin")
    with pytest.raises(TokenError, match="firma"):
        TokenSigner(SECRETO).verify(emitido)


def test_token_caducado_se_rechaza():
    firmante = TokenSigner(SECRETO)
    token, _ = firmante.issue("ana", "analyst", ttl_s=-3600)
    with pytest.raises(TokenError, match="caducado"):
        firmante.verify(token)


def test_token_sin_caducidad_se_rechaza():
    """Un token eterno emitido por error es indistinguible de uno legítimo."""
    firmante = TokenSigner(SECRETO)
    cabecera = base64.urlsafe_b64encode(
        json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    cuerpo = base64.urlsafe_b64encode(
        json.dumps({"iss": "cybersentinel", "sub": "ana", "role": "admin"}).encode()
    ).rstrip(b"=").decode()
    firma = base64.urlsafe_b64encode(
        firmante._sign(f"{cabecera}.{cuerpo}".encode())).rstrip(b"=").decode()
    with pytest.raises(TokenError, match="caducidad"):
        firmante.verify(f"{cabecera}.{cuerpo}.{firma}")


def test_secreto_corto_se_rechaza():
    with pytest.raises(ValueError, match="al menos 32 bytes"):
        TokenSigner("corto")


def test_sin_secreto_configurado_se_declara(monkeypatch):
    """
    Sin secreto no se inventa uno fijo —eso sería una puerta trasera—: se
    genera efímero y el servicio lo declara en `/ready`.
    """
    monkeypatch.delenv("CYBERSENTINEL_JWT_SECRET", raising=False)
    origen = load_secret()
    assert origen.source == "ephemeral"
    assert origen.warning and "producción" in origen.warning
    assert not origen.is_persistent


def test_logout_revoca_el_token(entorno):
    cliente = entorno["cliente"]
    cabecera = _bearer(cliente, "ana")
    assert cliente.get("/api/v1/auth/whoami", headers=cabecera).status_code == 200
    assert cliente.post("/api/v1/auth/logout", headers=cabecera).json()["revoked"] is True
    r = cliente.get("/api/v1/auth/whoami", headers=cabecera)
    assert r.status_code == 401 and "revocado" in r.text


# --------------------------------- RBAC -------------------------------------
def test_el_sensor_no_puede_leer_incidentes(entorno):
    """
    Robar la credencial de un sensor —que vive en un fichero de configuración—
    no debe dar acceso al historial de incidentes.
    """
    r = entorno["cliente"].get("/api/v1/incidents",
                               headers={"X-API-Key": entorno["sensor"].token})
    assert r.status_code == 403
    assert "incidents:read" in r.text


def test_el_analista_no_puede_ingerir(entorno):
    """Separación de funciones: quien investiga no inyecta telemetría."""
    cliente = entorno["cliente"]
    r = cliente.post("/api/v1/events", json={"events": [_evento()]},
                     headers=_bearer(cliente, "ana"))
    assert r.status_code == 403
    assert "events:write" in r.text


def test_el_analista_lee_incidentes_y_metricas(entorno):
    cliente = entorno["cliente"]
    cabecera = _bearer(cliente, "ana")
    assert cliente.get("/api/v1/incidents", headers=cabecera).status_code == 200
    assert cliente.get("/api/v1/metrics", headers=cabecera).status_code == 200


def test_el_auditor_no_escribe_nada(entorno):
    """Quien puede modificar lo que audita anula la auditoría."""
    cliente = entorno["cliente"]
    cabecera = _bearer(cliente, "aitor")
    assert cliente.post("/api/v1/events", json={"events": [_evento()]},
                        headers=cabecera).status_code == 403
    assert cliente.post("/api/v1/identities/keys", json={"label": "x"},
                        headers=cabecera).status_code == 403
    assert Permission.AUDIT_READ in permissions_for(Role.AUDITOR)
    assert Permission.INCIDENTS_WRITE not in permissions_for(Role.AUDITOR)


def test_solo_el_admin_gestiona_credenciales(entorno):
    cliente = entorno["cliente"]
    for usuario in ("ana", "rosa", "aitor"):
        assert cliente.get("/api/v1/identities",
                           headers=_bearer(cliente, usuario)).status_code == 403

    admin = _bearer(cliente, "admina")
    r = cliente.post("/api/v1/identities/keys",
                     json={"label": "suricata-dmz", "role": "sensor"}, headers=admin)
    assert r.status_code == 201
    emitida = r.json()
    assert emitida["api_key"].startswith("cs_")

    # La clave nueva funciona...
    assert cliente.post("/api/v1/events", json={"events": [_evento(4)]},
                        headers={"X-API-Key": emitida["api_key"]}).status_code == 202
    # ...y deja de funcionar al revocarla desde la API.
    assert cliente.delete(f"/api/v1/identities/keys/{emitida['key_id']}",
                          headers=admin).json()["revoked"] is True
    assert cliente.post("/api/v1/events", json={"events": [_evento(5)]},
                        headers={"X-API-Key": emitida["api_key"]}).status_code == 401


def test_el_admin_no_puede_inyectar_telemetria(entorno):
    """
    Administrar no es emitir. Si el admin pudiera ingerir, la auditoría no
    podría distinguir quién metió un evento en el sistema.
    """
    cliente = entorno["cliente"]
    r = cliente.post("/api/v1/events", json={"events": [_evento()]},
                     headers=_bearer(cliente, "admina"))
    assert r.status_code == 403


def test_rol_desconocido_no_concede_nada():
    """
    Despliegue escalonado: un token con un rol que esta versión no conoce debe
    quedarse sin permisos, no provocar un 500.
    """
    assert permissions_for("rol-del-futuro") == frozenset()


def test_whoami_declara_los_permisos(entorno):
    cliente = entorno["cliente"]
    datos = cliente.get("/api/v1/auth/whoami", headers=_bearer(cliente, "rosa")).json()
    assert datos["role"] == "responder"
    assert "response:approve" in datos["permissions"]
    assert "identity:admin" not in datos["permissions"]


# ----------------------------- límite de caudal -----------------------------
def test_limite_de_peticiones(tmp_path):
    """Un sensor mal configurado no debe poder agotar el servicio."""
    limitador = RateLimiter({"sensor": LimitPolicy(1, 3, 1000, 1000),
                             "anonymous": LimitPolicy(1, 3, 0, 0)})
    permitidas = sum(limitador.check("key:x", "sensor").allowed for _ in range(10))
    assert permitidas == 3, "el cubo debe agotarse tras la ráfaga configurada"

    decision = limitador.check("key:x", "sensor")
    assert not decision.allowed
    assert decision.headers()["Retry-After"] == "1"

    # Y se rellena con el tiempo, no se queda bloqueado para siempre.
    time.sleep(1.1)
    assert limitador.check("key:x", "sensor").allowed


def test_el_limite_es_por_cliente_no_global(tmp_path):
    """
    Es la diferencia con la contrapresión de la cola: el cliente desbocado se
    ahoga solo, no deja sin servicio a los otros cuarenta sensores.
    """
    limitador = RateLimiter({"sensor": LimitPolicy(1, 2, 1000, 1000),
                             "anonymous": LimitPolicy(1, 2, 0, 0)})
    for _ in range(5):
        limitador.check("key:desbocado", "sensor")
    assert limitador.check("key:tranquilo", "sensor").allowed


def test_limite_por_eventos_no_solo_por_peticiones():
    """
    Diez lotes de 10 000 eventos cumplen cualquier límite por petición y
    entregan 100 000 eventos. Por eso se cobra también por evento.
    """
    limitador = RateLimiter({"sensor": LimitPolicy(100, 100, 10, 10),
                             "anonymous": LimitPolicy(1, 2, 0, 0)})
    assert limitador.check("key:x", "sensor", events=10).allowed
    decision = limitador.check("key:x", "sensor", events=10)
    assert not decision.allowed and decision.scope == "events"


def test_limite_de_eventos_en_la_api(tmp_path):
    """El 429 por caudal llega antes de que el pipeline vea el lote."""
    directorio = tmp_path / "caudal"
    directorio.mkdir()
    almacen = IdentityStore(directorio / "identities.db")
    clave = almacen.create_api_key("ruidoso", Role.SENSOR)
    puerta = SecurityGate(SecurityConfig(
        identity_db=directorio / "identities.db", jwt_secret=SECRETO,
        rate_limiter=RateLimiter({"sensor": LimitPolicy(100, 100, 5, 5),
                                  "anonymous": LimitPolicy(1, 2, 0, 0)}),
    ))
    svc = IngestService(rules_dir=RULES, db_path=directorio / "e.db",
                        audit_path=None, queue_maxsize=500, batch_size=100,
                        enable_rag=False, enable_llm=False)
    with TestClient(create_app(svc, gate=puerta),
                    base_url="https://testserver") as cliente:
        cabecera = {"X-API-Key": clave.token}
        lote = {"events": [_evento(i) for i in range(5)]}
        assert cliente.post("/api/v1/events", json=lote, headers=cabecera).status_code == 202
        r = cliente.post("/api/v1/events", json=lote, headers=cabecera)
        assert r.status_code == 429
        assert int(r.headers["Retry-After"]) >= 1
        assert r.json()["detail"]["events_in_batch"] == 5


def test_los_cubos_no_crecen_sin_limite():
    """
    Un diccionario indexado por IP sin tope es un vector de agotamiento de
    memoria: basta con pedir desde muchos orígenes falsificados.
    """
    limitador = RateLimiter({"anonymous": LimitPolicy(1, 1, 0, 0)}, max_buckets=50)
    for i in range(500):
        limitador.check(f"ip:10.0.0.{i}", "anonymous")
    assert limitador.stats()["live_buckets"] <= 50


# -------------------------------- auditoría ---------------------------------
def test_la_auditoria_registra_la_frontera(entorno):
    """
    Emisiones de token y denegaciones quedan en la **misma** cadena encadenada
    que el resto: borrar un intento fallido invalida todo lo posterior.
    """
    cliente, auditoria = entorno["cliente"], entorno["auditoria"]
    _bearer(cliente, "ana")                                   # token_issued
    cliente.get("/api/v1/identities", headers=_bearer(cliente, "ana"))  # authz_denied

    acciones = {e.action for e in AuditLog(auditoria.path, secret_key="clave-de-prueba").entries}
    assert "token_issued" in acciones
    assert "authz_denied" in acciones

    ok, indice, _ = AuditLog(auditoria.path, secret_key="clave-de-prueba").verify_detailed()
    assert ok, f"cadena rota en {indice}"


def test_la_auditoria_no_guarda_secretos(entorno):
    """Un log de auditoría con contraseñas dentro es una filtración firmada."""
    contenido = Path(entorno["auditoria"].path).read_text(encoding="utf-8")
    assert CLAVE not in contenido
    assert entorno["sensor"].secret not in contenido


def test_los_fallos_repetidos_no_inflan_la_auditoria(entorno, tmp_path):
    """
    Un atacante que dispara credenciales falsas no debe poder escribir él mismo
    el tamaño del log: los fallos se agregan por ventana.
    """
    auditoria = AuditLog(tmp_path / "fallos.jsonl", secret_key="k")
    puerta = SecurityGate(SecurityConfig(
        identity_db=tmp_path / "vacio.db", jwt_secret=SECRETO, audit_log=auditoria))
    for _ in range(200):
        puerta._record_failure("10.0.0.9", "credenciales inválidas", "/api/v1/auth/token")

    entradas = [e for e in auditoria.entries if e.action == "auth_failed"]
    assert len(entradas) == 1
    assert entradas[0].detail["failures_since_last_entry"] == 1


# ------------------------------- transporte ---------------------------------
@pytest.fixture(scope="module")
def app_tls(tmp_path_factory):
    """Aplicación mínima para probar la política de transporte."""
    directorio = tmp_path_factory.mktemp("tls")
    almacen = IdentityStore(directorio / "identities.db")
    clave = almacen.create_api_key("sensor-tls", Role.SENSOR)
    abierto = LimitPolicy(10_000, 20_000, 10_000_000, 20_000_000)
    puerta = SecurityGate(SecurityConfig(
        identity_db=directorio / "identities.db", jwt_secret=SECRETO,
        rate_limiter=RateLimiter({r.value: abierto for r in Role} | {"anonymous": abierto}),
    ))
    svc = IngestService(rules_dir=RULES, db_path=directorio / "e.db",
                        incidents_path=directorio / "i.db", audit_path=None,
                        queue_maxsize=500, batch_size=100,
                        enable_rag=False, enable_llm=False)
    return {"app": create_app(svc, gate=puerta), "key": clave.token, "svc": svc}


def _cliente(app_tls, *, esquema="http", origen=("203.0.113.9", 4444), **kwargs):
    return TestClient(app_tls["app"], base_url=f"{esquema}://testserver",
                      client=origen, **kwargs)


def test_texto_en_claro_desde_fuera_se_rechaza(app_tls):
    """
    Ataque: escuchar la red. Comprobar una contraseña que acaba de viajar
    legible no la hace menos legible; lo único útil es no seguir.
    """
    with _cliente(app_tls) as c:
        r = c.post("/api/v1/events", json={"events": [_evento()]},
                   headers={"X-API-Key": app_tls["key"]})
    assert r.status_code == 403
    assert r.json()["error"] == "tls_requerido"
    assert "viajarían en claro" in r.json()["reason"]


def test_con_tls_la_misma_peticion_pasa(app_tls):
    with _cliente(app_tls, esquema="https") as c:
        r = c.post("/api/v1/events", json={"events": [_evento()]},
                   headers={"X-API-Key": app_tls["key"]})
    assert r.status_code == 202


def test_el_bucle_local_puede_usar_texto_en_claro(app_tls):
    """Desarrollo en la propia máquina: no hay red que escuchar."""
    with _cliente(app_tls, origen=("127.0.0.1", 5555)) as c:
        r = c.post("/api/v1/events", json={"events": [_evento()]},
                   headers={"X-API-Key": app_tls["key"]})
    assert r.status_code == 202


def test_la_sonda_de_salud_responde_aunque_no_haya_tls(app_tls):
    """
    Devolver 403 en `/health` haría que el orquestador reiniciase el proceso
    por un problema de red. No lleva credenciales ni revela nada.
    """
    with _cliente(app_tls) as c:
        assert c.get("/api/v1/health").status_code == 200


def test_x_forwarded_proto_no_se_cree_sin_proxy_declarado(app_tls):
    """
    Falsificación de cabecera: si `X-Forwarded-Proto` se creyera siempre,
    cualquiera se declara seguro escribiendo una línea y la comprobación no
    sirve de nada.
    """
    with _cliente(app_tls) as c:
        r = c.post("/api/v1/events", json={"events": [_evento()]},
                   headers={"X-API-Key": app_tls["key"],
                            "X-Forwarded-Proto": "https"})
    assert r.status_code == 403


def test_con_proxy_declarado_si_se_admite_x_forwarded_proto(app_tls, monkeypatch):
    politica = TransportPolicy(allow_plaintext=False, trust_forwarded=True)
    monkeypatch.setattr(app_tls["app"].state, "transport", politica, raising=False)
    with _cliente(app_tls) as c:
        r = c.post("/api/v1/events", json={"events": [_evento()]},
                   headers={"X-API-Key": app_tls["key"],
                            "X-Forwarded-Proto": "https"})
    assert r.status_code == 202


def test_la_escotilla_queda_declarada(app_tls, monkeypatch):
    """
    `ALLOW_PLAINTEXT` existe para el terminador TLS que no añade cabeceras de
    reenvío. Se admite, pero nadie puede decir después que no lo sabía.
    """
    politica = TransportPolicy(allow_plaintext=True, trust_forwarded=False)
    monkeypatch.setattr(app_tls["app"].state, "transport", politica, raising=False)
    with _cliente(app_tls) as c:
        assert c.post("/api/v1/events", json={"events": [_evento()]},
                      headers={"X-API-Key": app_tls["key"]}).status_code == 202
    assert "ALLOW_PLAINTEXT" in politica.status()["plaintext_allowed_from"]
    assert politica.status()["warning"]


def test_hsts_solo_sobre_una_conexion_ya_segura(app_tls):
    """
    Anunciar HSTS por HTTP no protege de nada —quien lee la respuesta puede
    quitarlo— y puede dejar inaccesible un laboratorio sin certificado.
    """
    with _cliente(app_tls, esquema="https") as c:
        segura = c.get("/api/v1/health")
    with _cliente(app_tls, origen=("127.0.0.1", 5555)) as c:
        clara = c.get("/api/v1/health")
    assert "max-age=31536000" in segura.headers["Strict-Transport-Security"]
    assert "Strict-Transport-Security" not in clara.headers


def test_la_politica_por_defecto_no_admite_texto_en_claro(monkeypatch):
    monkeypatch.delenv("CYBERSENTINEL_ALLOW_PLAINTEXT", raising=False)
    monkeypatch.delenv("CYBERSENTINEL_TRUST_FORWARDED_FOR", raising=False)
    politica = TransportPolicy.from_env()
    assert politica.allow_plaintext is False
    assert politica.trust_forwarded is False
    assert politica.status()["warning"] is None
