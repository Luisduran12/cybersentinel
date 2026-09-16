"""
Pruebas de integridad del registro de auditoría (Fase 0).

Cada prueba corresponde a un ataque concreto contra la trazabilidad. Las dos
primeras son las que la implementación original NO detectaba.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cybersentinel.governance import AuditLog  # noqa: E402

KEY = "clave-de-laboratorio"


def _populated(path: Path, n: int = 4, key: str | None = KEY) -> AuditLog:
    log = AuditLog(path, secret_key=key)
    for i in range(n):
        log.record("agent", "incident_analyzed", {"incident": i})
    return log


def test_chain_is_valid_when_untouched(tmp_path):
    log = _populated(tmp_path / "audit.jsonl")
    ok, bad = log.verify()
    assert ok and bad is None


def test_editing_an_entry_is_detected(tmp_path):
    log = _populated(tmp_path / "audit.jsonl")
    log.entries[0].detail = {"incident": "manipulado"}
    ok, bad = log.verify()
    assert not ok and bad == 0


def test_truncating_the_tail_is_detected(tmp_path):
    """
    Borrar las últimas entradas deja una cadena internamente válida: sin ancla
    externa, la verificación pasaba y el borrado quedaba invisible.
    """
    path = tmp_path / "audit.jsonl"
    _populated(path)
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(lines[:2]) + "\n", encoding="utf-8")

    ok, _, detail = AuditLog(path, secret_key=KEY).verify_detailed()
    assert not ok
    assert "eliminaron" in detail


def test_full_chain_rewrite_is_detected_when_signed(tmp_path):
    """
    Sin clave, un atacante recalcula toda la cadena y la verificación pasa.
    Con HMAC necesita además la clave, que no está en el archivo.
    """
    path = tmp_path / "audit.jsonl"
    _populated(path)

    # El atacante reescribe la cadena entera con SHA-256, sin conocer la clave.
    entries = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines()]
    entries[0]["detail"] = {"incident": "borrado del historial"}
    prev = AuditLog.GENESIS
    for entry in entries:
        entry["prev_hash"] = prev
        payload = {k: entry[k] for k in
                   ("index", "timestamp", "actor", "action", "detail", "prev_hash")}
        blob = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()
        entry["entry_hash"] = hashlib.sha256(blob).hexdigest()
        prev = entry["entry_hash"]
    path.write_text("\n".join(json.dumps(e, ensure_ascii=False) for e in entries) + "\n",
                    encoding="utf-8")

    ok, bad = AuditLog(path, secret_key=KEY).verify()
    assert not ok and bad == 0


def test_tampered_anchor_is_detected(tmp_path):
    """El ancla también está sellada: no basta con editarla para cuadrar el conteo."""
    path = tmp_path / "audit.jsonl"
    log = _populated(path)
    anchor = json.loads(log.anchor_path.read_text(encoding="utf-8"))
    anchor["entries"] = 2
    log.anchor_path.write_text(json.dumps(anchor, sort_keys=True), encoding="utf-8")

    ok, _, detail = AuditLog(path, secret_key=KEY).verify_detailed()
    assert not ok
    assert "ancla" in detail


def test_unsigned_log_still_works_and_warns(tmp_path):
    """Sin clave el registro funciona, pero debe declarar su límite."""
    path = tmp_path / "audit.jsonl"
    log = _populated(path, key=None)
    assert not log.is_signed
    ok, _, detail = log.verify_detailed()
    assert ok
    assert "sin clave de firma" in detail


def test_key_is_read_from_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERSENTINEL_AUDIT_KEY", KEY)
    log = AuditLog(tmp_path / "audit.jsonl")
    assert log.is_signed
    log.record("agent", "test", {"a": 1})
    assert log.entries[0].algo == "hmac-sha256"


def test_signature_uses_hmac(tmp_path):
    """La firma es HMAC con la clave, no un SHA-256 que cualquiera recalcula."""
    log = _populated(tmp_path / "audit.jsonl", n=1)
    entry = log.entries[0]
    expected = hmac.new(KEY.encode(), entry.payload().encode(), hashlib.sha256).hexdigest()
    assert entry.entry_hash == expected


# --- Varios escritores sobre el mismo registro ------------------------------
def test_dos_instancias_sobre_el_mismo_archivo_no_rompen_la_cadena(tmp_path):
    """
    Regresión de un fallo real, no de uno imaginado.

    Cuando la API empezó a auditar la autenticación en el mismo registro que el
    pipeline, había dos objetos `AuditLog` apuntando al mismo archivo. Cada uno
    calculaba `index` y `prev_hash` desde su propia lista en memoria, así que el
    segundo empezaba otra vez en el índice 0 y el archivo acababa con dos
    cadenas entrelazadas. `verify-audit` sobre un despliegue de verdad devolvía
    «integridad COMPROMETIDA (entrada #0)».

    Lo grave no era perder la verificación: era perderla justo cuando había más
    que auditar.
    """
    ruta = tmp_path / "compartido.jsonl"
    pipeline = AuditLog(ruta, secret_key="clave")
    frontera = AuditLog(ruta, secret_key="clave")

    pipeline.record("agent", "incident_analyzed", {"n": 1})
    frontera.record("user:ana", "token_issued", {"role": "analyst"})
    pipeline.record("agent", "incident_analyzed", {"n": 2})
    frontera.record("user:ana", "authz_denied", {"path": "/x"})

    ok, indice, detalle = AuditLog(ruta, secret_key="clave").verify_detailed()
    assert ok, f"cadena rota en {indice}: {detalle}"

    releido = AuditLog(ruta, secret_key="clave")
    assert [e.index for e in releido.entries] == [0, 1, 2, 3]
    assert [e.action for e in releido.entries] == [
        "incident_analyzed", "token_issued", "incident_analyzed", "authz_denied"]


def test_escrituras_concurrentes_mantienen_la_cadena(tmp_path):
    """
    La API audita desde el hilo de la petición y el worker desde el suyo: sin
    candado, dos `record` simultáneos calculan el mismo `prev_hash` y uno de los
    dos queda huérfano.
    """
    import threading

    ruta = tmp_path / "concurrente.jsonl"
    registros = [AuditLog(ruta, secret_key="k") for _ in range(4)]
    barrera = threading.Barrier(len(registros))

    def escribir(log, n):
        barrera.wait()
        for i in range(10):
            log.record(f"hilo-{n}", "evento", {"i": i})

    hilos = [threading.Thread(target=escribir, args=(log, n))
             for n, log in enumerate(registros)]
    for h in hilos:
        h.start()
    for h in hilos:
        h.join()

    final = AuditLog(ruta, secret_key="k")
    assert len(final.entries) == 40
    ok, indice, detalle = final.verify_detailed()
    assert ok, f"cadena rota en {indice}: {detalle}"
