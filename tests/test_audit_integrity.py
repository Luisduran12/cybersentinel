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
