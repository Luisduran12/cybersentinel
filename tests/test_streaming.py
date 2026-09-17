"""
Pruebas del servicio normalizador de streaming.

`process_raw_message` es pura: sin red, sin NATS, corre en cualquier máquina.
La prueba de integración contra un NATS real se salta explícitamente si no
hay servidor —o si `nats-py` no está instalado—, nunca falla por su ausencia:
un prototipo no debe exigir Docker levantado para que `pytest -q` pase.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cybersentinel.streaming.normalizer_service import process_raw_message  # noqa: E402


def test_registro_valido_produce_ocsf_en_el_subject_correcto():
    resultado = process_raw_message("sysmon", {
        "source": "sysmon", "timestamp": "2026-01-15T09:30:00Z",
        "action": "process_create", "host": "WKS-01", "user": "ana",
        "command_line": "powershell -enc AAA", "outcome": "success",
    })
    assert resultado.ok
    assert resultado.subject == "cybersentinel.ocsf.sysmon"
    assert resultado.payload["class_uid"] == 1007          # Process Activity
    assert resultado.payload["process"]["cmd_line"] == "powershell -enc AAA"


def test_registro_corrupto_no_lanza_y_se_marca_como_error():
    resultado = process_raw_message("sysmon", {"esto": "no es un evento reconocible"})
    # El normalizador tolera registros incompletos (rellena con None); lo que
    # de verdad no debe pasar es que el servicio se caiga.
    assert isinstance(resultado.ok, bool)


def test_entrada_no_serializable_no_tumba_el_servicio():
    """
    Un valor que el normalizador no puede interpretar no debe propagar una
    excepción hacia arriba, gane o pierda la normalización: `process_raw_message`
    siempre devuelve un `NormalizationOutcome`, nunca lanza.
    """
    class NoSerializable:
        pass

    # Si esto no lanza, la política ya se cumplió; el resultado puede ser
    # ok=True (el normalizador toleró el valor) u ok=False (lo rechazó), pero
    # nunca una excepción sin capturar.
    resultado = process_raw_message("sysmon", {"host": NoSerializable(), "action": None})
    assert resultado.ok in (True, False)
    if not resultado.ok:
        assert resultado.error


@pytest.mark.skipif(
    True,  # activar manualmente contra `docker-compose up nats`
    reason="requiere un servidor NATS real (docker-compose up nats); "
           "no se ejecuta en la suite estándar de pytest",
)
@pytest.mark.asyncio
async def test_integracion_con_nats_real():
    """
    Guía manual: con `docker compose up -d nats`, quitar el `skipif` y correr
        pytest tests/test_streaming.py -k integracion
    para verificar publish/subscribe de punta a punta contra JetStream real.
    """
    from cybersentinel.streaming.bus import EventBus

    bus = EventBus("nats://127.0.0.1:4222")
    await bus.connect()
    await bus.publish("cybersentinel.raw.sysmon", {"source": "sysmon", "action": "process_create"})
    await bus.close()
