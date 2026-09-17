"""
Servicio normalizador: la alternativa funcional a Substation/Tenzir.

Ambos son herramientas reales y usadas en la industria para transformar logs
a OCSF/ECS y enrutarlos — pero son binarios Go con su propio DSL de
transformación, y reimplementar en ese DSL la lógica que ya vive (y ya está
probada) en `ingestion/normalizer.py` habría significado mantener la misma
semántica de normalización en dos sitios. Este servicio hace exactamente lo
mismo que Substation/Tenzir harían en el pipeline de Fase 1 —consumir crudo,
normalizar, enriquecer a OCSF, reenrutar—, pero reutilizando el normalizador
existente en vez de duplicarlo. Si el volumen o la variedad de transformación
crecen más allá de lo que un `Normalizer` en Python puede sostener, migrar a
Substation/Tenzir sigue siendo la vía natural: este servicio ya aísla el punto
exacto donde ese reemplazo entraría (`process_raw_message`).

`process_raw_message` es la parte que importa probar: pura, sin red, sin
async. `run_forever` es el pegamento con NATS y no se prueba con un servidor
real en la suite principal (ver `tests/test_streaming.py`).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from ..ingestion.normalizer import Normalizer
from .bus import EventBus, OCSF_SUBJECT_FMT, RAW_SUBJECT_FMT
from ..ingestion.ocsf import to_ocsf

logger = logging.getLogger(__name__)


@dataclass
class NormalizationOutcome:
    ok: bool
    subject: str | None = None
    payload: dict[str, Any] | None = None
    error: str | None = None


def process_raw_message(source: str, record: dict[str, Any],
                         normalizer: Normalizer | None = None) -> NormalizationOutcome:
    """
    Traduce un registro crudo de `source` a OCSF.

    Nunca lanza: un registro corrupto de una fuente no puede tumbar el
    servicio ni bloquear al resto — la misma política que ya siguen los 4
    collectors en `collectors/base.py`.
    """
    normalizer = normalizer or Normalizer()
    try:
        registro = dict(record)
        registro.setdefault("source", source)
        evento = normalizer.normalize_record(registro)
        ocsf = to_ocsf(evento)
        return NormalizationOutcome(
            ok=True, subject=OCSF_SUBJECT_FMT.format(source=source), payload=ocsf)
    except Exception as exc:
        motivo = f"{type(exc).__name__}: {exc}"
        logger.error("normalizador: registro ilegible de %s (%s)", source, motivo)
        return NormalizationOutcome(ok=False, error=motivo)


async def run_forever(nats_url: str, sources: list[str]) -> None:
    """
    Se suscribe a `cybersentinel.raw.<source>` por cada fuente y republica en
    `cybersentinel.ocsf.<source>`. Requiere un servidor NATS real: ver
    `docker-compose.yml`.
    """
    bus = EventBus(nats_url)
    await bus.connect()
    normalizer = Normalizer()

    async def _manejar(source: str, datos: dict[str, Any]) -> None:
        resultado = process_raw_message(source, datos, normalizer)
        if resultado.ok:
            await bus.publish(resultado.subject, resultado.payload)
        # Un fallo de normalización ya quedó registrado en process_raw_message;
        # no se relanza, para que JetStream confirme el mensaje y no lo
        # reintente en bucle contra un registro que nunca va a normalizar.

    import asyncio

    async def _suscribir(source: str) -> None:
        await bus.subscribe(
            RAW_SUBJECT_FMT.format(source=source),
            durable=f"normalizer-{source}",
            callback=lambda datos: _manejar(source, datos),
        )

    await asyncio.gather(*(_suscribir(s) for s in sources))


def main() -> None:
    import argparse
    import asyncio
    import os

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nats-url", default=os.environ.get("NATS_URL", "nats://nats:4222"))
    parser.add_argument("--sources", nargs="+",
                        default=["sysmon", "linux", "firewall", "suricata"])
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    logger.info("Normalizador arrancando contra %s para fuentes %s", args.nats_url, args.sources)
    asyncio.run(run_forever(args.nats_url, args.sources))


if __name__ == "__main__":
    main()
