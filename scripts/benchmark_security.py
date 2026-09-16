"""
Coste de la frontera de seguridad, medido.

La pregunta que esto responde es concreta: **¿cuánto cuesta autenticar?** Un
servicio de ingestión que mide 528 ev/s en el pipeline completo no puede
permitirse una comprobación de credencial de 100 ms por petición; el diseño de
`identity.py` —SHA-256 para claves de máquina, scrypt solo para contraseñas de
persona— se justifica en esa diferencia, y aquí se comprueba que la diferencia
es la que se dice.

    python scripts/benchmark_security.py [--iteraciones 20000] [--json salida.json]

Lo que NO mide: latencia de red, TLS ni el coste de la escritura de `last_used_at`
en SQLite bajo concurrencia real. Es un banco en proceso, no un despliegue.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cybersentinel.api.security import (  # noqa: E402
    IdentityStore, RateLimiter, Role, TokenSigner,
)

SECRETO = "0" * 48
CLAVE_HUMANA = "contraseña-de-laboratorio-1"


def _mide(fn, iteraciones: int) -> dict[str, float]:
    muestras = []
    for _ in range(iteraciones):
        t0 = time.perf_counter()
        fn()
        muestras.append((time.perf_counter() - t0) * 1e6)  # microsegundos
    muestras.sort()
    return {
        "n": iteraciones,
        "p50_us": round(statistics.median(muestras), 2),
        "p95_us": round(muestras[int(len(muestras) * 0.95)], 2),
        "p99_us": round(muestras[int(len(muestras) * 0.99)], 2),
        "media_us": round(statistics.fmean(muestras), 2),
        "ops_por_segundo": round(1e6 / statistics.fmean(muestras), 1),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iteraciones", type=int, default=20_000)
    parser.add_argument("--iteraciones-scrypt", type=int, default=30,
                        help="scrypt es lento a propósito; pocas muestras bastan.")
    parser.add_argument("--json", help="Ruta para volcar el informe.")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        almacen = IdentityStore(Path(tmp) / "identities.db")
        clave = almacen.create_api_key("banco-de-pruebas", Role.SENSOR)
        almacen.create_user("ana", CLAVE_HUMANA, Role.ANALYST)
        firmante = TokenSigner(SECRETO)
        token, _ = firmante.issue("ana", "analyst")
        limitador = RateLimiter()

        resultados = {
            "verify_api_key (SHA-256 + SQLite)": _mide(
                lambda: almacen.verify_api_key(clave.token), args.iteraciones // 10),
            "token JWT: verificar (HMAC-SHA256)": _mide(
                lambda: firmante.verify(token), args.iteraciones),
            "limitador: cubo de fichas": _mide(
                lambda: limitador.check("key:x", "sensor", events=50), args.iteraciones),
            "verify_password (scrypt n=2^15)": _mide(
                lambda: almacen.verify_password("ana", CLAVE_HUMANA),
                args.iteraciones_scrypt),
        }

    ancho = max(len(k) for k in resultados)
    print(f"\n{'operación'.ljust(ancho)}  {'p50':>10} {'p95':>10} {'ops/s':>12}")
    print("-" * (ancho + 36))
    for nombre, m in resultados.items():
        print(f"{nombre.ljust(ancho)}  {m['p50_us']:>9.1f}µs {m['p95_us']:>9.1f}µs "
              f"{m['ops_por_segundo']:>12,.0f}")

    api = resultados["verify_api_key (SHA-256 + SQLite)"]["media_us"]
    pwd = resultados["verify_password (scrypt n=2^15)"]["media_us"]
    print(f"\nLa contraseña cuesta {pwd / api:,.0f}× lo que la clave de máquina.")
    print("Por eso se derivan distinto: una se verifica una vez por sesión, la otra "
          "miles de veces por segundo.")

    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(
            json.dumps({"resultados": resultados,
                        "ratio_password_sobre_api_key": round(pwd / api, 1)},
                       indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\nInforme en {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
