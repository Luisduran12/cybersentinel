"""
Generador de telemetría sintética contra la API de ingestión.

    python scripts/telemetry_generator.py --rate 100  --seconds 10
    python scripts/telemetry_generator.py --rate 1000 --seconds 10
    python scripts/telemetry_generator.py --rate 5000 --seconds 10

Genera carga a un caudal objetivo y mide lo que realmente ocurre. **No fabrica
resultados**: no toca el detector, no inventa puntuaciones y no decide qué es un
incidente. Solo emite telemetría sintética de laboratorio y reporta el caudal y
la latencia observados desde el lado del cliente.

Los eventos imitan telemetría Windows/Sysmon y de red. Los "comandos" son
cadenas ilustrativas para ejercitar las reglas: no contienen exploits, payloads
ni artefactos maliciosos reales.
"""
from __future__ import annotations

import argparse
import json
import random
import statistics
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

HOSTS = ["WKS-01", "WKS-02", "WKS-03", "SRV-APP", "SRV-DB"]
USERS = ["ana", "carlos", "sofia", "jdoe", "admin"]
BENIGNOS = ["chrome.exe --tab", "code.exe --folder", "explorer.exe",
            "python.exe script.py", "svchost.exe -k netsvcs"]

#: Patrones que SÍ pueden activar las reglas del proyecto. Son cadenas de texto
#: ilustrativas, no comandos operativos.
SOSPECHOSOS = [
    ("sysmon", "powershell.exe -nop -w hidden -enc SQBFAFgAKAAuAC4A"),
    ("sysmon", "schtasks /create /sc minute /tn Updater /tr tarea.ps1"),
    ("sysmon", "nmap -sS -p- 10.0.0.0/24"),
]


def genera_evento(rng: random.Random, momento: datetime, prob_sospechoso: float) -> dict:
    """Un evento de telemetría sintética."""
    ts = momento.isoformat()

    if rng.random() < prob_sospechoso:
        tipo = rng.random()
        if tipo < 0.5:
            fuente, comando = rng.choice(SOSPECHOSOS)
            return {"source": fuente, "timestamp": ts, "action": "process_create",
                    "host": "SRV-APP", "user": "admin", "command_line": comando,
                    "process_name": comando.split()[0], "outcome": "success"}
        if tipo < 0.75:
            # Ráfaga de autenticación fallida (alimenta la regla agregada).
            return {"source": "auth", "timestamp": ts, "action": "user_login",
                    "host": "SRV-APP", "user": "admin", "src_ip": "203.0.113.66",
                    "outcome": "failure"}
        # Conexión a puerto asociado a herramientas ofensivas.
        return {"source": "firewall", "timestamp": ts, "action": "connection",
                "host": "SRV-APP", "src_ip": "10.0.0.50", "dst_ip": "203.0.113.66",
                "dst_port": 4444, "protocol": "tcp", "bytes_out": rng.randint(1000, 5000)}

    if rng.random() < 0.6:
        return {"source": "sysmon", "timestamp": ts, "action": "process_create",
                "host": rng.choice(HOSTS), "user": rng.choice(USERS),
                "command_line": f"{rng.choice(BENIGNOS)} {rng.randint(1, 999)}",
                "process_name": rng.choice(BENIGNOS).split()[0], "outcome": "success"}
    return {"source": "firewall", "timestamp": ts, "action": "connection",
            "host": rng.choice(HOSTS), "src_ip": f"10.0.0.{rng.randint(10, 60)}",
            "dst_ip": f"93.184.216.{rng.randint(1, 250)}",
            "dst_port": rng.choice([443, 443, 80, 53]), "protocol": "tcp",
            "bytes_out": rng.randint(200, 50_000), "bytes_in": rng.randint(500, 900_000)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8000/api/v1/events")
    parser.add_argument("--rate", type=int, default=100, help="Eventos por segundo objetivo.")
    parser.add_argument("--seconds", type=int, default=10)
    parser.add_argument("--batch", type=int, default=50, help="Eventos por petición HTTP.")
    parser.add_argument("--suspicious", type=float, default=0.05,
                        help="Proporción de eventos sospechosos (0.0-1.0).")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--json", help="Ruta para volcar el informe.")
    args = parser.parse_args()

    import httpx

    rng = random.Random(args.seed)
    objetivo = args.rate * args.seconds
    por_peticion = min(args.batch, args.rate)
    intervalo = por_peticion / args.rate

    print(f"Generando {objetivo:,} eventos a {args.rate:,}/s durante {args.seconds}s")
    print(f"  lotes de {por_peticion} · {args.suspicious:.0%} sospechosos · semilla {args.seed}")
    print(f"  destino: {args.url}\n")

    base = datetime.now(tz=timezone.utc)
    latencias: list[float] = []
    enviados = aceptados = rechazados = 0
    codigos: dict[int, int] = {}
    errores_red = 0

    inicio = time.perf_counter()
    siguiente = inicio
    n = 0

    with httpx.Client(timeout=30.0) as cliente:
        while n < objetivo:
            cuantos = min(por_peticion, objetivo - n)
            lote = [
                genera_evento(rng, base + timedelta(milliseconds=(n + i) * 10),
                              args.suspicious)
                for i in range(cuantos)
            ]
            n += cuantos

            t0 = time.perf_counter()
            try:
                r = cliente.post(args.url, json={"events": lote})
                latencias.append((time.perf_counter() - t0) * 1000.0)
                codigos[r.status_code] = codigos.get(r.status_code, 0) + 1
                if r.status_code in (200, 202, 207, 429, 422):
                    datos = r.json()
                    aceptados += datos.get("accepted", 0)
                    rechazados += datos.get("rejected", 0)
            except httpx.HTTPError as exc:
                errores_red += 1
                print(f"  error de red: {type(exc).__name__}: {exc}")
            enviados += cuantos

            siguiente += intervalo
            espera = siguiente - time.perf_counter()
            if espera > 0:
                time.sleep(espera)

    duracion = time.perf_counter() - inicio

    def pct(p: float) -> float:
        if not latencias:
            return 0.0
        orden = sorted(latencias)
        k = (len(orden) - 1) * p / 100
        b, a = int(k), min(int(k) + 1, len(orden) - 1)
        return orden[b] + (orden[a] - orden[b]) * (k - b)

    informe = {
        "target_rate_eps": args.rate,
        "duration_s": round(duracion, 3),
        "events_sent": enviados,
        "events_accepted": aceptados,
        "events_rejected": rechazados,
        "achieved_rate_eps": round(enviados / duracion, 1),
        "accepted_rate_eps": round(aceptados / duracion, 1),
        "http_status_codes": codigos,
        "network_errors": errores_red,
        "request_latency_ms": {
            "p50": round(pct(50), 3), "p95": round(pct(95), 3),
            "p99": round(pct(99), 3),
            "mean": round(statistics.mean(latencias), 3) if latencias else 0.0,
            "max": round(max(latencias), 3) if latencias else 0.0,
            "requests": len(latencias),
        },
        "seed": args.seed,
        "suspicious_ratio": args.suspicious,
    }

    print(f"Enviados   {enviados:,} en {duracion:.2f}s -> "
          f"{informe['achieved_rate_eps']:,.0f} ev/s (objetivo {args.rate:,})")
    print(f"Aceptados  {aceptados:,}   Rechazados {rechazados:,}")
    print(f"Codigos    {codigos}")
    print(f"Latencia de peticion (ms): p50={informe['request_latency_ms']['p50']} "
          f"p95={informe['request_latency_ms']['p95']} "
          f"p99={informe['request_latency_ms']['p99']}")

    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(json.dumps(informe, indent=2, ensure_ascii=False),
                                   encoding="utf-8")
        print(f"\nInforme: {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
