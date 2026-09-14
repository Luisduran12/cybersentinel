"""
Generador de telemetría sintética de laboratorio.

Produce un archivo JSON Lines con:
  - Actividad "normal" de fondo (ruido benigno).
  - Una cadena de ataque simulada (brute force -> ejecución -> persistencia ->
    descubrimiento -> movimiento lateral -> C2 -> exfiltración) para demostrar
    la detección, correlación y PREDICCIÓN de la fase siguiente.

100% sintético. No contiene exploits ni payloads reales; los "comandos" son
cadenas de texto ilustrativas para disparar reglas de detección.
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(7)

BENIGN_PROCESSES = ["explorer.exe", "chrome.exe", "code.exe", "python.exe", "svchost.exe"]
USERS = ["ana", "carlos", "sofia", "jdoe"]
HOSTS = ["WKS-01", "WKS-02", "SRV-APP"]


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def generate(path: str | Path = "sample_logs.jsonl", num_benign: int = 120) -> Path:
    path = Path(path)
    base = datetime(2025, 3, 10, 8, 0, 0, tzinfo=timezone.utc)
    records: list[dict] = []

    # --- Ruido benigno ---
    for i in range(num_benign):
        t = base + timedelta(minutes=random.randint(0, 600))
        host = random.choice(HOSTS)
        user = random.choice(USERS)
        records.append({
            "source": "sysmon",
            "timestamp": _iso(t),
            "action": "process_create",
            "host": host,
            "user": user,
            "process_name": random.choice(BENIGN_PROCESSES),
            "command_line": f"{random.choice(BENIGN_PROCESSES)} --normal-flag {random.randint(1,99)}",
            "outcome": "success",
        })

    # --- Cadena de ataque contra un host objetivo ---
    target = "SRV-APP"
    attacker_ip = "203.0.113.66"   # rango de documentación (TEST-NET-3), no enrutable
    t0 = base + timedelta(hours=2)

    # 1) Brute force (credential-access, T1110): múltiples fallos de login
    for i in range(8):
        records.append({
            "source": "auth",
            "timestamp": _iso(t0 + timedelta(seconds=i * 20)),
            "action": "user_login",
            "host": target,
            "user": "admin",
            "src_ip": attacker_ip,
            "outcome": "failure",
        })
    # login exitoso final
    records.append({
        "source": "auth",
        "timestamp": _iso(t0 + timedelta(minutes=3)),
        "action": "user_login",
        "host": target,
        "user": "admin",
        "src_ip": attacker_ip,
        "outcome": "success",
    })

    # 2) Ejecución (T1059): interprete de scripts codificado
    records.append({
        "source": "sysmon",
        "timestamp": _iso(t0 + timedelta(minutes=5)),
        "action": "process_create",
        "host": target,
        "user": "admin",
        "process_name": "powershell.exe",
        "parent_process": "cmd.exe",
        "command_line": "powershell.exe -nop -w hidden -enc SQBFAFgAKAAuAC4A",
        "outcome": "success",
    })

    # 3) Persistencia (T1053): tarea programada
    records.append({
        "source": "sysmon",
        "timestamp": _iso(t0 + timedelta(minutes=8)),
        "action": "process_create",
        "host": target,
        "user": "admin",
        "process_name": "schtasks.exe",
        "command_line": "schtasks /create /sc minute /tn Updater /tr backdoor.ps1",
        "outcome": "success",
    })

    # 4) Descubrimiento (T1046): escaneo de servicios de red
    records.append({
        "source": "sysmon",
        "timestamp": _iso(t0 + timedelta(minutes=11)),
        "action": "process_create",
        "host": target,
        "user": "admin",
        "process_name": "nmap.exe",
        "command_line": "nmap -sS -p- 10.0.0.0/24",
        "outcome": "success",
    })

    # 5) Movimiento lateral (T1021): conexión RDP a otro host
    records.append({
        "source": "firewall",
        "timestamp": _iso(t0 + timedelta(minutes=15)),
        "action": "connection",
        "host": target,
        "src_ip": "10.0.0.50",
        "dst_ip": "10.0.0.60",
        "dst_port": 3389,
        "protocol": "tcp",
        "outcome": "allow",
    })

    # 6) C2 (T1071): baliza saliente periódica a puerto raro
    for i in range(3):
        records.append({
            "source": "firewall",
            "timestamp": _iso(t0 + timedelta(minutes=18 + i * 2)),
            "action": "connection",
            "host": target,
            "src_ip": "10.0.0.50",
            "dst_ip": attacker_ip,
            "dst_port": 4444,
            "protocol": "tcp",
            "bytes_out": 2048,
            "outcome": "allow",
        })

    # 7) Exfiltración (T1048): gran volumen saliente
    records.append({
        "source": "firewall",
        "timestamp": _iso(t0 + timedelta(minutes=25)),
        "action": "connection",
        "host": target,
        "src_ip": "10.0.0.50",
        "dst_ip": attacker_ip,
        "dst_port": 4444,
        "protocol": "tcp",
        "bytes_out": 524288000,   # ~500 MB
        "outcome": "allow",
    })

    records.sort(key=lambda r: r["timestamp"])
    with open(path, "w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    return path


if __name__ == "__main__":
    out = generate(Path(__file__).parent / "sample_logs.jsonl")
    print(f"Generado: {out}")
