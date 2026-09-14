"""
Generador de flujos de red sintéticos EN FORMATO UNSW-NB15.

Sirve para ejecutar y validar toda la maquinaria de evaluación (cargador →
detector → métricas → curvas) sin esperar a descargar los datasets reales, que
pesan entre cientos de megas y varios gigas.

LO QUE ESTO NO ES
-----------------
**Las métricas obtenidas con este archivo no valen para la memoria.** Miden que
la tubería funciona, no la eficacia del detector: las distribuciones las escribí
yo. Los números que se reportan en una tesis salen de UNSW-NB15 o CICIDS2017
reales — ver `docs/DATASETS.md`.

Por eso los ataques sintéticos se solapan deliberadamente con el tráfico benigno:
un generador que hiciera los ataques trivialmente separables produciría un AUC
cercano a 1.0 y daría una falsa sensación de que el detector funciona.

El formato de salida imita los CSV crudos `UNSW-NB15_1.csv`…`_4.csv`: 49 columnas
y **sin fila de cabecera**, que es como se publican.
"""
from __future__ import annotations

import csv
import random
from dataclasses import dataclass
from pathlib import Path

from datetime import datetime, timezone

# Mismo orden de columnas que usa el cargador para los CSV crudos.
COLUMNS = [
    "srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes",
    "dbytes", "sttl", "dttl", "sloss", "dloss", "service", "sload", "dload",
    "spkts", "dpkts", "swin", "dwin", "stcpb", "dtcpb", "smeansz", "dmeansz",
    "trans_depth", "res_bdy_len", "sjit", "djit", "stime", "ltime", "sintpkt",
    "dintpkt", "tcprtt", "synack", "ackdat", "is_sm_ips_ports", "ct_state_ttl",
    "ct_flw_http_mthd", "is_ftp_login", "ct_ftp_cmd", "ct_srv_src", "ct_srv_dst",
    "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm",
    "ct_dst_src_ltm", "attack_cat", "label",
]

BASE_TIME = int(datetime(2025, 3, 10, 0, 0, tzinfo=timezone.utc).timestamp())

INTERNAL = [f"10.0.0.{i}" for i in range(10, 60)]
EXTERNAL = [f"203.0.113.{i}" for i in range(1, 40)]


@dataclass
class Flow:
    """Un flujo de red con lo mínimo que necesita el detector."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str
    service: str
    state: str
    duration: float
    bytes_out: int
    bytes_in: int
    packets_out: int
    packets_in: int
    stime: int
    category: str
    label: int

    def to_row(self) -> list:
        """Rellena las 49 columnas; las que el detector no usa van a valores planos."""
        return [
            self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.proto,
            self.state, f"{self.duration:.6f}", self.bytes_out, self.bytes_in,
            31, 29, 0, 0, self.service,
            f"{self.bytes_out / max(self.duration, 0.001):.2f}",
            f"{self.bytes_in / max(self.duration, 0.001):.2f}",
            self.packets_out, self.packets_in, 255, 255, 0, 0,
            self.bytes_out // max(self.packets_out, 1),
            self.bytes_in // max(self.packets_in, 1),
            0, 0, 0, 0, self.stime, self.stime + max(int(self.duration), 1),
            0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1,
            self.category if self.label else "",
            self.label,
        ]


def _business_hour(rng: random.Random) -> int:
    """Hora de oficina con cola nocturna: el tráfico real no es uniforme."""
    if rng.random() < 0.85:
        return rng.randint(8, 19)
    return rng.choice([0, 1, 2, 3, 4, 5, 6, 7, 20, 21, 22, 23])


def _moment(rng: random.Random, hour: int | None = None) -> int:
    hour = _business_hour(rng) if hour is None else hour
    return BASE_TIME + hour * 3600 + rng.randint(0, 3599)


def _benign(rng: random.Random) -> Flow:
    """Tráfico normal: web, DNS y ficheros internos."""
    kind = rng.choices(["web", "dns", "smb"], weights=[0.6, 0.25, 0.15], k=1)[0]
    src = rng.choice(INTERNAL)
    if kind == "web":
        out = int(rng.lognormvariate(6.2, 1.1))
        return Flow(src, rng.choice(EXTERNAL), rng.randint(49152, 65535),
                    rng.choice([443, 443, 443, 80]), "tcp", "http", "FIN",
                    rng.uniform(0.05, 12.0), out, int(out * rng.uniform(3, 40)),
                    rng.randint(4, 40), rng.randint(4, 60), _moment(rng), "Normal", 0)
    if kind == "dns":
        return Flow(src, "10.0.0.2", rng.randint(49152, 65535), 53, "udp", "dns", "CON",
                    rng.uniform(0.001, 0.05), rng.randint(60, 180), rng.randint(80, 400),
                    rng.randint(1, 3), rng.randint(1, 3), _moment(rng), "Normal", 0)
    out = int(rng.lognormvariate(7.5, 1.4))
    return Flow(src, rng.choice(INTERNAL), rng.randint(49152, 65535), 445, "tcp", "-", "FIN",
                rng.uniform(0.1, 30.0), out, int(out * rng.uniform(0.2, 3)),
                rng.randint(5, 80), rng.randint(5, 80), _moment(rng), "Normal", 0)


def _reconnaissance(rng: random.Random) -> Flow:
    """Escaneo: muchos flujos diminutos a puertos variados, sin respuesta."""
    return Flow(rng.choice(EXTERNAL), rng.choice(INTERNAL), rng.randint(1024, 65535),
                rng.choice([21, 22, 23, 25, 135, 139, 445, 1433, 3306, 3389, 8080, 8443]),
                "tcp", "-", "INT", rng.uniform(0.0, 0.01),
                rng.randint(40, 200), 0, rng.randint(1, 2), 0,
                _moment(rng), "Reconnaissance", 1)


def _exploits(rng: random.Random) -> Flow:
    """
    Explotación de un servicio expuesto.

    Se parece mucho a una petición web normal: es el caso difícil a propósito.
    """
    out = int(rng.lognormvariate(6.6, 0.9))
    return Flow(rng.choice(EXTERNAL), rng.choice(INTERNAL), rng.randint(1024, 65535),
                rng.choice([80, 443, 445]), "tcp", "http", "FIN",
                rng.uniform(0.1, 3.0), out, int(out * rng.uniform(0.3, 6)),
                rng.randint(6, 30), rng.randint(4, 25), _moment(rng), "Exploits", 1)


def _dos(rng: random.Random) -> Flow:
    """Denegación de servicio: ráfagas cortas y repetitivas contra un destino."""
    return Flow(rng.choice(EXTERNAL), "10.0.0.11", rng.randint(1024, 65535), 80,
                "tcp", "http", "INT", rng.uniform(0.0, 0.2),
                rng.randint(100, 600), rng.randint(0, 80),
                rng.randint(1, 6), rng.randint(0, 3), _moment(rng), "DoS", 1)


def _backdoor(rng: random.Random) -> Flow:
    """Canal de mando: puerto alto poco común, tráfico pequeño y periódico."""
    return Flow(rng.choice(INTERNAL), rng.choice(EXTERNAL), rng.randint(49152, 65535),
                rng.choice([4444, 1337, 31337, 8081]), "tcp", "-", "CON",
                rng.uniform(1.0, 60.0), rng.randint(200, 3000), rng.randint(100, 900),
                rng.randint(3, 20), rng.randint(3, 20),
                _moment(rng, hour=rng.choice([1, 2, 3, 4, 23])), "Backdoor", 1)


def _exfiltration(rng: random.Random) -> Flow:
    """Fuga de datos: mucho saliente, poco entrante, fuera de horario."""
    out = int(rng.lognormvariate(14.5, 1.0))
    return Flow(rng.choice(INTERNAL), rng.choice(EXTERNAL), rng.randint(49152, 65535),
                rng.choice([443, 21, 22, 8443]), "tcp", "-", "FIN",
                rng.uniform(30.0, 600.0), out, rng.randint(500, 5000),
                rng.randint(200, 4000), rng.randint(20, 200),
                _moment(rng, hour=rng.choice([0, 1, 2, 3, 4, 22, 23])), "Exfiltration", 1)


ATTACKS = [
    (_reconnaissance, 0.30),
    (_exploits, 0.28),
    (_dos, 0.20),
    (_backdoor, 0.14),
    (_exfiltration, 0.08),
]


def generate(
    path: str | Path | None = None,
    n_benign: int = 4500,
    n_attacks: int = 500,
    seed: int = 7,
) -> Path:
    """
    Escribe el CSV sintético. La proporción por defecto (10% de ataques) ya es
    optimista: en tráfico real el desbalance es mucho mayor.
    """
    path = Path(path or Path(__file__).parent / "synthetic_flows_unsw_format.csv")
    rng = random.Random(seed)

    flows = [_benign(rng) for _ in range(n_benign)]
    generators, weights = zip(*ATTACKS)
    for _ in range(n_attacks):
        flows.append(rng.choices(generators, weights=weights, k=1)[0](rng))

    flows.sort(key=lambda f: f.stime)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        csv.writer(fh).writerows(flow.to_row() for flow in flows)
    return path


if __name__ == "__main__":
    salida = generate()
    print(f"Generado: {salida}")
    print("AVISO: datos sinteticos. Sirven para validar la tuberia de evaluacion,")
    print("       no para reportar metricas en la memoria. Ver docs/DATASETS.md.")
