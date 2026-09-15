"""
Benchmark Empresarial (Fase 7 / Fase 8).

Ejecuta un Ablation Study automatizado sobre el pipeline y exporta
métricas de rendimiento y latencias fraccionadas.

DT-04 FIX (Fase 8): Dataset reproducible mediante:
  - --seed:   controla los timestamps base (derivados del seed, no datetime.now()).
  - run_id:   UUID único por ejecución (varía entre runs, identifica la sesión).
  - dataset_hash: SHA-256 del contenido del dataset generado (debe ser idéntico
                  si se usa el mismo seed y n_events, en distintas máquinas/horas).

Uso:
    python scripts/benchmark_runner.py --seed 42 --events 100
    python scripts/benchmark_runner.py --seed 99 --events 100   # dataset distinto
"""
import sys
import os
import uuid
import hashlib
import argparse
import json
from datetime import datetime, timezone, timedelta
from importlib.metadata import version as pkg_version, PackageNotFoundError

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cybersentinel.schema import SecurityEvent
from cybersentinel.pipeline import Pipeline


BASELINE_EPOCH = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


#: Eventos de ataque que las reglas de config/rules SI pueden detectar.
#: El generador anterior emitia eventos con category="net" y dst_ip="malicious.com",
#: que ninguna regla podia casar: la columna "Detecciones" del benchmark salia a
#: cero por construccion, en todas las configuraciones, y no medía nada.
ATTACK_TEMPLATES = [
    dict(source="sysmon", category="process", action="process_create",
         command_line="powershell.exe -nop -w hidden -enc SQBFAFgAKAAuAC4A",
         process_name="powershell.exe", label="T1059"),
    dict(source="sysmon", category="process", action="process_create",
         command_line="schtasks /create /sc minute /tn Updater /tr backdoor.ps1",
         process_name="schtasks.exe", label="T1053"),
    dict(source="sysmon", category="process", action="process_create",
         command_line="nmap -sS -p- 10.0.0.0/24", process_name="nmap.exe", label="T1046"),
    dict(source="firewall", category="network", action="connection",
         src_ip="10.0.0.50", dst_ip="10.0.0.60", dst_port=3389, label="T1021"),
    dict(source="firewall", category="network", action="connection",
         src_ip="10.0.0.50", dst_ip="203.0.113.66", dst_port=4444, label="T1071"),
    dict(source="firewall", category="network", action="connection",
         src_ip="10.0.0.50", dst_ip="203.0.113.66", dst_port=4444,
         bytes_out=524288000, label="T1048"),
]


def generate_synthetic_dataset(n: int, seed: int) -> list[SecurityEvent]:
    """
    Genera una mezcla determinista de eventos benignos y de ataque.

    Los eventos de ataque se construyen a partir de plantillas que las reglas
    vigentes pueden detectar. Sin esa correspondencia el estudio de ablacion no
    es evaluable: no habria ninguna deteccion que atribuir a un componente u
    otro.

    DT-04: los timestamps se derivan deterministicamente de seed+indice, asi que
    el hash del dataset es estable entre maquinas y ejecuciones.
    """
    events = []
    base_offset_seconds = (seed * 1000) % (365 * 24 * 3600)
    base = BASELINE_EPOCH + timedelta(seconds=base_offset_seconds)

    for i in range(n):
        ts = base + timedelta(minutes=i)
        if i % 10 == 0:
            plantilla = dict(ATTACK_TEMPLATES[(i // 10) % len(ATTACK_TEMPLATES)])
            etiqueta = plantilla.pop("label")
            ev = SecurityEvent(f"e_{i:05d}", ts, host="SRV-APP", user="admin", **plantilla)
            ev.tags.extend(["malicious", etiqueta])
        elif i % 10 == 5:
            # Fallos de autenticacion consecutivos: alimentan la regla agregada
            # de fuerza bruta, que exige varios eventos en una ventana.
            ev = SecurityEvent(f"e_{i:05d}", ts, source="auth", category="authentication",
                               action="user_login", host="SRV-APP", user="admin",
                               src_ip="203.0.113.66", outcome="failure")
            ev.tags.extend(["malicious", "T1110"])
        else:
            ev = SecurityEvent(f"e_{i:05d}", ts, source="sysmon", category="process",
                               action="process_create", host="WKS-01", user="ana",
                               process_name="chrome.exe",
                               command_line=f"chrome.exe --tab {i}", outcome="success")
            ev.tags.append("benign")
        events.append(ev)
    return events


def compute_dataset_hash(events: list[SecurityEvent]) -> str:
    """
    Calcula un SHA-256 estable del contenido lógico del dataset.

    Usa event_id, timestamp ISO, source, category, action, src_ip, dst_ip y tags.
    Debe producir el mismo hash en distintas máquinas si se usa el mismo seed y n.
    """
    h = hashlib.sha256()
    for ev in events:
        record = "|".join([
            ev.event_id,
            ev.timestamp.isoformat(),
            ev.source,
            ev.category,
            ev.action,
            str(ev.src_ip),
            str(ev.dst_ip),
            ",".join(sorted(ev.tags)),
        ])
        h.update(record.encode("utf-8"))
    return h.hexdigest()


def _safe_pkg_version(name: str) -> str:
    try:
        return pkg_version(name)
    except PackageNotFoundError:
        return "unknown"


def print_markdown_table(results: dict):
    print("\n## Resultados del Benchmark Científico (Fase 8)\n")
    print("| Configuración | Detecciones | p95 Latencia Core (ms) | p95 Latencia Total (ms) |")
    print("| ------------- | ----------- | ---------------------- | ----------------------- |")

    for config_name, data in results.items():
        dets = data["total_findings"]
        core_ms = f"{data['p95_core']:.4f}" if data['p95_core'] else "N/A"
        tot_ms = f"{data['p95_total']:.4f}" if data['p95_total'] else "N/A"
        print(f"| {config_name:<13} | {dets:<11} | {core_ms:<22} | {tot_ms:<23} |")


def run_benchmark():
    parser = argparse.ArgumentParser(description="CyberSentinel Benchmark Phase 8")
    parser.add_argument("--events", type=int, default=100, help="Number of synthetic events to run")
    parser.add_argument("--seed", type=int, default=42,
                        help="Seed for deterministic dataset generation (default: 42)")
    parser.add_argument("--output-json", type=str, default=None,
                        help="Optional path to dump benchmark metadata+results as JSON")
    args = parser.parse_args()

    # --- Run metadata ---
    run_id = str(uuid.uuid4())
    execution_ts = datetime.now(timezone.utc).isoformat()

    print(f"\n╔════════════════════════════════════════════╗")
    print(f"║   CyberSentinel Benchmark Runner (Fase 8)  ║")
    print(f"╚════════════════════════════════════════════╝")
    print(f"  run_id:      {run_id}")
    print(f"  seed:        {args.seed}")
    print(f"  n_events:    {args.events}")
    print(f"  executed_at: {execution_ts}")
    print(f"  python:      {sys.version.split()[0]}")
    print()

    # --- Generate reproducible dataset ---
    print(f"Generando dataset ({args.events} eventos, seed={args.seed})...")
    dataset = generate_synthetic_dataset(n=args.events, seed=args.seed)
    dataset_hash = compute_dataset_hash(dataset)
    print(f"  dataset_hash (SHA-256): {dataset_hash}")
    print(f"  primer timestamp:  {dataset[0].timestamp.isoformat()}")
    print(f"  último timestamp:  {dataset[-1].timestamp.isoformat()}")
    print()

    configurations = {
        "A. Sigma Only":  {"enable_ml": False, "enable_temporal": False, "enable_cti": False, "enable_rag": False, "enable_llm": False},
        "B. + ML":        {"enable_ml": True,  "enable_temporal": False, "enable_cti": False, "enable_rag": False, "enable_llm": False},
        "C. + Temporal":  {"enable_ml": True,  "enable_temporal": True,  "enable_cti": False, "enable_rag": False, "enable_llm": False},
        "D. + CTI":       {"enable_ml": True,  "enable_temporal": True,  "enable_cti": True,  "enable_rag": False, "enable_llm": False},
        "E. Full System": {"enable_ml": True,  "enable_temporal": True,  "enable_cti": True,  "enable_rag": True,  "enable_llm": True},
    }

    benchmark_results = {}

    for name, flags in configurations.items():
        print(f"Ejecutando Ablation: {name}...")
        # Las reglas reales del proyecto. Antes apuntaba a tests/fixtures/, que
        # solo contiene CSV de datasets: se cargaban 0 reglas.
        pipeline = Pipeline(rules_dir=ROOT / "config" / "rules", **flags)
        report = pipeline.run_events(dataset)

        core_latencies = sorted([inc.trace.total_core_ms for inc in report.results])
        total_latencies = sorted([inc.trace.total_ms for inc in report.results])

        def p95(arr):
            if not arr:
                return 0.0
            idx = int(len(arr) * 0.95)
            return arr[min(idx, len(arr) - 1)]

        benchmark_results[name] = {
            "total_findings": report.total_findings,
            "p95_core": p95(core_latencies),
            "p95_total": p95(total_latencies),
        }

    print_markdown_table(benchmark_results)

    # --- Full metadata record ---
    metadata = {
        "run_id": run_id,
        "seed": args.seed,
        "n_events": args.events,
        "dataset_hash_sha256": dataset_hash,
        "executed_at_utc": execution_ts,
        "python_version": sys.version.split()[0],
        "cybersentinel_version": _safe_pkg_version("cybersentinel"),
        "scikit_learn_version": _safe_pkg_version("scikit-learn"),
        "configurations": list(configurations.keys()),
        "results": benchmark_results,
    }

    print(f"\n## Metadata de Reproducibilidad")
    print(f"  run_id:        {metadata['run_id']}")
    print(f"  seed:          {metadata['seed']}")
    print(f"  dataset_hash:  {metadata['dataset_hash_sha256']}")
    print(f"  cybersentinel: {metadata['cybersentinel_version']}")

    if args.output_json:
        from pathlib import Path
        Path(args.output_json).write_text(
            json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(f"\n[OK] Metadata JSON guardada en: {args.output_json}")

    return metadata


if __name__ == "__main__":
    run_benchmark()
