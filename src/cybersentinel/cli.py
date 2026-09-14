"""
Interfaz de línea de comandos de CyberSentinel.

Uso:
    python -m cybersentinel.cli analyze --input data/sample_logs.jsonl
    python -m cybersentinel.cli analyze --input logs.jsonl --json report.json
    python -m cybersentinel.cli verify-audit --audit audit_log.jsonl
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from .config import Settings, DEFAULT_POLICY_PATH, DEFAULT_RULES_DIR
from .correlation import mitre
from .pipeline import Pipeline, PipelineReport
from .governance import GovernancePolicy, AuditLog

console = Console()

DEFAULT_RULES = DEFAULT_RULES_DIR
DEFAULT_POLICY = DEFAULT_POLICY_PATH

DECISION_STYLE = {
    "allowed": "green",
    "requires_approval": "yellow",
    "prohibited": "red",
}
SEVERITY_STYLE = {
    "critical": "bold red", "high": "red", "medium": "yellow",
    "low": "cyan", "info": "dim",
}


def _load_policy() -> GovernancePolicy:
    if DEFAULT_POLICY.exists():
        return GovernancePolicy.from_yaml(DEFAULT_POLICY)
    return GovernancePolicy()


def cmd_analyze(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    if not input_path.exists():
        console.print(f"[red]No existe el archivo de entrada: {input_path}[/red]")
        return 1

    console.print(Panel.fit(
        "[bold cyan]CyberSentinel[/bold cyan] — Agente defensivo de ciberseguridad\n"
        "[dim]Análisis · Predicción de kill-chain · Explicabilidad · Gobernanza ética[/dim]",
        box=box.ROUNDED,
    ))

    settings = Settings.load(args.config)
    pipeline = Pipeline(
        rules_dir=DEFAULT_RULES,
        policy=_load_policy(),
        audit_path=args.audit,
        # --use-llm solo fuerza el modo si se pide; si no, manda la configuracion.
        use_llm=True if args.use_llm else None,
        settings=settings,
    )
    report = pipeline.run_file(input_path)
    _render_report(report)

    if args.json:
        Path(args.json).write_text(
            json.dumps(report.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8"
        )
        console.print(f"\n[green]Reporte JSON guardado en:[/green] {args.json}")
    return 0


def _render_report(report: PipelineReport) -> None:
    console.print(
        f"\n[bold]Eventos procesados:[/bold] {report.total_events}   "
        f"[bold]Hallazgos:[/bold] {report.total_findings}   "
        f"[bold]Incidentes:[/bold] {len(report.results)}   "
        f"[bold]Integridad auditoría:[/bold] "
        f"{'[green]OK[/green]' if report.audit_integrity else '[red]COMPROMETIDA[/red]'}"
    )
    if report.anomaly_threshold_used is not None:
        console.print(
            f"[dim]Umbral de anomalía aplicado: {report.anomaly_threshold_used:.3f} "
            f"(percentil 99 de la línea base)[/dim]"
        )
    console.print()

    if not report.results:
        console.print("[dim]No se detectaron incidentes.[/dim]")
        return

    for res in report.results:
        inc = res.incident
        sev_style = SEVERITY_STYLE.get(inc.max_severity.value, "white")
        header = (
            f"[bold]{inc.incident_id}[/bold]  ·  entidad [cyan]{inc.entity}[/cyan]  ·  "
            f"riesgo [bold]{inc.risk_score}/100[/bold]  ·  "
            f"severidad [{sev_style}]{inc.max_severity.value.upper()}[/{sev_style}]"
        )
        console.print(Panel(header, box=box.HEAVY, border_style=sev_style))

        # Narrativa explicable
        nar = res.narrative
        console.print(f"[bold]Resumen:[/bold] {nar.summary}")
        console.print(f"[bold]Razonamiento:[/bold] {nar.reasoning}")
        console.print(f"[bold]Predicción:[/bold] {nar.prediction_text}")
        console.print(f"[bold]Confianza global:[/bold] {nar.confidence:.0%}")

        # Técnicas ATT&CK
        if inc.techniques:
            techs = ", ".join(
                f"{t} ({mitre.technique_name(t)})" for t in inc.techniques
            )
            console.print(f"[bold]MITRE ATT&CK:[/bold] {techs}")

        # Evidencia
        console.print("[bold]Evidencia:[/bold]")
        for e in nar.evidence:
            console.print(f"   [dim]{e}[/dim]")

        # Recomendaciones con veredicto de gobernanza
        table = Table(title="Contramedidas recomendadas (gobernanza ética)", box=box.SIMPLE)
        table.add_column("Prio", justify="center")
        table.add_column("Acción")
        table.add_column("Objetivo")
        table.add_column("Decisión")
        for rec in res.recommendations:
            d = rec.verdict.decision.value
            style = DECISION_STYLE.get(d, "white")
            table.add_row(
                str(rec.priority),
                rec.verdict.action.action_type,
                rec.verdict.action.target,
                f"[{style}]{d}[/{style}]",
            )
        console.print(table)
        console.print()


def cmd_verify_audit(args: argparse.Namespace) -> int:
    path = Path(args.audit)
    if not path.exists():
        console.print(f"[red]No existe el log de auditoría: {path}[/red]")
        return 1
    log = AuditLog(path)
    ok, bad_index, detail = log.verify_detailed()
    modo = "firmada con clave (HMAC-SHA256)" if log.is_signed else "sin clave (SHA-256)"
    console.print(f"[dim]Modo: {modo} · {len(log.entries)} entradas[/dim]")
    if ok:
        console.print(f"[green]Cadena de auditoría íntegra.[/green] {detail}")
        return 0
    console.print(f"[red]Integridad COMPROMETIDA (entrada #{bad_index}).[/red] {detail}")
    return 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cybersentinel",
        description="Agente defensivo de ciberseguridad (blue team).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_an = sub.add_parser("analyze", help="Analiza un archivo de telemetría JSONL.")
    p_an.add_argument("--input", "-i", required=True, help="Ruta al archivo JSONL de logs.")
    p_an.add_argument("--audit", default="audit_log.jsonl", help="Ruta del log de auditoría.")
    p_an.add_argument("--json", help="Ruta para volcar el reporte en JSON.")
    p_an.add_argument("--config", help="Ruta a config.yaml (por defecto config/config.yaml).")
    p_an.add_argument("--use-llm", action="store_true",
                      help="Enriquecer narrativas con Claude (requiere ANTHROPIC_API_KEY).")
    p_an.set_defaults(func=cmd_analyze)

    p_va = sub.add_parser("verify-audit", help="Verifica la integridad del log de auditoría.")
    p_va.add_argument("--audit", default="audit_log.jsonl")
    p_va.set_defaults(func=cmd_verify_audit)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
