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

from .config import ROOT, Settings, DEFAULT_POLICY_PATH, DEFAULT_RULES_DIR
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
    if args.model:
        settings.prediction.model_path = args.model
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


def cmd_train_prediction(args: argparse.Namespace) -> int:
    """
    Entrena el modelo de secuencia, lo evalúa contra la línea base y reporta.

    Todo el protocolo es reproducible con la semilla: mismo corpus, misma
    partición, mismos números.
    """
    sys.path.insert(0, str(ROOT / "data"))
    import generate_campaigns  # noqa: PLC0415

    from .correlation import evaluation
    from .correlation.sequence_model import CanonicalBaseline, MarkovChainModel

    console.print(Panel.fit(
        "[bold cyan]CyberSentinel[/bold cyan] — Predicción de kill-chain\n"
        "[dim]Entrenamiento de la cadena de Markov y comparación con la heurística[/dim]",
        box=box.ROUNDED,
    ))

    sequences, labels = generate_campaigns.generate_sequences(n=args.campaigns, seed=args.seed)
    train_s, _, test_s, test_l = generate_campaigns.train_test_split(
        sequences, labels, test_ratio=args.test_ratio, seed=args.seed
    )
    examples = evaluation.build_examples(test_s, test_l)

    console.print(
        f"\n[bold]Corpus:[/bold] {len(sequences)} campañas sintéticas etiquetadas "
        f"(semilla {args.seed})   "
        f"[bold]Entrenamiento:[/bold] {len(train_s)}   "
        f"[bold]Evaluación:[/bold] {len(test_s)} campañas / {len(examples)} prefijos\n"
    )
    console.print(
        "[yellow]Aviso metodológico:[/yellow] [dim]las campañas las genera "
        "data/generate_campaigns.py. El modelo aprende esa distribución, no el "
        "comportamiento de atacantes reales. La comparación con la línea base sí es "
        "justa: ninguno de los dos modelos conoce el generador.[/dim]\n"
    )

    markov = MarkovChainModel(alpha=args.alpha, condition_on=args.condition_on).fit(train_s)
    models = {
        "Heurística canónica (línea base)": CanonicalBaseline(condition_on=args.condition_on),
        f"Cadena de Markov ({args.condition_on})": markov,
    }
    results = evaluation.compare(models, examples, ks=(1, 3))

    table = Table(title="Predicción de la fase siguiente", box=box.SIMPLE_HEAVY)
    table.add_column("Modelo")
    table.add_column("precisión@1", justify="right")
    table.add_column("precisión@3", justify="right")
    table.add_column("F1 macro", justify="right")
    table.add_column("F1 ponderado", justify="right")
    table.add_column("Cobertura", justify="right")
    for name, result in results.items():
        table.add_row(
            name,
            f"{result.precision_at[1]:.3f}", f"{result.precision_at[3]:.3f}",
            f"{result.macro_f1:.3f}", f"{result.weighted_f1:.3f}",
            f"{result.coverage:.3f}",
        )
    console.print(table)

    baseline, trained = results.values()
    delta = trained.precision_at[1] - baseline.precision_at[1]
    style = "green" if delta > 0 else "red"
    console.print(
        f"[{style}]La cadena de Markov cambia la precisión@1 en "
        f"{delta:+.3f} ({delta * 100:+.1f} puntos) frente a la heurística.[/{style}]\n"
    )

    console.print("[bold]Matriz de confusión (cadena de Markov)[/bold]")
    console.print(f"[dim]{evaluation.format_confusion(trained)}[/dim]\n")

    console.print("[bold]F1 por táctica (cadena de Markov)[/bold]")
    f1_table = Table(box=box.SIMPLE)
    f1_table.add_column("Táctica")
    f1_table.add_column("F1", justify="right")
    for tactic, score in sorted(trained.per_class_f1.items(), key=lambda kv: -kv[1]):
        f1_table.add_row(mitre.TACTIC_LABELS_ES.get(tactic, tactic), f"{score:.3f}")
    console.print(f1_table)

    if args.save_model:
        path = Path(args.save_model)
        path.parent.mkdir(parents=True, exist_ok=True)
        markov.save(path)
        console.print(f"\n[green]Modelo guardado en:[/green] {path}")
        console.print(
            "[dim]Actívalo en config.yaml con  prediction.model_path: "
            f"{args.save_model}[/dim]"
        )

    if args.json:
        report = {
            "corpus": {
                "n_campaigns": len(sequences), "n_train": len(train_s),
                "n_test": len(test_s), "n_examples": len(examples),
                "seed": args.seed, "source": "data/generate_campaigns.py (sintetico)",
            },
            "results": {name: r.to_dict() for name, r in results.items()},
            "transition_matrix": markov.to_dict(),
        }
        Path(args.json).write_text(
            json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        console.print(f"[green]Reporte JSON guardado en:[/green] {args.json}")
    return 0


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
    p_an.add_argument("--model", help="Modelo de predicción entrenado (JSON). "
                                      "Sin él se usa la heurística canónica.")
    p_an.add_argument("--use-llm", action="store_true",
                      help="Enriquecer narrativas con Claude (requiere ANTHROPIC_API_KEY).")
    p_an.set_defaults(func=cmd_analyze)

    p_tp = sub.add_parser(
        "train-prediction",
        help="Entrena y evalúa el modelo de predicción de kill-chain.",
    )
    p_tp.add_argument("--campaigns", type=int, default=400,
                      help="Número de campañas sintéticas a generar (por defecto 400).")
    p_tp.add_argument("--seed", type=int, default=7, help="Semilla de reproducibilidad.")
    p_tp.add_argument("--test-ratio", type=float, default=0.3,
                      help="Proporción de campañas reservadas para evaluar.")
    p_tp.add_argument("--alpha", type=float, default=0.5,
                      help="Suavizado de Laplace de la matriz de transición.")
    p_tp.add_argument("--condition-on", choices=("deepest", "last"), default="deepest",
                      help="Condicionar en la fase más profunda o en la última vista.")
    p_tp.add_argument("--save-model", help="Ruta donde guardar el modelo entrenado (JSON).")
    p_tp.add_argument("--json", help="Ruta para volcar el reporte de métricas en JSON.")
    p_tp.set_defaults(func=cmd_train_prediction)

    p_va = sub.add_parser("verify-audit", help="Verifica la integridad del log de auditoría.")
    p_va.add_argument("--audit", default="audit_log.jsonl")
    p_va.set_defaults(func=cmd_verify_audit)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
