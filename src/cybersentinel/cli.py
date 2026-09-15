"""
Interfaz de línea de comandos de CyberSentinel.

Uso:
    python -m cybersentinel.cli analyze --input data/sample_logs.jsonl
    python -m cybersentinel.cli analyze --input logs.jsonl --json report.json
    python -m cybersentinel.cli train-prediction --save-model models/markov.json
    python -m cybersentinel.cli evaluate-detection --dataset unsw-nb15 -i flows.csv
    python -m cybersentinel.cli verify-audit --audit audit_log.jsonl
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from .config import ROOT, Settings, DEFAULT_POLICY_PATH, DEFAULT_RULES_DIR
from .correlation import mitre
from .detection import RulesEngine
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
        settings=settings,
        enable_llm=not args.no_llm,
        enable_rag=not args.no_rag,
        enable_cti=not args.no_cti,
    )
    report = pipeline.run_file(input_path)
    _render_report(report, mostrar_todo=args.all)

    if args.json:
        Path(args.json).write_text(
            json.dumps(report.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8"
        )
        console.print(f"\n[green]Reporte JSON guardado en:[/green] {args.json}")

    if args.navigator:
        from .correlation import navigator
        # Phase 7: IncidentResult has .evidence (DetectionEvidence) with .mitre_context
        # layer_from_incidents accepts Any iterable — pass evidence objects directly.
        capa = navigator.layer_from_incidents(
            [r.evidence for r in report.results],
            name="CyberSentinel — incidentes detectados",
        )
        ruta = navigator.save_layer(capa, args.navigator)
        console.print(
            f"[green]Capa de ATT&CK Navigator guardada en:[/green] {ruta}\n"
            "[dim]Ábrela en https://mitre-attack.github.io/attack-navigator/ "
            "→ Open Existing Layer → Upload from local.[/dim]"
        )

    if args.text:
        # Phase 7: narrative is a plain str per IncidentResult (no .to_text())
        narrativas = "\n\n".join(r.narrative for r in report.results)
        Path(args.text).write_text(
            narrativas or "No se detectaron incidentes.\n", encoding="utf-8"
        )
        console.print(f"[green]Narrativas en texto guardadas en:[/green] {args.text}")
    return 0


def _render_components(report: PipelineReport) -> None:
    """
    Qué componentes se ejecutaron de verdad.

    Es lo primero que hay que poder ver: un pipeline en el que RAG o CTI no
    tienen datos produce resultados válidos pero incompletos, y eso debe saberse
    antes de leer ninguna conclusión.
    """
    tabla = Table(title="Estado de los componentes", box=box.SIMPLE)
    tabla.add_column("Componente")
    tabla.add_column("Estado")
    for nombre, estado in report.component_status.items():
        if estado.startswith("OK"):
            color = "green"
        elif estado.startswith(("NO_DATA", "UNAVAILABLE")):
            color = "yellow"
        else:
            color = "dim"
        tabla.add_row(nombre, f"[{color}]{estado}[/{color}]")
    console.print(tabla)


def _render_report(report: PipelineReport, mostrar_todo: bool = False) -> None:
    console.print(f"\n[dim]run_id: {report.run_id}[/dim]")
    _render_components(report)

    console.print(
        f"\n[bold]Eventos procesados:[/bold] {report.total_events}   "
        f"[bold]Hallazgos:[/bold] {report.total_findings}   "
        f"[bold]Secuencias correladas:[/bold] {len(report.correlated_incidents)}"
    )

    if report.correlated_incidents:
        console.print("\n[bold]Cadenas de ataque detectadas por correlación temporal:[/bold]")
        for inc in report.correlated_incidents:
            console.print(
                f"   [cyan]{inc['incident_name']}[/cyan]: "
                f"{' → '.join(inc['matched_sequence'])} "
                f"[dim](confianza {inc['confidence']:.2f}, "
                f"{inc['start_time'][11:19]}–{inc['end_time'][11:19]})[/dim]"
            )
    if report.anomaly_threshold_used is not None:
        console.print(
            f"[dim]Umbral de anomalía aplicado: {report.anomaly_threshold_used:.3f} "
            f"(percentil 99 de la línea base)[/dim]"
        )
    console.print()

    mostrados = report.results if mostrar_todo else report.findings
    if not mostrados:
        console.print(
            "\n[dim]Ningún evento superó el umbral de alerta "
            f"({int(len(report.results))} analizados). Usa --all para ver todos.[/dim]"
        )
        return

    console.print(
        f"\n[bold]Mostrando {len(mostrados)} de {len(report.results)} eventos "
        f"{'(todos)' if mostrar_todo else '(solo hallazgos)'}[/bold]\n"
    )
    for res in mostrados:
        ev_id = res.evidence.event_id
        score = res.evidence.hybrid_score
        sigma_hits = len(res.evidence.rule_matches)
        cti_hits = len(res.evidence.cti_hits)
        anomaly = res.evidence.anomaly_score
        mitre_techs = res.evidence.mitre_context

        # Determine severity from hybrid_score for display
        if score >= 80:
            sev_label, sev_style = "CRITICAL", "bold red"
        elif score >= 60:
            sev_label, sev_style = "HIGH", "red"
        elif score >= 50:
            sev_label, sev_style = "MEDIUM", "yellow"
        else:
            sev_label, sev_style = "LOW", "cyan"

        header = (
            f"[bold]{ev_id}[/bold]  ·  "
            f"score [{sev_style}]{score:.1f}/100[/{sev_style}]  ·  "
            f"severidad [{sev_style}]{sev_label}[/{sev_style}]"
        )
        console.print(Panel(header, box=box.HEAVY, border_style=sev_style))

        # Signals breakdown
        console.print(f"  [bold]Sigma hits:[/bold] {sigma_hits}  |  "
                      f"[bold]CTI hits:[/bold] {cti_hits}  |  "
                      f"[bold]Anomaly score:[/bold] {anomaly:.3f}")

        # MITRE techniques from evidence
        if mitre_techs:
            techs = ", ".join(
                f"{t} ({mitre.technique_name(t)})" for t in mitre_techs
            )
            console.print(f"  [bold]MITRE ATT&CK:[/bold] {techs}")

        evid = res.evidence
        console.print(f"  [bold]event_ref:[/bold] [dim]{evid.event_ref}[/dim]  |  "
                      f"[bold]entidad:[/bold] {evid.entity}  |  "
                      f"[bold]estado:[/bold] {evid.detection_status}")

        if evid.temporal_context:
            for secuencia in evid.temporal_context:
                console.print(f"  [bold]Correlación:[/bold] {secuencia}")

        if evid.cti_hits:
            for hit in evid.cti_hits:
                actores = ", ".join(a.name for a in hit.related_actors) or "sin actor asociado"
                console.print(
                    f"  [bold]CTI:[/bold] {hit.observable_value} "
                    f"[dim]({', '.join(hit.indicator.labels)} · {actores})[/dim]"
                )
        else:
            console.print("  [bold]CTI:[/bold] [dim]CTI_MATCH=NONE[/dim]")

        if evid.rag_context:
            fuentes = ", ".join(sorted({c.filename or c.source_uri for c in evid.rag_context}))
            console.print(f"  [bold]Contexto RAG:[/bold] [dim]{fuentes}[/dim]")
        else:
            console.print("  [bold]Contexto RAG:[/bold] [dim]sin contexto recuperado[/dim]")

        estado_llm = evid.llm_status
        color_llm = "green" if estado_llm == "OK" else "yellow"
        console.print(
            f"  [bold]LLM:[/bold] [{color_llm}]{estado_llm}[/{color_llm}]"
            f"{'  [yellow](respaldo determinista)[/yellow]' if evid.fallback_used else ''}"
        )
        if res.narrative:
            console.print(f"  [bold]Explicación:[/bold] {res.narrative}")

        if res.recommendations:
            acciones = ", ".join(
                f"{r.verdict.action.action_type}[{r.verdict.decision.value}]"
                for r in res.recommendations[:5]
            )
            console.print(f"  [bold]Contramedidas:[/bold] [dim]{acciones}[/dim]")
        console.print()

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


def cmd_attack_sync(args: argparse.Namespace) -> int:
    """Genera la caché de ATT&CK a partir del STIX oficial de MITRE."""
    from .correlation import mitre, navigator
    from .correlation.attack_data import DEFAULT_CACHE_PATH, DEFAULT_STIX_PATH, build_from_stix

    stix = Path(args.stix) if args.stix else DEFAULT_STIX_PATH
    if not stix.exists():
        console.print(f"[red]No existe el STIX de ATT&CK en:[/red] {stix}\n")
        console.print("Descárgalo con:")
        console.print(
            "  [dim]curl -sSL -o data/attack/enterprise-attack.json \\\n"
            "    https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
            "master/enterprise-attack/enterprise-attack.json[/dim]"
        )
        return 1

    console.print(Panel.fit(
        "[bold cyan]CyberSentinel[/bold cyan] — Sincronización de MITRE ATT&CK\n"
        f"[dim]{stix} ({stix.stat().st_size / 1024 / 1024:.0f} MB)[/dim]",
        box=box.ROUNDED,
    ))
    with console.status("[dim]Interpretando el STIX oficial…[/dim]"):
        data = build_from_stix(stix)

    destino = Path(args.output) if args.output else DEFAULT_CACHE_PATH
    data.save(destino)
    mitre.reload(destino)

    console.print(
        f"\n[green]Matriz ATT&CK v{data.version}[/green]: {data.n_techniques} técnicas, "
        f"{data.n_subtechniques} subtécnicas, {len(data.tactic_order)} tácticas."
    )
    console.print(
        f"[green]Caché escrita en:[/green] {destino} "
        f"({destino.stat().st_size / 1024:.0f} KB)"
    )
    console.print(
        "[dim]La caché se versiona con el proyecto: a partir de ahora el sistema usa "
        "la matriz oficial sin necesitar el STIX ni mitreattack-python.[/dim]"
    )

    tabla = Table(title="Orden oficial de tácticas", box=box.SIMPLE)
    tabla.add_column("#", justify="right")
    tabla.add_column("Táctica")
    tabla.add_column("Nombre")
    for indice, tactic in enumerate(data.tactic_order, start=1):
        tabla.add_row(str(indice), tactic, mitre.tactic_label(tactic))
    console.print(tabla)

    if args.coverage:
        _render_coverage(navigator.coverage_summary(
            RulesEngine.from_directory(DEFAULT_RULES).rules
        ))
    return 0


def _render_coverage(resumen: dict) -> None:
    """Cobertura de la matriz por las reglas propias."""
    console.print(
        f"\n[bold]Cobertura de detección:[/bold] {resumen['tecnicas_cubiertas']} de "
        f"{resumen['tecnicas_totales']} técnicas ([bold]{resumen['cobertura']:.1%}[/bold])"
    )
    tabla = Table(box=box.SIMPLE)
    tabla.add_column("Táctica")
    tabla.add_column("Cubiertas", justify="right")
    tabla.add_column("Totales", justify="right")
    for fila in resumen["por_tactica"]:
        estilo = "green" if fila["cubiertas"] else "dim"
        tabla.add_row(
            f"[{estilo}]{fila['tactica_es']}[/{estilo}]",
            f"[{estilo}]{fila['cubiertas']}[/{estilo}]", str(fila["totales"]),
        )
    console.print(tabla)
    console.print(
        "[dim]Una cobertura baja no es un defecto que esconder: es la medida honesta "
        "del alcance de un prototipo de laboratorio, y señala el trabajo pendiente.[/dim]"
    )


def cmd_evaluate_detection(args: argparse.Namespace) -> int:
    """Mide el detector de anomalías contra las etiquetas de un dataset real."""
    from .detection.evaluation import evaluate_anomaly_detector, save_curves
    from .ingestion.datasets import LOADERS

    rutas = [Path(p) for p in args.input]
    faltan = [p for p in rutas if not p.exists()]
    if faltan:
        console.print(f"[red]No existen estos archivos:[/red] {', '.join(map(str, faltan))}")
        return 1

    console.print(Panel.fit(
        "[bold cyan]CyberSentinel[/bold cyan] — Evaluación del detector\n"
        f"[dim]Dataset: {args.dataset} · {len(rutas)} archivo(s)[/dim]",
        box=box.ROUNDED,
    ))

    # Nombre con el que se rotulan el reporte y las figuras. Por defecto el del
    # dataset, pero conviene distinguirlo cuando la entrada no es el dataset real.
    nombre = args.name or args.dataset
    if any("sintetic" in p.name.lower() or "synthetic" in p.name.lower() for p in rutas):
        nombre = args.name or f"{args.dataset} (SINTETICO)"
        console.print(
            "\n[yellow]Aviso:[/yellow] [dim]la entrada parece un archivo sintético. "
            "Estas métricas validan la tubería de evaluación, no la eficacia del "
            "detector: para la memoria hacen falta los datasets reales "
            "(ver docs/DATASETS.md).[/dim]"
        )

    kwargs = {"technique": args.technique} if args.dataset == "security-datasets" else {}
    loader = LOADERS[args.dataset](**kwargs)
    with console.status("[dim]Cargando y normalizando…[/dim]"):
        labeled = list(loader.load_many(rutas, limit=args.limit))

    if not labeled:
        console.print("[red]El dataset no contiene eventos legibles.[/red]")
        return 1

    n_ataques = sum(item.label for item in labeled)
    console.print(
        f"\n[bold]Eventos:[/bold] {len(labeled)}   "
        f"[bold]Ataques:[/bold] {n_ataques} ({n_ataques / len(labeled):.1%})   "
        f"[bold]Benignos:[/bold] {len(labeled) - n_ataques}"
    )
    if n_ataques == 0 or n_ataques == len(labeled):
        console.print("[red]Se necesitan ambas clases para evaluar.[/red]")
        return 1

    with console.status("[dim]Entrenando la línea base y midiendo…[/dim]"):
        evaluation = evaluate_anomaly_detector(
            labeled, dataset=nombre, train_ratio=args.train_ratio,
            threshold=args.threshold, seed=args.seed,
        )

    _render_evaluation(evaluation)

    if args.curves:
        ruta = save_curves(evaluation, args.curves)
        if ruta:
            console.print(f"\n[green]Curvas ROC y precisión-exhaustividad en:[/green] {ruta}")
        else:
            console.print(
                "\n[yellow]matplotlib no está instalado[/yellow] [dim](pip install "
                "'matplotlib>=3.7'); los puntos de ambas curvas están en el JSON.[/dim]"
            )

    if args.json:
        Path(args.json).write_text(
            json.dumps(evaluation.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8"
        )
        console.print(f"[green]Reporte de métricas en:[/green] {args.json}")
    return 0


def _render_evaluation(evaluation: Any) -> None:
    """Presenta las métricas con el contexto que hace falta para interpretarlas."""
    c = evaluation.confusion
    console.print(
        f"[dim]Protocolo: entrenamiento con {evaluation.n_train_benign} eventos benignos; "
        f"evaluación sobre {evaluation.n_test} eventos no vistos "
        f"({evaluation.n_test_attacks} ataques, {evaluation.attack_ratio:.1%}). "
        f"Umbral aplicado: {evaluation.threshold:.3f}.[/dim]\n"
    )

    tabla = Table(title="Detector de anomalías en el punto de operación", box=box.SIMPLE_HEAVY)
    for columna in ("Precisión", "Exhaustividad", "F1", "Tasa FP", "AUC-ROC", "AUC-PR"):
        tabla.add_column(columna, justify="right")
    tabla.add_row(
        f"{c.precision:.3f}", f"{c.recall:.3f}", f"{c.f1:.3f}",
        f"{c.false_positive_rate:.3f}", f"{evaluation.roc_auc:.3f}", f"{evaluation.pr_auc:.3f}",
    )
    console.print(tabla)

    matriz = Table(title="Matriz de confusión", box=box.SIMPLE)
    matriz.add_column("")
    matriz.add_column("Predicho: ataque", justify="right")
    matriz.add_column("Predicho: benigno", justify="right")
    matriz.add_row("Real: ataque", f"[green]{c.true_positives}[/green]", f"[red]{c.false_negatives}[/red]")
    matriz.add_row("Real: benigno", f"[red]{c.false_positives}[/red]", f"[green]{c.true_negatives}[/green]")
    console.print(matriz)

    if evaluation.per_category:
        por_familia = Table(title="Exhaustividad por familia de ataque", box=box.SIMPLE)
        por_familia.add_column("Familia")
        por_familia.add_column("Detectados", justify="right")
        por_familia.add_column("Total", justify="right")
        por_familia.add_column("Recall", justify="right")
        for categoria in sorted(evaluation.per_category, key=lambda c: -c.total):
            estilo = "green" if categoria.recall >= 0.7 else "yellow" if categoria.recall >= 0.3 else "red"
            por_familia.add_row(
                categoria.category, str(categoria.detected), str(categoria.total),
                f"[{estilo}]{categoria.recall:.2f}[/{estilo}]",
            )
        console.print(por_familia)
        console.print(
            "[dim]Un F1 global aceptable puede esconder una familia entera que no se "
            "detecta nunca; por eso se desglosa.[/dim]\n"
        )

    barrido = Table(title="Puntos de operación posibles", box=box.SIMPLE)
    for columna in ("Percentil", "Umbral", "Precisión", "Exhaustividad", "F1", "Tasa FP"):
        barrido.add_column(columna, justify="right")
    for fila in evaluation.threshold_sweep:
        barrido.add_row(
            f"p{fila['percentile']}", f"{fila['threshold']:.3f}", f"{fila['precision']:.3f}",
            f"{fila['recall']:.3f}", f"{fila['f1']:.3f}", f"{fila['false_positive_rate']:.3f}",
        )
    console.print(barrido)
    console.print(
        "[dim]Elegir el punto de operación es una decisión del equipo —cuántos falsos "
        "positivos se toleran a cambio de cuánta cobertura—, no un valor por defecto.[/dim]"
    )


DEFAULT_FEEDBACK_STORE = ROOT / "data" / "feedback" / "decisions.jsonl"


def cmd_decide(args: argparse.Namespace) -> int:
    """
    Registra la decisión de un analista sobre un hallazgo (human-in-the-loop).

    Cierra el bucle: la evidencia que el agente produjo se sella dentro de la
    decisión, de modo que un cambio posterior en las reglas no pueda reescribir
    lo que el analista vio cuando decidió.
    """
    from datetime import datetime, timezone

    from .governance.dataset_manager import DatasetManager
    from .governance.feedback import HumanDecision, StructuredDecision

    reporte_path = Path(args.report)
    if not reporte_path.exists():
        console.print(f"[red]No existe el reporte:[/red] {reporte_path}")
        console.print("[dim]Genéralo con: analyze -i <telemetría> --json <reporte>[/dim]")
        return 1

    reporte = json.loads(reporte_path.read_text(encoding="utf-8"))
    incidentes = reporte.get("incidents", [])
    objetivo = next(
        (i for i in incidentes if i["evidence"].get("event_ref") == args.event_ref), None
    )
    if objetivo is None:
        console.print(f"[red]No hay ningún evento con event_ref={args.event_ref}[/red]")
        console.print(
            "[dim]Los event_ref disponibles se ven en la salida de analyze "
            "o en el campo evidence.event_ref del reporte.[/dim]"
        )
        return 1

    evidencia = objetivo["evidence"]
    manager = DatasetManager(store_path=args.store or DEFAULT_FEEDBACK_STORE)
    decision = StructuredDecision(
        detection_id=f"{evidencia['run_id']}:{evidencia['event_ref']}",
        event_id=evidencia["event_ref"],
        # Marca de tiempo del EVENTO, no del etiquetado: usar la segunda
        # introduciría fuga temporal al construir particiones.
        timestamp=datetime.fromisoformat(evidencia["created_at"]),
        analyst_decision=HumanDecision(args.decision),
        confidence=args.confidence,
        reason=args.reason,
        # La evidencia queda sellada tal y como la vio el analista.
        selected_evidence=evidencia,
        analyst_id=args.analyst,
        model_version=reporte.get("component_status", {}).get("ml", "desconocida"),
        rule_version=reporte.get("component_status", {}).get("sigma", "desconocida"),
        data_source=str(reporte_path),
        created_at=datetime.now(tz=timezone.utc),
    )

    if not manager.submit_decision(decision):
        console.print("[red]La decisión fue rechazada por el gestor de dataset.[/red]")
        return 2

    console.print(Panel.fit(
        f"[bold cyan]Decisión registrada[/bold cyan]\n"
        f"[dim]{decision.fingerprint()}[/dim]", box=box.ROUNDED,
    ))
    console.print(f"  [bold]Evento:[/bold] {decision.event_id}")
    console.print(f"  [bold]Decisión:[/bold] {decision.analyst_decision.value}")
    console.print(f"  [bold]Analista:[/bold] {decision.analyst_id}   "
                  f"[bold]Confianza:[/bold] {decision.confidence:.2f}")
    console.print(f"  [bold]run_id:[/bold] [dim]{evidencia['run_id']}[/dim]")

    metricas = manager.get_metrics()
    console.print(f"\n[bold]Estado del dataset de feedback:[/bold] {metricas}")
    console.print(f"[green]Persistido en:[/green] {manager.store_path}")

    if args.audit:
        log = AuditLog(args.audit)
        log.record(
            actor=f"human:{decision.analyst_id}",
            action="analyst_decision",
            detail={
                "run_id": evidencia["run_id"],
                "event_ref": decision.event_id,
                "decision": decision.analyst_decision.value,
                "confidence": decision.confidence,
                "reason": decision.reason,
                "fingerprint": decision.fingerprint(),
            },
        )
        console.print(f"[green]Registrado en la auditoría:[/green] {args.audit}")
    return 0


def cmd_feedback_status(args: argparse.Namespace) -> int:
    """Muestra el estado del dataset de decisiones humanas."""
    from .governance.dataset_manager import DatasetManager

    ruta = Path(args.store or DEFAULT_FEEDBACK_STORE)
    manager = DatasetManager(store_path=ruta)
    if not ruta.exists():
        console.print(f"[yellow]Todavía no hay decisiones registradas en {ruta}.[/yellow]")
        return 0

    console.print(Panel.fit(
        "[bold cyan]CyberSentinel[/bold cyan] — Dataset de feedback humano",
        box=box.ROUNDED,
    ))
    metricas = manager.get_metrics()
    tabla = Table(box=box.SIMPLE)
    tabla.add_column("Métrica")
    tabla.add_column("Valor", justify="right")
    for clave, valor in metricas.items():
        tabla.add_row(str(clave), str(valor))
    console.print(tabla)
    console.print(
        "[dim]UNCERTAIN y CONFLICT no son etiquetas de entrenamiento: quedan "
        "registradas, pero no alimentan un modelo supervisado.[/dim]"
    )
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
    p_an.add_argument("--text", help="Ruta para volcar las narrativas en texto plano "
                                     "(util para pegarlas en la memoria).")
    p_an.add_argument("--navigator", help="Ruta para exportar una capa de ATT&CK Navigator.")
    p_an.add_argument("--all", action="store_true",
                      help="Mostrar todos los eventos, no solo los hallazgos.")
    p_an.add_argument("--no-llm", action="store_true", help="Desactivar la explicación.")
    p_an.add_argument("--no-rag", action="store_true", help="Desactivar la recuperación de contexto.")
    p_an.add_argument("--no-cti", action="store_true", help="Desactivar el enriquecimiento CTI.")
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

    p_as = sub.add_parser(
        "attack-sync",
        help="Genera la caché de MITRE ATT&CK desde el STIX oficial.",
    )
    p_as.add_argument("--stix", help="Ruta al enterprise-attack.json de MITRE.")
    p_as.add_argument("--output", help="Ruta de la caché a generar.")
    p_as.add_argument("--coverage", action="store_true",
                      help="Mostrar además qué parte de la matriz cubren las reglas.")
    p_as.set_defaults(func=cmd_attack_sync)

    p_ed = sub.add_parser(
        "evaluate-detection",
        help="Mide el detector de anomalías contra un dataset público etiquetado.",
    )
    p_ed.add_argument("--dataset", required=True,
                      choices=("unsw-nb15", "cicids2017", "security-datasets"),
                      help="Dataset de entrada.")
    p_ed.add_argument("--input", "-i", required=True, nargs="+",
                      help="Uno o varios archivos del dataset.")
    p_ed.add_argument("--limit", type=int, help="Máximo de eventos a cargar.")
    p_ed.add_argument("--name", help="Nombre con el que rotular el reporte y las figuras.")
    p_ed.add_argument("--train-ratio", type=float, default=0.5,
                      help="Proporción del tráfico benigno usada como línea base.")
    p_ed.add_argument("--threshold", type=float,
                      help="Umbral fijo. Por defecto, el que sugiere la línea base.")
    p_ed.add_argument("--seed", type=int, default=42, help="Semilla de la partición.")
    p_ed.add_argument("--technique", default="unknown",
                      help="Técnica ATT&CK del archivo (solo para security-datasets).")
    p_ed.add_argument("--curves", help="Ruta del PNG con las curvas ROC y precisión-exhaustividad.")
    p_ed.add_argument("--json", help="Ruta para volcar las métricas en JSON.")
    p_ed.set_defaults(func=cmd_evaluate_detection)

    p_hd = sub.add_parser(
        "decide", help="Registra la decisión de un analista sobre un hallazgo (HITL).",
    )
    p_hd.add_argument("--report", required=True, help="Reporte JSON producido por analyze.")
    p_hd.add_argument("--event-ref", required=True, help="event_ref del hallazgo a etiquetar.")
    p_hd.add_argument("--decision", required=True,
                      choices=("TRUE_POSITIVE", "FALSE_POSITIVE", "BENIGN", "UNCERTAIN"))
    p_hd.add_argument("--analyst", required=True, help="Identificador del analista.")
    p_hd.add_argument("--reason", default="", help="Justificación de la decisión.")
    p_hd.add_argument("--confidence", type=float, default=1.0, help="Confianza (0.0–1.0).")
    p_hd.add_argument("--store", help="Ruta del almacén de decisiones (JSONL).")
    p_hd.add_argument("--audit", help="Ruta del log de auditoría donde registrar la decisión.")
    p_hd.set_defaults(func=cmd_decide)

    p_fs = sub.add_parser(
        "feedback-status", help="Estado del dataset de decisiones humanas.",
    )
    p_fs.add_argument("--store", help="Ruta del almacén de decisiones (JSONL).")
    p_fs.set_defaults(func=cmd_feedback_status)

    p_va = sub.add_parser("verify-audit", help="Verifica la integridad del log de auditoría.")
    p_va.add_argument("--audit", default="audit_log.jsonl")
    p_va.set_defaults(func=cmd_verify_audit)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
