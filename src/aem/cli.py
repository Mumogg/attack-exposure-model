"""Command-line interface (texts in Spanish)."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from aem import config
from aem.config import (
    ATTACK_CHECKSUMS, ATTACK_FILE, ATTACK_URL, DATA_DIR, LLM_CACHE_DIR, ORG_FILE, PREVALENCE_FILE, RUNS_DIR,
    SCENARIOS_FILE, SSVC_TREE_FILE, Settings, load_model_config,
)
from aem.fetch import http_get

app = typer.Typer(
    help="Prototipo de tesis: evaluación de exposición a técnicas MITRE ATT&CK asistida por IA "
         "(solo para reproducibilidad; no es una herramienta de producción).",
    no_args_is_help=True, add_completion=False,
)
console = Console()

DEMO_REPORT = DATA_DIR / "reports" / "gunra_aa26-222a_stripped.txt"
DEMO_OUT = RUNS_DIR / "demo" / "gunra"


def _load_env() -> None:
    from dotenv import load_dotenv

    load_dotenv(config.REPO_ROOT / ".env")


def _fail(message: str) -> None:
    console.print(f"[bold red]Error:[/bold red] {message}")
    raise typer.Exit(1)


def _build_context(org: Path, attack: Path, cache_dir: Path, demo: bool):
    from aem.attack_data import AttackData
    from aem.boundaries import load_patterns
    from aem.llm import GeminiClient, LLMCache
    from aem.org import load_org
    from aem.pipeline import PipelineContext
    from aem.step3_prioritize import load_tree
    from aem.step4_reference import load_prevalence

    _load_env()
    settings = Settings.from_env(load_dotenv_file=False)
    return PipelineContext(
        attack=AttackData.load(attack), org=load_org(org),
        client=GeminiClient(settings, LLMCache(cache_dir), demo=demo), model_cfg=load_model_config(),
        tree=load_tree(SSVC_TREE_FILE), prevalence=load_prevalence(PREVALENCE_FILE), patterns=load_patterns(),
        console=console,
    )


def _run(report: Path, org: Path, analyst_mode: str, demo: bool, out: Path, attack: Path, cache_dir: Path) -> None:
    from aem.llm import LLMError
    from aem.pipeline import EmptyExtraction, run_pipeline, write_outputs, write_record

    if not Path(report).is_file():
        _fail(f"No existe el reporte {report}. Para los escenarios de la tesis ejecute `aem fetch-data`.")
    try:
        ctx = _build_context(org, attack, cache_dir, demo)
        result = run_pipeline(Path(report).read_text(encoding="utf-8"), ctx, analyst_mode=analyst_mode)
    except EmptyExtraction as exc:
        write_record(Path(out) / "run_record.json", exc.extraction, {"error": str(exc)})
        _fail(f"{exc} Registro guardado en {Path(out) / 'run_record.json'}")
    except (LLMError, FileNotFoundError, ValueError, KeyError) as exc:
        _fail(str(exc))
    paths = write_outputs(result, out, stem=Path(report).stem)
    counts = {a: sum(r["action"] == a for r in result.rows) for a in ("Act", "Attend", "Track*", "Track")}
    console.print(f"[green]Listo.[/green] {len(result.rows)} técnicas. Acciones asignadas por el analista "
                  f"(árbol SSVC adaptado): " + ", ".join(f"{a}={n}" for a, n in counts.items()))
    for label, p in paths.items():
        console.print(f"  {label}: {p}")
    console.print("La salida no afirma que la organización haya sido comprometida.")


def _fetch_attack() -> Path:
    from aem.fetch import fetch_verified

    digest = fetch_verified(ATTACK_URL, ATTACK_FILE, ATTACK_CHECKSUMS)
    console.print(f"ATT&CK v19.2: {ATTACK_FILE} (SHA-256 {digest})")
    return ATTACK_FILE


def _prepare_reports(attack_path: Path, force: bool, download: bool) -> None:
    from aem.attack_data import AttackData
    from aem.reports import AttackSectionNotFound
    from aem.scenarios import load_reference, load_scenarios, prepare_cisa, prepare_plain

    attack = AttackData.load(attack_path)
    for sc in load_scenarios(SCENARIOS_FILE).values():
        if sc.source == "cisa":
            if sc.stripped.exists() and not force:
                console.print(f"{sc.name}: ya preparado ({sc.stripped.name}); use --force para regenerar.")
                continue
            if download or not sc.raw_html.exists():
                sc.raw_html.parent.mkdir(parents=True, exist_ok=True)
                sc.raw_html.write_bytes(http_get(sc.url))
            log = prepare_cisa(sc, sc.raw_html.read_text(encoding="utf-8"), attack)
            console.print(f"{sc.name}: {sc.stripped.name} y {sc.reference.name} "
                          f"({log['reference_techniques']} técnicas de referencia)")
        else:
            if not sc.text.exists():
                console.print(f"[yellow]{sc.name}:[/yellow] falta el texto. Descárguelo de {sc.url} y guárdelo "
                              f"como {sc.text} (no se sube al repositorio). Luego ejecute `aem prepare-reports`.")
                continue
            try:
                expected = [r.technique_id for r in load_reference(sc.reference)]
                log = prepare_plain(sc, expected)
            except AttackSectionNotFound as exc:
                _fail(f"{sc.name}: {exc}")
            console.print(f"{sc.name}: {sc.stripped.name}; mapeo de referencia: {log['reference_check']}")


@app.command("fetch-data")
def fetch_data(
    force: bool = typer.Option(False, "--force", help="Volver a descargar y regenerar los boletines de CISA."),
) -> None:
    """Descarga ATT&CK Enterprise v19.2 (verificando su SHA-256) y los boletines de CISA, y prepara los textos."""
    from aem.fetch import ChecksumMismatch

    try:
        attack_path = _fetch_attack()
        _prepare_reports(attack_path, force=force, download=True)
    except (ChecksumMismatch, OSError) as exc:
        _fail(str(exc))


@app.command("prepare-reports")
def prepare_reports(
    attack: Path = typer.Option(ATTACK_FILE, "--attack", help="Archivo STIX de ATT&CK v19.2."),
    force: bool = typer.Option(False, "--force", help="Regenerar también los textos de CISA ya preparados."),
) -> None:
    """Quita el mapeo ATT&CK y todos los IDs de los reportes (incluido el texto de Akira que usted coloque)."""
    try:
        _prepare_reports(attack, force=force, download=False)
    except (FileNotFoundError, OSError) as exc:
        _fail(str(exc))


@app.command("run")
def run(
    report: Path = typer.Option(..., "--report", help="Reporte de amenaza en texto plano (.txt o .md)."),
    org: Path = typer.Option(ORG_FILE, "--org", help="YAML de la organización (estilo DeTT&CT)."),
    analyst_mode: str = typer.Option("interactive", "--analyst-mode",
                                     help="interactive (analista en la terminal) o auto (solo experimentos)."),
    demo: bool = typer.Option(False, "--demo", help="Usar solo respuestas guardadas en la caché (sin API key)."),
    out: Path = typer.Option(..., "--out", help="Carpeta de salida."),
    attack: Path = typer.Option(ATTACK_FILE, "--attack", help="Archivo STIX de ATT&CK v19.2."),
    cache_dir: Path = typer.Option(LLM_CACHE_DIR, "--cache-dir", help="Carpeta de la caché de respuestas del LLM."),
) -> None:
    """Corre los 4 pasos del modelo sobre un reporte y escribe el CSV y global_review.json."""
    _run(report, org, analyst_mode, demo, out, attack, cache_dir)


@app.command("demo")
def demo_cmd(
    out: Path = typer.Option(DEMO_OUT, "--out", help="Carpeta de salida."),
    attack: Path = typer.Option(ATTACK_FILE, "--attack", help="Archivo STIX de ATT&CK v19.2."),
    cache_dir: Path = typer.Option(LLM_CACHE_DIR, "--cache-dir", help="Carpeta de la caché de respuestas del LLM."),
) -> None:
    """Corre el escenario de Gunra (AA26-222A) en modo demo, sin API key."""
    _run(DEMO_REPORT, ORG_FILE, "auto", True, out, attack, cache_dir)


if __name__ == "__main__":
    app()
