"""Command-line interface (texts in Spanish)."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from typer.core import TyperCommand, TyperGroup

from aem import config
from aem.config import (
    ANON_NAMES_FILE, ATTACK_CHECKSUMS, ATTACK_FILE, ATTACK_URL, DATA_DIR, KNOWN_IOCS_FILE, LLM_CACHE_DIR, LLM_PRIVATE_CACHE_DIR,
    ORG_FILE, PREVALENCE_FILE, RUNS_DIR, SCENARIOS_FILE, SSVC_TREE_FILE, Settings, load_model_config,
)
from aem.fetch import http_get

HELP_TEXT = "Muestra esta ayuda y termina."


def _spanish_help(cls):
    """Typer/Click class whose --help option is described in Spanish."""
    class Spanish(cls):
        def get_help_option(self, ctx):
            opt = super().get_help_option(ctx)
            if opt is not None:
                opt.help = HELP_TEXT
            return opt
    return Spanish


SpanishGroup = _spanish_help(TyperGroup)
SpanishCommand = _spanish_help(TyperCommand)

app = typer.Typer(
    cls=SpanishGroup,
    help="Prototipo de tesis: evaluación de exposición a técnicas MITRE ATT&CK asistida por IA "
         "(solo para reproducibilidad; no es una herramienta de producción).",
    no_args_is_help=True, add_completion=False,
)
console = Console()

DEMO_REPORT = DATA_DIR / "reports" / "gunra_aa26-222a_stripped.txt"
DEMO_OUT = RUNS_DIR / "demo" / "gunra"
REVIEW_SHEETS_DIR = config.REPO_ROOT / "eval" / "review_sheets"


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
        client=GeminiClient(settings, LLMCache(cache_dir), demo=demo,
                            private_cache=LLMCache(LLM_PRIVATE_CACHE_DIR)), model_cfg=load_model_config(),
        tree=load_tree(SSVC_TREE_FILE), prevalence=load_prevalence(PREVALENCE_FILE), patterns=load_patterns(),
        console=console,
    )


def _is_copyrighted(report: Path) -> bool:
    """True if the report is (a version of) a scenario whose text cannot be published."""
    from aem.scenarios import load_scenarios

    target = Path(report).resolve()
    return any(target in {p.resolve() for p in (sc.text, sc.stripped, sc.variant, sc.anon)}
               for sc in load_scenarios(SCENARIOS_FILE).values() if sc.copyrighted)


def _run(report: Path, org: Path, analyst_mode: str, demo: bool, out: Path, attack: Path, cache_dir: Path) -> None:
    from aem.llm import LLMError
    from aem.pipeline import EmptyExtraction, run_pipeline, write_outputs, write_record

    if not Path(report).is_file():
        _fail(f"No existe el reporte {report}. Para los escenarios de la tesis ejecute `aem fetch-data`.")
    try:
        ctx = _build_context(org, attack, cache_dir, demo)
        private = _is_copyrighted(report)
        if private:
            console.print("[yellow]Reporte con derechos de autor:[/yellow] la caché va a runs/llm_cache_private/ "
                          "(ignorada por git). No suba la carpeta de salida: contiene citas del reporte.")
        result = run_pipeline(Path(report).read_text(encoding="utf-8"), ctx, analyst_mode=analyst_mode,
                              private=private)
    except EmptyExtraction as exc:
        write_record(Path(out) / "run_record.json", exc.extraction, {"error": str(exc)})
        _fail(f"{exc} Registro guardado en {Path(out) / 'run_record.json'}")
    except (LLMError, FileNotFoundError, ValueError, KeyError) as exc:
        _fail(str(exc))
    paths = write_outputs(result, out, stem=Path(report).stem)
    if result.meta["fake"]:
        console.print(f"[bold red]FAKE:[/bold red] respuestas que no provienen de la API real de Gemini "
                      f"(origen: {', '.join(result.meta['llm_sources'])}). Los archivos llevan el prefijo FAKE_.")
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
            try:
                log = prepare_cisa(sc, sc.raw_html.read_text(encoding="utf-8"), attack)
            except AttackSectionNotFound as exc:
                _fail(f"{sc.name}: {exc}. La página de CISA pudo haber cambiado de estructura ({sc.url}); "
                      "revise el HTML en data/reports/raw/.")
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


@app.command("fetch-data", cls=SpanishCommand)
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


@app.command("prepare-reports", cls=SpanishCommand)
def prepare_reports(
    attack: Path = typer.Option(ATTACK_FILE, "--attack", help="Archivo STIX de ATT&CK v19.2."),
    force: bool = typer.Option(False, "--force", help="Regenerar también los textos de CISA ya preparados."),
) -> None:
    """Quita el mapeo ATT&CK y todos los IDs de los reportes (incluido el texto de Akira que usted coloque)."""
    try:
        _prepare_reports(attack, force=force, download=False)
    except (FileNotFoundError, OSError) as exc:
        _fail(str(exc))


@app.command("make-variants", cls=SpanishCommand)
def make_variants() -> None:
    """Genera la variante «mut» de cada reporte (IoC modificados, comportamiento intacto) y los IoC conocidos."""
    from aem.scenarios import load_scenarios
    from eval.make_variants import VariantLeak, build_variants

    cfg = load_model_config()
    scenarios = load_scenarios(SCENARIOS_FILE)
    try:
        logs = build_variants(scenarios, cfg, KNOWN_IOCS_FILE)
    except VariantLeak as exc:
        _fail(str(exc))
    for log in logs:
        console.print(f"{log['scenario']}: {log['variant']} — {log['unique_replaced']} IoC distintos reemplazados "
                      f"({log['occurrences_replaced']} apariciones) {log['replacements_by_type']}; "
                      "verificación: ningún IoC del original queda en mut")
        a = log["anon"]
        console.print(f"  anon: {a['file']} — {a['names_replaced']} nombres de la amenaza reemplazados; "
                      "verificación: ningún nombre ni IoC del original queda en anon"
                      + (f" (no aparecen en el texto: {', '.join(a['names_absent'])})" if a["names_absent"] else ""))
        if log["plain_candidates_kept"]:
            console.print(f"  {len(log['plain_candidates_kept'])} tokens sin defang con forma de IoC se dejaron "
                          f"intactos (revíselos en el diff): "
                          + ", ".join(f"{c['value']} (línea {c['line']})" for c in log["plain_candidates_kept"]))
    for name in sorted(set(scenarios) - {log["scenario"] for log in logs}):
        console.print(f"[yellow]{name}:[/yellow] sin texto preparado; ejecute `aem prepare-reports` primero.")
    console.print(f"semilla {cfg.variants.seed}; IoC conocidos de la organización: {KNOWN_IOCS_FILE}")


@app.command("run", cls=SpanishCommand)
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


@app.command("demo", cls=SpanishCommand)
def demo_cmd(
    out: Path = typer.Option(DEMO_OUT, "--out", help="Carpeta de salida."),
    attack: Path = typer.Option(ATTACK_FILE, "--attack", help="Archivo STIX de ATT&CK v19.2."),
    cache_dir: Path = typer.Option(LLM_CACHE_DIR, "--cache-dir", help="Carpeta de la caché de respuestas del LLM."),
) -> None:
    """Corre el escenario de Gunra (AA26-222A) en modo demo, sin API key."""
    _run(DEMO_REPORT, ORG_FILE, "auto", True, out, attack, cache_dir)


_STATUS_STYLE = {"OK": "green", "FALTA": "bold red", "AVISO": "yellow", "INFO": "cyan"}


def _preflight_checks(demo: bool, replicates: int, attack: Path) -> list:
    from aem.preflight import run_preflight
    from aem.scenarios import load_scenarios

    _load_env()
    cfg = load_model_config()
    return run_preflight(settings=Settings.from_env(load_dotenv_file=False), demo=demo, attack_path=attack,
                         checksums_path=ATTACK_CHECKSUMS, scenarios=load_scenarios(SCENARIOS_FILE),
                         prevalence_path=PREVALENCE_FILE, repo_root=config.REPO_ROOT, model_cfg=cfg,
                         replicates=replicates or cfg.experiment.replicates)


def _print_checks(checks: list) -> None:
    for c in checks:
        style = _STATUS_STYLE.get(c.status, "")
        console.print(f"[{style}]{c.status:<5}[/{style}] {c.item}" + (f" — {c.detail}" if c.detail else ""),
                      highlight=False)


@app.command("suggest-anon-names", cls=SpanishCommand)
def suggest_anon_names(
    scenario: str = typer.Option("", "--scenario", help="Escenario (akira, gunra, interlock); vacío = todos."),
) -> None:
    """Propone nombres de la amenaza para data/anon_names.yaml (no lo modifica)."""
    from aem.scenarios import load_scenarios
    from eval.anon_suggest import CRITERIA, coverage, suggest, write_candidates
    from eval.make_variants import load_anon_names

    scenarios = load_scenarios(SCENARIOS_FILE)
    if scenario and scenario not in scenarios:
        _fail(f"Escenario desconocido: {scenario!r} (opciones: {', '.join(scenarios)})")
    names = load_anon_names(ANON_NAMES_FILE)
    console.print("[bold]Criterio[/bold]\n" + CRITERIA.strip(), highlight=False)
    for sc in [scenarios[scenario]] if scenario else list(scenarios.values()):
        if not sc.text.exists():
            console.print(f"[yellow]AVISO[/yellow] {sc.name}: no existe {sc.text}; nada que sugerir.", highlight=False)
            continue
        text = sc.text.read_text(encoding="utf-8")
        cands = suggest(text)
        console.print(f"\n[bold]{sc.name}[/bold]: {len(cands)} candidatos", highlight=False)
        for i, c in enumerate(cands, 1):
            ctx = " · ".join(f"«{x}»" for x in c.contexts)
            console.print(f"{i}. {c.name} — {c.count}× — {c.label} ({c.reason}) — {ctx}", highlight=False)
        cov = coverage(text, cands, names.get(sc.name, []))
        console.print(f"Ya en anon_names.yaml y propuestos: {', '.join(cov['covered']) or 'ninguno'}", highlight=False)
        for n in cov["missing_in_text"]:
            console.print(f"[yellow]AVISO[/yellow] «{n}» está en anon_names.yaml y en el texto, pero el sugeridor no "
                          "lo propuso: revise el criterio o el nombre.", highlight=False)
        for n in cov["absent"]:
            console.print(f"[yellow]AVISO[/yellow] «{n}» está en anon_names.yaml pero no aparece en el texto.",
                          highlight=False)
        out = write_candidates(sc.text.parent / "private", sc.name, text, cands, names.get(sc.name, []))
        console.print(f"Archivo (ignorado por git): {out}\nCopie a mano a {ANON_NAMES_FILE.name} solo las filas que "
                      "apruebe (sección final del archivo) y ejecute `aem make-variants`.", highlight=False)


@app.command("preflight", cls=SpanishCommand)
def preflight_cmd(
    demo: bool = typer.Option(False, "--demo", help="Comprobar para `aem eval --demo` (sin API key)."),
    replicates: int = typer.Option(0, "--replicates", help="Corridas por escenario × versión para la estimación "
                                                            "(0 = valor de data/model_config.yaml)."),
    attack: Path = typer.Option(ATTACK_FILE, "--attack", help="Archivo STIX de ATT&CK v19.2."),
) -> None:
    """Comprueba que todo está listo antes de gastar llamadas a la API (OK / FALTA / AVISO)."""
    from aem.preflight import has_blocker

    checks = _preflight_checks(demo, replicates, attack)
    _print_checks(checks)
    if has_blocker(checks):
        _fail("hay al menos un FALTA: corríjalo antes de ejecutar `aem eval`.")
    console.print("[green]Listo para `aem eval`.[/green]")


@app.command("check-repo", cls=SpanishCommand)
def check_repo_cmd(
    repo: Path = typer.Option(config.REPO_ROOT, "--repo", help="Repositorio git a revisar."),
    dfir_text: Path = typer.Option(DATA_DIR / "reports" / "akira_dfir_2026.txt", "--dfir-text",
                                   help="Copia local del reporte de DFIR (para buscar sus frases)."),
) -> None:
    """Busca .env, API keys, texto del reporte de DFIR y archivos private/ en los archivos versionados y en todo
    el historial de git. Termina con código 1 si encuentra algo."""
    from aem.repo_check import check_repo, distinctive_phrases

    phrases = []
    if Path(dfir_text).exists():
        phrases = distinctive_phrases(Path(dfir_text).read_text(encoding="utf-8"))
    else:
        console.print(f"[yellow]AVISO[/yellow] no existe {dfir_text}: no se buscó texto del reporte de DFIR "
                      "(solo .env, API keys y carpetas private/).", highlight=False)
    try:
        result = check_repo(repo, phrases)
    except ValueError as exc:
        _fail(str(exc))
    console.print(f"Revisados {result['commits']} commits y el índice; {result['phrases']} frases del reporte "
                  "de DFIR.", highlight=False)
    if result["findings"]:
        for f in result["findings"]:
            console.print(f"[bold red]ENCONTRADO[/bold red] {f['kind']}: {f['where']}", highlight=False)
        _fail(f"{len(result['findings'])} hallazgo(s). No suba el repositorio: si está en el historial, hay que "
              "reescribirlo (p. ej. git filter-repo) antes de publicarlo.")
    console.print("[green]OK[/green] nada sensible en los archivos versionados ni en el historial.")


@app.command("eval", cls=SpanishCommand)
def eval_cmd(
    demo: bool = typer.Option(False, "--demo", help="Usar solo respuestas guardadas en la caché (sin API key)."),
    run_id: str = typer.Option("", "--run-id", help="Nombre de la carpeta en runs/ (por defecto, la fecha de hoy)."),
    replicates: int = typer.Option(0, "--replicates", help="Corridas por escenario × versión (0 = valor de "
                                                            "data/model_config.yaml)."),
    org: Path = typer.Option(ORG_FILE, "--org", help="YAML de la organización (estilo DeTT&CT)."),
    attack: Path = typer.Option(ATTACK_FILE, "--attack", help="Archivo STIX de ATT&CK v19.2."),
    cache_dir: Path = typer.Option(LLM_CACHE_DIR, "--cache-dir", help="Carpeta de la caché de respuestas del LLM."),
) -> None:
    """Corre el experimento completo (escenarios × orig/mut × corridas) y genera las tablas de los 5 indicadores."""
    from datetime import date

    from aem.llm import LLMError
    from aem.scenarios import load_scenarios
    from eval.run_experiments import run_experiment

    from aem.preflight import has_blocker

    checks = _preflight_checks(demo, replicates, attack)
    _print_checks(checks)
    if has_blocker(checks):
        _fail("el preflight encontró al menos un FALTA (arriba); `aem eval` no se ejecuta. "
              "Corríjalo y vuelva a intentar (`aem preflight` repite solo la comprobación).")
    run_dir = RUNS_DIR / (run_id or date.today().isoformat())
    try:
        ctx = _build_context(org, attack, cache_dir, demo)
        n = replicates or ctx.model_cfg.experiment.replicates
        result = run_experiment(ctx, load_scenarios(SCENARIOS_FILE), run_dir, REVIEW_SHEETS_DIR, n, console=console)
    except (LLMError, FileNotFoundError, ValueError) as exc:
        _fail(f"{exc}\nLas respuestas ya obtenidas quedan en la caché: al repetir el comando se reutilizan.")
    for item in result["skipped"]:
        console.print(f"[yellow]Sin texto, no evaluado:[/yellow] {item}")
    if result["paths"]["markdown"].parent.name == "results_FAKE":
        console.print("[bold red]FAKE:[/bold red] alguna respuesta no proviene de la API real de Gemini. Las tablas "
                      "quedaron en results_FAKE/ con prefijo FAKE_ y no sirven como resultados de la tesis.")
    failed = [r for r in result["runs"] if r["status"] != "ok"]
    console.print(f"[green]Listo.[/green] {len(result['runs'])} corridas ({len(failed)} sin salida utilizable).")
    for label in ("markdown", "indicator4_sheet", "indicator5_sheet"):
        console.print(f"  {label}: {result['paths'][label]}")


if __name__ == "__main__":
    app()
