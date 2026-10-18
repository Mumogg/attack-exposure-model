import csv
import json

import pytest
import yaml
from typer.testing import CliRunner

from aem.cli import app
from test_pipeline import REPORT, RoutingTransport, mk_ctx
from aem.pipeline import run_pipeline

runner = CliRunner()


@pytest.fixture
def files(tmp_path, mini_attack, monkeypatch):
    monkeypatch.setenv("GEMINI_MODEL", "gemini-3.8-flash")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setattr("aem.cli._load_env", lambda: None)  # never read the developer's .env in tests
    ctx = mk_ctx(tmp_path, mini_attack, RoutingTransport())
    report = tmp_path / "report.txt"
    report.write_text(REPORT, encoding="utf-8")
    org = tmp_path / "org.yaml"
    org.write_text(yaml.safe_dump(ctx.org.model_dump(mode="json"), allow_unicode=True), encoding="utf-8")
    return {"ctx": ctx, "report": report, "org": org, "cache": tmp_path / "cache", "attack": mini_attack.bundle_path,
            "out": tmp_path / "out"}


def _args(f, *extra):
    return ["run", "--report", str(f["report"]), "--org", str(f["org"]), "--analyst-mode", "auto",
            "--out", str(f["out"]), "--attack", str(f["attack"]), "--cache-dir", str(f["cache"]), *extra]


def test_help_is_in_spanish():
    res = runner.invoke(app, ["--help"])
    assert res.exit_code == 0
    for cmd in ("fetch-data", "run", "demo"):
        assert cmd in res.output
    assert "Descarga" in res.output


def test_run_demo_end_to_end(files):
    run_pipeline(REPORT, files["ctx"], analyst_mode="auto")  # fills the tmp cache with fake answers
    res = runner.invoke(app, _args(files, "--demo"))
    assert res.exit_code == 0, res.output
    csv_path = files["out"] / "FAKE_report_exposure.csv"  # the cache holds fake answers (D-71)
    assert "FAKE" in res.output
    with csv_path.open(encoding="utf-8-sig", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert [r["technique_id"] for r in rows] == ["T1190", "T1021.001", "T1059.003"]
    assert json.loads((files["out"] / "FAKE_global_review.json").read_text(encoding="utf-8"))["mode"] == "auto"


def test_run_demo_without_cache_fails_clearly(files):
    res = runner.invoke(app, _args(files, "--demo"))
    assert res.exit_code == 1
    assert "Modo demo" in res.output


def test_run_without_key_fails_clearly(files):
    res = runner.invoke(app, _args(files))
    assert res.exit_code == 1
    assert "GEMINI_API_KEY" in res.output


def test_demo_command_missing_report(files, tmp_path, monkeypatch):
    monkeypatch.setattr("aem.cli.DEMO_REPORT", tmp_path / "no_existe.txt")
    res = runner.invoke(app, ["demo", "--attack", str(files["attack"]), "--cache-dir", str(files["cache"])])
    assert res.exit_code == 1
    assert "no_existe.txt" in res.output


def test_fetch_data_prepares_cisa_reports(tmp_path, monkeypatch, mini_attack):
    import shutil
    from test_reports import HTML
    from aem.config import SCENARIOS_FILE

    data = tmp_path / "data"
    (data / "reference_mappings").mkdir(parents=True)
    shutil.copy(SCENARIOS_FILE, data / "scenarios.yaml")
    monkeypatch.setattr("aem.cli.SCENARIOS_FILE", data / "scenarios.yaml")
    monkeypatch.setattr("aem.cli._fetch_attack", lambda: mini_attack.bundle_path)
    monkeypatch.setattr("aem.cli.http_get", lambda url: HTML.encode("utf-8"))
    res = runner.invoke(app, ["fetch-data"])
    assert res.exit_code == 0, res.output
    assert (data / "reports" / "gunra_aa26-222a_stripped.txt").exists()
    assert (data / "reports" / "interlock_aa25-203a_stripped.txt").exists()
    assert (data / "reference_mappings" / "gunra.csv").exists()
    assert "akira_dfir_2026.txt" in res.output.replace("\n", "")  # tells Sebas where to place the DFIR text


def test_make_variants_command(tmp_path, monkeypatch):
    import shutil
    from aem.config import SCENARIOS_FILE

    data = tmp_path / "data"
    (data / "reports").mkdir(parents=True)
    shutil.copy(SCENARIOS_FILE, data / "scenarios.yaml")
    (data / "reports" / "gunra_aa26-222a_stripped.txt").write_text("C2 45.61.136[.]10\n", encoding="utf-8")
    monkeypatch.setattr("aem.cli.SCENARIOS_FILE", data / "scenarios.yaml")
    monkeypatch.setattr("aem.cli.KNOWN_IOCS_FILE", tmp_path / "known.yaml")
    res = runner.invoke(app, ["make-variants"])
    assert res.exit_code == 0, res.output
    assert (data / "reports" / "gunra_aa26-222a_mut_stripped.txt").exists()
    assert (tmp_path / "known.yaml").exists()
    assert "semilla" in res.output


def test_eval_demo_without_cache_fails_clearly(files, tmp_path, monkeypatch):
    monkeypatch.setattr("aem.cli._preflight_checks", lambda demo, replicates, attack: [])  # tested on its own
    monkeypatch.setattr("aem.cli.RUNS_DIR", tmp_path / "runs")
    monkeypatch.setattr("aem.cli.REVIEW_SHEETS_DIR", tmp_path / "sheets")
    res = runner.invoke(app, ["eval", "--demo", "--attack", str(files["attack"]), "--cache-dir", str(files["cache"]),
                              "--org", str(files["org"]), "--run-id", "prueba", "--replicates", "1"])
    assert res.exit_code == 1
    assert "Modo demo" in res.output


def test_copyrighted_report_detection():
    from aem.cli import _is_copyrighted
    from aem.config import DATA_DIR

    assert _is_copyrighted(DATA_DIR / "reports" / "akira_dfir_2026_stripped.txt")
    assert _is_copyrighted(DATA_DIR / "reports" / "akira_dfir_2026_mut_stripped.txt")
    assert _is_copyrighted(DATA_DIR / "reports" / "akira_dfir_2026_anon_stripped.txt")
    assert not _is_copyrighted(DATA_DIR / "reports" / "gunra_aa26-222a_stripped.txt")


def test_gitignore_keeps_copyrighted_material_out():
    from aem.config import REPO_ROOT

    rules = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    for rule in ("data/reports/akira_dfir_2026*", "runs/llm_cache_private/", "runs/*/private/",
                 "eval/review_sheets/private/", "data/reports/private/", ".env"):
        assert rule in rules, rule


def test_fetch_data_reports_changed_page_clearly(tmp_path, monkeypatch, mini_attack):
    import shutil
    from aem.config import SCENARIOS_FILE

    data = tmp_path / "data"
    data.mkdir()
    shutil.copy(SCENARIOS_FILE, data / "scenarios.yaml")
    monkeypatch.setattr("aem.cli.SCENARIOS_FILE", data / "scenarios.yaml")
    monkeypatch.setattr("aem.cli._fetch_attack", lambda: mini_attack.bundle_path)
    page = '<div class="l-page-section--rich-text csaf-imported"><h2>Otra cosa</h2><p>x</p></div>'
    monkeypatch.setattr("aem.cli.http_get", lambda url: page.encode("utf-8"))
    res = runner.invoke(app, ["fetch-data"])
    assert res.exit_code == 1
    assert "gunra" in res.output and "ATT&CK" in res.output
    assert res.exception is None or isinstance(res.exception, SystemExit)


@pytest.mark.parametrize("args", [["--help"], ["run", "--help"], ["eval", "--help"]])
def test_help_option_text_is_in_spanish(args):
    res = runner.invoke(app, args)
    assert res.exit_code == 0
    assert "Show this message and exit" not in res.output
    assert "Muestra esta ayuda y termina." in res.output


def test_make_variants_leak_is_a_clear_error(tmp_path, monkeypatch):
    import shutil
    from aem.config import SCENARIOS_FILE

    data = tmp_path / "data"
    (data / "reports").mkdir(parents=True)
    shutil.copy(SCENARIOS_FILE, data / "scenarios.yaml")
    (data / "reports" / "gunra_aa26-222a_stripped.txt").write_text("x\nC2 45.61.136[.]10\n", encoding="utf-8")
    monkeypatch.setattr("aem.cli.SCENARIOS_FILE", data / "scenarios.yaml")
    monkeypatch.setattr("aem.cli.KNOWN_IOCS_FILE", tmp_path / "known.yaml")
    monkeypatch.setattr("eval.make_variants.make_variant", lambda text, cfg, seed, salt: (text, []))
    res = runner.invoke(app, ["make-variants"])
    assert res.exit_code == 1 and "Traceback" not in res.output
    out = res.output.replace("\n", "")
    assert "45.61.136.10" in out and "línea 2" in out


def test_preflight_command_reports_falta_without_key(files):
    res = runner.invoke(app, ["preflight"])  # no GEMINI_API_KEY in the test environment: no network call
    out = res.output.replace("\n", " ")
    assert res.exit_code == 1 and "FALTA" in out and "GEMINI_API_KEY" in out and "Estimación" in out


def test_eval_refuses_to_start_when_preflight_has_falta(files, tmp_path, monkeypatch):
    from aem.preflight import Check
    called = []
    monkeypatch.setattr("aem.cli._preflight_checks",
                        lambda demo, replicates, attack: [Check("FALTA", "Versiones de akira", "faltan anon")])
    monkeypatch.setattr("eval.run_experiments.run_experiment", lambda *a, **k: called.append(1))
    monkeypatch.setattr("aem.cli.RUNS_DIR", tmp_path / "runs")
    res = runner.invoke(app, ["eval", "--run-id", "x", "--attack", str(files["attack"]), "--org", str(files["org"])])
    assert res.exit_code == 1 and not called
    assert "preflight" in res.output and "Versiones de akira" in res.output.replace("\n", " ")


def test_eval_announces_omitted_scenarios_at_start_and_end(files, tmp_path, monkeypatch):
    """D-73: the CLI prints ESCENARIOS OMITIDOS before running and again, with RESULTADO PARCIAL, at the end."""
    from aem.config import SCENARIOS_FILE
    from aem.scenarios import load_scenarios

    data = tmp_path / "data"
    scenarios = {k: v.relocated(data) for k, v in load_scenarios(SCENARIOS_FILE).items()}
    monkeypatch.setattr("aem.scenarios.load_scenarios", lambda path: scenarios)
    monkeypatch.setattr("aem.cli._preflight_checks", lambda demo, replicates, attack: [])
    monkeypatch.setattr("aem.cli.RUNS_DIR", tmp_path / "runs")
    out = tmp_path / "results.md"
    out.write_text("", encoding="utf-8")
    order = []

    def fake_run(ctx, scs, run_dir, sheets, n, console=None):
        order.append("run")
        return {"runs": [], "skipped": [], "partial": True, "paths": {"markdown": out, "indicator4_sheet": out,
                                                                      "indicator5_sheet": out},
                "omitted": [{"scenario": "akira", "reason": "sin texto local"}]}

    monkeypatch.setattr("eval.run_experiments.run_experiment", fake_run)
    res = runner.invoke(app, ["eval", "--run-id", "x", "--attack", str(files["attack"]), "--org", str(files["org"]),
                              "--cache-dir", str(files["cache"]), "--replicates", "1"])
    text = res.output.replace("\n", " ")
    assert res.exit_code == 0, res.output
    assert text.count("ESCENARIOS OMITIDOS: akira (sin texto local)") == 2
    assert text.index("ESCENARIOS OMITIDOS") < text.index("Listo.") < text.index("RESULTADO PARCIAL: faltan escenarios")
    assert order == ["run"]
