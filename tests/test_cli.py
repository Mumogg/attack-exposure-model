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
    csv_path = files["out"] / "report_exposure.csv"
    with csv_path.open(encoding="utf-8-sig", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert [r["technique_id"] for r in rows] == ["T1190", "T1021.001", "T1059.003"]
    assert json.loads((files["out"] / "global_review.json").read_text(encoding="utf-8"))["mode"] == "auto"


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
    assert not _is_copyrighted(DATA_DIR / "reports" / "gunra_aa26-222a_stripped.txt")


def test_gitignore_keeps_copyrighted_material_out():
    from aem.config import REPO_ROOT

    rules = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    for rule in ("data/reports/akira_dfir_2026*", "runs/llm_cache_private/", "runs/*/private/",
                 "eval/review_sheets/private/", ".env"):
        assert rule in rules, rule
