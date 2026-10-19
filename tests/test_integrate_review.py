"""`aem integrate-review`: the review sheets into an evaluated run, with no `aem eval`, no preflight and no API.
Synthetic runs, plus a copy of 2026-10-18-main in a temporary folder (the real run is never written)."""

from __future__ import annotations

import csv
import hashlib
import json
import shutil

import pytest
from typer.testing import CliRunner

from aem import cli
from aem.config import RUNS_DIR
from eval import review
from eval.integrate_review import STATUS, IntegrationError, integrate_review
from eval.run_experiments import run_experiment
from test_pipeline import RoutingTransport
from test_run_experiments import EXTRACTION, setup  # noqa: F401  (fixture)

MAIN_RUN = RUNS_DIR / "2026-10-18-main"
WRITTEN = {"results/indicator4.csv", "results/indicator5_manual.csv", "results/results.md", "results/results.json",
           "eval_history.json"}


def _guard(monkeypatch):
    """Integrating must not even build an LLM client or run the preflight."""
    def refuse(*a, **k):
        raise AssertionError("integrate-review no debe crear un cliente del LLM ni correr el preflight")

    monkeypatch.setattr("aem.llm.GeminiClient.__init__", refuse)
    monkeypatch.setattr("aem.preflight.run_preflight", refuse)
    monkeypatch.setattr("aem.cli._preflight_checks", refuse)


def _hashes(root):
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*")) if p.is_file()}


def _fill(path, kind, verdicts):
    columns, rows = review.read_sheet(path)
    for i, r in enumerate(rows):
        verdict = verdicts(i)
        r[kind.verdict], r[review.OBSERVATION] = verdict, ("OBS-SINTETICA" if verdict == kind.negative else "")
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=columns)
        w.writeheader()
        w.writerows(rows)
    return len(rows)


@pytest.fixture
def run(setup, monkeypatch):  # noqa: F811
    run_experiment(setup["ctx"](RoutingTransport(extraction=EXTRACTION)), setup["scenarios"], setup["run"],
                   setup["sheets"], replicates=2)  # the evaluation uses the fake client; the guard comes after
    _guard(monkeypatch)
    return setup


def test_integration_rewrites_only_the_review_tables(run, tmp_path):
    sheets, run_dir, docs = run["sheets"], run["run"], tmp_path / "docs"
    n4 = _fill(review.sheet_path(sheets, "r1", review.IND4), review.IND4, lambda i: "no" if i == 0 else "si")
    n5 = _fill(review.sheet_path(sheets, "r1", review.IND5), review.IND5, lambda i: "si" if i == 0 else "no")
    before = _hashes(run_dir)
    old = json.loads((run_dir / "results" / "results.json").read_text(encoding="utf-8"))
    result = integrate_review(run_dir, sheets, docs)
    after = _hashes(run_dir)
    changed = {p for p in after if before.get(p) != after[p]}
    assert changed <= WRITTEN and "eval_history.json" in changed and "results/results.json" in changed
    assert set(after) == set(before)  # nothing new, nothing removed (per-run files, provenance.json untouched)
    new = json.loads((run_dir / "results" / "results.json").read_text(encoding="utf-8"))
    assert {k: v for k, v in new.items() if k != "tables"} == {k: v for k, v in old.items() if k != "tables"}
    assert {k: v for k, v in new["tables"].items() if k not in ("indicator4", "indicator5_manual")} == {
        k: v for k, v in old["tables"].items() if k not in ("indicator4", "indicator5_manual")}
    ind4 = new["tables"]["indicator4"][0]
    assert ind4["manual_review"] == "revisión completa" and ind4["manual_ok"] == n4 - 1
    assert ind4["manual_ok_pct"] == round(100 * (n4 - 1) / n4, 2) and ind4["llm_source"] == old["tables"]["indicator4"][0]["llm_source"]
    total = new["tables"]["indicator5_manual"][-1]
    assert total["scenario"] == "total" and total["with_valuation"] == 1 and total["sample_rows"] == n5
    md = (run_dir / "results" / "results.md").read_text(encoding="utf-8")
    assert "OBS-SINTETICA" in md and "revisión completa" in md
    assert (docs / "resumen.md").exists() and "revisión completa" in (docs / "resumen.md").read_text(encoding="utf-8")
    entry = json.loads((run_dir / "eval_history.json").read_text(encoding="utf-8"))[-1]
    assert entry == result["entry"] and entry["status"] == STATUS and entry["api_calls"] == 0
    shas = {s["file"]: s["sha256"] for s in entry["sheets"]}
    for kind in (review.IND4, review.IND5):
        path = review.sheet_path(sheets, "r1", kind)
        assert shas[path.name] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert entry["started"] <= entry["finished"]


def test_a_second_integration_changes_only_the_history(run, tmp_path):
    for kind in (review.IND4, review.IND5):
        _fill(review.sheet_path(run["sheets"], "r1", kind), kind, lambda i: "si" if kind is review.IND4 else "no")
    integrate_review(run["run"], run["sheets"], tmp_path / "docs")
    before = _hashes(run["run"])
    integrate_review(run["run"], run["sheets"], tmp_path / "docs")
    after = _hashes(run["run"])
    assert {p for p in after if before[p] != after[p]} == {"eval_history.json"}
    assert len(json.loads((run["run"] / "eval_history.json").read_text(encoding="utf-8"))) == 3  # eval + 2


def test_incomplete_or_wrong_review_writes_nothing(run, tmp_path):
    sheet4 = review.sheet_path(run["sheets"], "r1", review.IND4)
    before = _hashes(run["run"])
    with pytest.raises(IntegrationError, match="no está completa"):
        integrate_review(run["run"], run["sheets"], tmp_path / "docs")
    _fill(sheet4, review.IND4, lambda i: "no")
    columns, rows = review.read_sheet(sheet4)
    rows[0][review.OBSERVATION] = ""  # «no» without an observation
    with sheet4.open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=columns)
        w.writeheader()
        w.writerows(rows)
    with pytest.raises(IntegrationError, match="hojas con errores"):
        integrate_review(run["run"], run["sheets"], tmp_path / "docs", allow_incomplete=True)
    assert _hashes(run["run"]) == before and not (tmp_path / "docs").exists()


def test_allow_incomplete_records_the_state(run, tmp_path):
    entry = integrate_review(run["run"], run["sheets"], tmp_path / "docs", allow_incomplete=True)["entry"]
    assert entry["review"]["indicator4"].startswith("revisión incompleta: 0 de ")
    ind4 = json.loads((run["run"] / "results" / "results.json").read_text(encoding="utf-8"))["tables"]["indicator4"][0]
    assert ind4["manual_ok_pct"] == "sin dato disponible"


def test_fake_results_are_never_integrated(tmp_path, monkeypatch):
    _guard(monkeypatch)
    (tmp_path / "r" / "results_FAKE").mkdir(parents=True)
    with pytest.raises(IntegrationError, match="FAKE"):
        integrate_review(tmp_path / "r", tmp_path / "sheets", tmp_path / "docs")


def test_cli_command(run, tmp_path, monkeypatch):
    monkeypatch.setattr("aem.cli.RUNS_DIR", run["run"].parent)
    monkeypatch.setattr("aem.cli.REVIEW_SHEETS_DIR", run["sheets"])
    monkeypatch.setattr("aem.cli.RESULTS_DOCS_DIR", tmp_path / "docs")
    res = CliRunner().invoke(cli.app, ["integrate-review", "--run-id", "r1"])
    assert res.exit_code != 0 and "no está completa" in res.output
    res = CliRunner().invoke(cli.app, ["integrate-review", "--run-id", "r1", "--allow-incomplete"])
    assert res.exit_code == 0 and "0 llamadas a la API" in res.output


@pytest.mark.skipif(not (MAIN_RUN / "results" / "results.json").exists(), reason="sin la corrida 2026-10-18-main")
def test_main_run_copy_keeps_everything_else_identical(tmp_path, monkeypatch):
    """On a temporary copy of the real run and its sheets: only the review tables, results.md and the history
    change; indicators 1, 2, 3 and 5, the sensitivity, provenance.json and every per-run file stay identical."""
    _guard(monkeypatch)
    run_dir = tmp_path / "runs" / MAIN_RUN.name
    shutil.copytree(MAIN_RUN, run_dir, ignore=shutil.ignore_patterns("report.html"))
    sheets = tmp_path / "sheets"
    shutil.copytree(cli.REVIEW_SHEETS_DIR, sheets)
    before = _hashes(run_dir)
    old_md = (run_dir / "results" / "results.md").read_text(encoding="utf-8")
    from eval.report import build_report

    build_report(run_dir, tmp_path / "docs_before", sheets)
    integrate_review(run_dir, sheets, tmp_path / "docs", allow_incomplete=True)
    after = _hashes(run_dir)
    changed = {p for p in after if before.get(p) != after[p]}
    assert changed <= WRITTEN and not any(p.startswith(("results/sensitivity", "results/provenance")) for p in changed)
    assert set(before) <= set(after) and set(after) - set(before) <= {"results/indicator5_manual.csv"}
    new_md = (run_dir / "results" / "results.md").read_text(encoding="utf-8")
    section = lambda md: md.split("## Corridas", 1)[1].split("## Indicador 4", 1)[0]  # runs, indicators 1-3
    assert section(new_md) == section(old_md)
    # the charts of indicators 1 and 3 come out the same as before the integration (same machine: PNG bytes
    # depend on the installed fonts)
    for name in ("indicador1_precision.png", "indicador1_exhaustividad.png", "indicador3_persistencia.png"):
        assert (tmp_path / "docs" / name).read_bytes() == (tmp_path / "docs_before" / name).read_bytes()
