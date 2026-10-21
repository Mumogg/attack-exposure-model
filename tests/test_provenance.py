"""results/provenance.json: written by `aem eval`, or rebuilt for an older run (never guessed)."""

from __future__ import annotations

import json
import os
import platform
import subprocess

import pytest
from typer.testing import CliRunner

from aem import cli
from aem.config import REPO_ROOT, RUNS_DIR
from eval import provenance
from eval.integrate_review import STATUS as INTEGRATION_STATUS
from eval.provenance import FROZEN_FILES, NOT_RECORDED, reconstruct, summary_lines
from eval.run_experiments import run_experiment
from test_pipeline import RoutingTransport
from test_run_experiments import EXTRACTION, setup  # noqa: F401  (fixture)

MAIN_RUN = RUNS_DIR / "2026-10-18-main"


def test_eval_writes_provenance_next_to_results(setup):  # noqa: F811
    run_experiment(setup["ctx"](RoutingTransport(extraction=EXTRACTION)), setup["scenarios"], setup["run"],
                   setup["sheets"], replicates=1)
    data = json.loads((setup["run"] / "results" / "provenance.json").read_text(encoding="utf-8"))
    assert data["reconstructed"] is False and data["written_by"] == "aem eval"
    head = subprocess.run(["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"], capture_output=True, text=True).stdout
    assert data["code"]["commit"] == head.strip()
    dirty = data["code"]["uncommitted_changes_in_frozen_files"]
    assert isinstance(dirty, list) and all((REPO_ROOT / f).exists() for f in dirty)  # full paths, nothing cut
    assert data["model"]["name"] == "gemini-3.8-flash"
    assert data["python"] == platform.python_version()
    assert set(data["dependencies"]) == set(provenance.MAIN_DEPENDENCIES)
    assert set(data["frozen_files_sha256"]) == set(FROZEN_FILES)
    assert data["prompt_templates_sha256"].startswith("extract_v1.txt=")
    assert str(REPO_ROOT) not in json.dumps(data)


def test_fake_run_provenance_is_prefixed(setup):  # noqa: F811
    run_experiment(setup["ctx"](RoutingTransport(extraction=EXTRACTION), real=False), setup["scenarios"],
                   setup["run"], setup["sheets"], replicates=1)
    assert (setup["run"] / "results_FAKE" / "FAKE_provenance.json").exists()
    assert not (setup["run"] / "results").exists()


# --- reconstruction on a synthetic repository -----------------------------------------------------


def _git(repo, *args, date=None):
    env = dict(os.environ, GIT_AUTHOR_DATE=date or "", GIT_COMMITTER_DATE=date or "") if date else None
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, env=env)


def _commit(repo, files: dict, msg: str, date: str):
    for path, text in files.items():
        (repo / path).parent.mkdir(parents=True, exist_ok=True)
        (repo / path).write_text(text, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", msg, date=date)


@pytest.fixture
def old_run(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "t")
    _commit(repo, {"src/aem/x.py": "a = 1\n", "data/model_config.yaml": "k: 1\n",
                   "src/aem/prompts/extract_v1.txt": "E", "src/aem/prompts/summary_v1.txt": "S"},
            "feat: code", "2099-01-01T10:00:00+00:00")
    _commit(repo, {"README.md": "docs\n"}, "docs: only docs", "2099-01-01T10:30:00+00:00")
    run = repo / "runs" / "r1"
    results = {"run_id": "r1", "model": "m-1", "model_versions": ["m-1-001"], "temperature": 0,
               "attack_version": "19.2", "prompt_templates_sha256": "extract_v1.txt=x; summary_v1.txt=y",
               "tables": {}, "runs": []}
    history = [{"started": "2099-01-01T11:00:00+00:00", "finished": "2099-01-01T11:05:00+00:00",
                "status": "completa", "runs_completed": 2}]
    # code committed after the evaluation but before the results: the run may have used it uncommitted
    _commit(repo, {"src/aem/x.py": "a = 2\n"}, "feat: later code", "2099-01-01T11:10:00+00:00")
    _commit(repo, {"runs/r1/results/results.json": json.dumps(results), "runs/r1/eval_history.json": json.dumps(history),
                   "runs/r1/alpha/orig/r0/run_record.json": "{}"}, "eval: results", "2099-01-01T11:20:00+00:00")
    return repo, run


def test_reconstruction_lists_commits_and_never_guesses(old_run):
    repo, run = old_run
    data = reconstruct(run, repo)
    assert data["reconstructed"] is True and data["code"]["commit"] == NOT_RECORDED
    inv = data["code"]["invocations"][0]
    log = subprocess.run(["git", "-C", str(repo), "log", "--format=%H %s"], capture_output=True, text=True).stdout
    sha = {subject: h for h, subject in (line.split(" ", 1) for line in log.splitlines())}
    assert inv["head_commit_before_start"]["commit"] == sha["docs: only docs"]
    assert [c["commit"] for c in inv["code_commits_after_start_until_results_commit"]] == [sha["feat: later code"]]
    assert inv["results_committed_in"] == sha["eval: results"] and inv["working_tree"] == NOT_RECORDED
    assert data["code"]["per_run_outputs"]["alpha"]["versioned_in_commit"] == sha["eval: results"]
    assert data["python"] == NOT_RECORDED and data["dependencies"] == NOT_RECORDED
    assert data["model"] == {"name": "m-1", "versions_reported_by_api": ["m-1-001"], "temperature": 0}
    assert all(k in data["sources"] for k in ("python, dependencies", "frozen_files_sha256"))
    assert data["frozen_files_sha256"]["data/model_config.yaml"]["at_results_commit"] != NOT_RECORDED
    assert data["frozen_files_sha256"]["data/ssvc_tree.yaml"]["at_results_commit"] == NOT_RECORDED  # not in repo
    assert dict(summary_lines(data))["Python"] == NOT_RECORDED


def test_cli_rebuilds_once_and_refuses_to_overwrite(tmp_path, monkeypatch):
    run = tmp_path / "runs" / "r9" / "results"
    run.mkdir(parents=True)
    (run / "provenance.json").write_text("{}", encoding="utf-8")
    (run / "results.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr("aem.cli.RUNS_DIR", tmp_path / "runs")
    res = CliRunner().invoke(cli.app, ["provenance", "--run-id", "r9"])
    assert res.exit_code != 0 and "no se reemplaza" in res.output


@pytest.mark.skipif(not (MAIN_RUN / "results" / "provenance.json").exists(), reason="sin provenance.json publicado")
def test_main_run_provenance_is_reconstructed_and_consistent():
    data = json.loads((MAIN_RUN / "results" / "provenance.json").read_text(encoding="utf-8"))
    results = json.loads((MAIN_RUN / "results" / "results.json").read_text(encoding="utf-8"))
    assert data["reconstructed"] is True and data["code"]["commit"] == NOT_RECORDED
    assert data["model"]["name"] == results["model"]
    assert data["prompt_templates_sha256"] == results["prompt_templates_sha256"]
    assert data["python"] == NOT_RECORDED
    # integrate-review appends to eval_history.json but is not an `aem eval` invocation
    history = json.loads((MAIN_RUN / "eval_history.json").read_text(encoding="utf-8"))
    evals = [e for e in history if e.get("status") != INTEGRATION_STATUS]
    assert len(data["code"]["invocations"]) == len(evals)


def test_frozen_files_changed_only_in_comments_are_told_apart(old_run):
    repo, run = old_run
    data = reconstruct(run, repo)
    assert provenance.frozen_file_status(data, repo) == []
    (repo / "data/model_config.yaml").write_text("# header comment\nk: 1  # same value\n", encoding="utf-8")
    assert provenance.frozen_file_status(data, repo) == [("data/model_config.yaml", "comments_only")]
    assert "data/model_config.yaml (solo comentarios; datos idénticos)" in dict(summary_lines(data, repo))[
        "Archivos congelados"]
    (repo / "data/model_config.yaml").write_text("# header comment\nk: 2\n", encoding="utf-8")
    assert provenance.frozen_file_status(data, repo) == [("data/model_config.yaml", "data_changed")]
    assert "datos cambiados" in dict(summary_lines(data, repo))["Archivos congelados"]


def test_summary_shows_the_model_once_when_the_api_reports_the_same_name():
    base = {"reconstructed": False, "code": {"commit": "a" * 40}, "attack": {}}
    same = provenance.summary(dict(base, model={"name": "m-1", "versions_reported_by_api": ["m-1"]}), REPO_ROOT)
    other = provenance.summary(dict(base, model={"name": "m-1", "versions_reported_by_api": ["m-1-001"]}), REPO_ROOT)
    assert same["model"] == "m-1" and other["model"] == "m-1 (m-1-001)"
