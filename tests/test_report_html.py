"""`aem report --html`: self-contained page, public and private versions. Written only to temporary folders."""

from __future__ import annotations

import json
import re

import pytest
from typer.testing import CliRunner

from aem import cli
from aem.config import DATA_DIR, REPO_ROOT, RUNS_DIR, SCENARIOS_FILE, load_model_config
from aem.repo_check import copied_windows, ioc_values
from aem.scenarios import load_scenarios
from eval.baseline_ioc import extract_iocs
from eval.report_html import LeakError, build_html, leak_findings, visible_text
from eval.run_experiments import run_experiment
from test_pipeline import RoutingTransport
from test_run_experiments import EXTRACTION, _with_akira, setup  # noqa: F401  (fixture)

SENTINEL = "SENTINELA privada de la cita de Akira"
DFIR_TEXT = DATA_DIR / "reports" / "akira_dfir_2026.txt"
MAIN_RUN = RUNS_DIR / "2026-10-18-main"


@pytest.fixture
def run(setup):  # noqa: F811
    _with_akira(setup)
    run_experiment(setup["ctx"](RoutingTransport(extraction=EXTRACTION)), setup["scenarios"], setup["run"],
                   setup["sheets"], replicates=2)
    for rec_path in (setup["run"] / "private" / "akira").rglob("run_record.json"):
        rec = json.loads(rec_path.read_text(encoding="utf-8"))
        for t in rec["extraction"]["extracted_raw"]:
            t["evidence_quote"] = SENTINEL
        rec_path.write_text(json.dumps(rec), encoding="utf-8")
    return setup


def _build(run, tmp_path, **kw):
    out = build_html(run["run"], tmp_path / "out" / "report.html", run["sheets"], run["scenarios"], **kw)
    return out.read_text(encoding="utf-8")


def test_minimal_structure(run, tmp_path):
    html = _build(run, tmp_path)
    assert html.startswith("<!doctype html>")
    assert '<meta name="viewport"' in html and '<html lang="en" data-lang="en">' in html
    for section in ("indicators", "comparison", "distribution", "techniques", "limits"):
        assert f'<section id="{section}">' in html
    for i in range(1, 6):
        assert f"Indicator {i}" in html and f"Indicador {i}" in html
    assert 'id="lang"' in html and '<span lang="es">' in html
    assert all(f'data-filter="{f}"' in html for f in ("scenario", "version", "tactics", "actions"))
    assert "RESULTADO PARCIAL" in html  # interlock has no text in the fixture
    assert "sin dato disponible" in html  # manual review not done
    assert "_fail0" in html and "_valid" in html
    assert "<svg" in html and "<title>" in html  # charts with an accessible name


def test_only_attack_urls_and_nothing_external(run, tmp_path):
    html = _build(run, tmp_path)
    hosts = set(re.findall(r"(?:https?:)?//([A-Za-z0-9.-]+\.[A-Za-z]{2,})", html))
    assert hosts == {"attack.mitre.org"}
    assert not re.search(r"<script[^>]+src=|<link[^>]+href=|@import|url\(\s*['\"]?http", html)


def test_no_absolute_paths_or_keys(run, tmp_path):
    html = _build(run, tmp_path)
    assert str(REPO_ROOT) not in html and str(tmp_path) not in html
    assert "AIza" not in html and "private/" not in html


def test_copyrighted_quotes_only_in_the_private_page(run, tmp_path):
    public = _build(run, tmp_path)
    assert SENTINEL not in public and 'data-scenario="akira"' in public
    assert "used cmd.exe" in public  # public quotes (gunra) are shown
    private = build_html(run["run"], tmp_path / "priv" / "report_full.html", run["sheets"], run["scenarios"],
                         private=True).read_text(encoding="utf-8")
    assert SENTINEL in private and "PRIVADA" in private


def test_word_window_and_ioc_check_stop_the_public_page(run, tmp_path):
    with pytest.raises(LeakError, match="frase del reporte"):
        _build(run, tmp_path, dfir_text="Shared: the design of the model, the technical decisions of this text.")
    with pytest.raises(LeakError, match="IoC"):
        _build(run, tmp_path, iocs=["cmd.exe"])
    assert not (tmp_path / "out" / "report.html").exists()


def test_copied_windows_ignore_case_and_punctuation():
    src = "One two three, four FIVE six seven eight nine."
    assert copied_windows("x one TWO three four five six seven eight y", src) == [
        "one two three four five six seven eight"]
    assert copied_windows("one two three four five six seven", src) == []


def test_private_needs_html():
    res = CliRunner().invoke(cli.app, ["report", "--run-id", "x", "--private"])
    assert res.exit_code != 0 and "--html" in res.output


@pytest.mark.skipif(not DFIR_TEXT.exists() or not (MAIN_RUN / "results" / "results.json").exists(),
                    reason="requiere la copia local del reporte de DFIR y la corrida 2026-10-18-main")
def test_main_run_public_page_has_no_dfir_text_or_iocs(tmp_path):
    """Same sources as check-repo (local DFIR copy and its IoC values), 8-word windows; output in a temp folder."""
    text = DFIR_TEXT.read_text(encoding="utf-8")
    iocs = ioc_values(extract_iocs(text, load_model_config().ioc))
    out = build_html(MAIN_RUN, tmp_path / "report.html", cli.REVIEW_SHEETS_DIR, load_scenarios(SCENARIOS_FILE),
                     dfir_text=text, iocs=iocs)
    html = out.read_text(encoding="utf-8")
    assert leak_findings(html, text, iocs) == []
    assert copied_windows(visible_text(html), text) == []
    assert str(REPO_ROOT) not in html


def test_provenance_block_in_the_page(run, tmp_path):
    from eval import provenance

    (run["run"] / "results" / "provenance.json").unlink()  # aem eval wrote one
    assert "sin dato disponible" in _build(run, tmp_path).split('class="prov"', 1)[1][:400]
    data = provenance.live(REPO_ROOT, json.loads((run["run"] / "results" / "results.json").read_text(encoding="utf-8")))
    provenance.write(run["run"] / "results", data)
    html = _build(run, tmp_path)
    block = html.split('class="prov"', 1)[1].split("</details>", 1)[0]
    assert "Provenance" in block and "Procedencia" in block and data["code"]["commit"][:12] in block
    assert str(REPO_ROOT) not in html
