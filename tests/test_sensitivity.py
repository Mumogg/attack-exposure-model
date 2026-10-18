"""`aem sensitivity`: steps 2 and 3 and indicator 3 with other coverage parameters (no API)."""

from __future__ import annotations

import json
import shutil

import pytest

from aem.attack_data import AttackData
from aem.config import (
    ATTACK_FILE, ORG_FILE, RUNS_DIR, SCENARIOS_FILE, SSVC_TREE_FILE, CoverageConfig, load_model_config,
)
from aem.org import load_org
from aem.scenarios import load_scenarios
from aem.step3_prioritize import load_tree
from eval.run_experiments import NO_DATA, run_experiment
from eval.sensitivity import (
    HEADER, NO_RUN_RECORDS, SensitivityError, check_against_results, compute_sensitivity, load_runs, variants,
    write_sensitivity,
)
from test_pipeline import RoutingTransport
from test_run_experiments import EXTRACTION, setup  # noqa: F401  (fixture)

MAIN_RUN = RUNS_DIR / "2026-10-18-main"


def _model_rows(results: dict) -> dict:
    return {r["scenario"]: r for r in results["tables"]["indicator3"] if r["approach"] == "modelo"}


def test_variants_change_one_parameter_at_a_time():
    base = CoverageConfig()
    got = [(p, v) for p, v, _ in variants(base)]
    assert got == [("actual", "covered_min=4, partial_min=1, no_inherit"), ("covered_min", "3"), ("covered_min", "5"),
                   ("partial_min", "2"), ("subtechnique_policy", "inherit_parent")]
    for p, v, cfg in variants(base)[1:]:
        changed = {k for k, val in cfg.model_dump().items() if val != base.model_dump()[k]}
        assert changed == {p}


def test_current_row_equals_indicator3_exactly(setup):  # noqa: F811
    ctx = setup["ctx"](RoutingTransport(extraction=EXTRACTION))
    run_experiment(ctx, setup["scenarios"], setup["run"], setup["sheets"], replicates=2)
    loaded = load_runs(setup["run"], setup["scenarios"])
    rows = compute_sensitivity(loaded, setup["scenarios"], ctx.org, ctx.model_cfg, ctx.attack, ctx.tree)
    main = _model_rows(loaded["results"])
    current = [r for r in rows if r["parameter"] == "actual"]
    assert current
    for row in current:
        ref = main[row["scenario"]]
        assert row["gaps"] == ref["denominator_techniques"]
        for col in ref:
            if col in row and col != "scenario":
                assert row[col] == ref[col], col
        assert row["step3_action_changes_vs_current"] == 0
    assert check_against_results(rows, loaded["results"]) == []
    paths = write_sensitivity(setup["run"], rows, loaded, ctx.model_cfg)
    assert paths["markdown"].read_text(encoding="utf-8").startswith(f"# {HEADER}\n")
    assert {p.name for p in paths.values()} == {"sensitivity.csv", "sensitivity.json", "sensitivity.md"}
    assert paths["csv"].parent == setup["run"] / "results" / "sensitivity"
    assert json.loads(paths["json"].read_text(encoding="utf-8"))["note"] == HEADER


def test_main_results_are_not_touched(setup):  # noqa: F811
    ctx = setup["ctx"](RoutingTransport(extraction=EXTRACTION))
    run_experiment(ctx, setup["scenarios"], setup["run"], setup["sheets"], replicates=1)
    results = setup["run"] / "results"
    before = {p: p.read_bytes() for p in results.rglob("*") if p.is_file()}
    loaded = load_runs(setup["run"], setup["scenarios"])
    write_sensitivity(setup["run"], compute_sensitivity(loaded, setup["scenarios"], ctx.org, ctx.model_cfg,
                                                        ctx.attack, ctx.tree), loaded, ctx.model_cfg)
    assert all(p.read_bytes() == b for p, b in before.items())


def test_missing_run_records_give_gaps_only(setup):  # noqa: F811
    ctx = setup["ctx"](RoutingTransport(extraction=EXTRACTION))
    run_experiment(ctx, setup["scenarios"], setup["run"], setup["sheets"], replicates=1)
    shutil.rmtree(setup["run"] / "gunra")  # e.g. a copyrighted scenario on a clone without private/
    loaded = load_runs(setup["run"], setup["scenarios"])
    rows = compute_sensitivity(loaded, setup["scenarios"], ctx.org, ctx.model_cfg, ctx.attack, ctx.tree)
    gunra = [r for r in rows if r["scenario"] == "gunra"]
    assert gunra and all(r["failed_runs"] == NO_RUN_RECORDS and r["orig_mean_fail0"] == NO_DATA for r in gunra)
    assert all(isinstance(r["gaps"], int) for r in gunra)


def test_fake_or_missing_results_are_refused(setup):  # noqa: F811
    with pytest.raises(SensitivityError, match="no se calcula|results_FAKE"):
        load_runs(setup["run"], setup["scenarios"])
    ctx = setup["ctx"](RoutingTransport(extraction=EXTRACTION), real=False)
    run_experiment(ctx, setup["scenarios"], setup["run"], setup["sheets"], replicates=1)
    with pytest.raises(SensitivityError):
        load_runs(setup["run"], setup["scenarios"])


@pytest.mark.skipif(not ATTACK_FILE.exists() or not (MAIN_RUN / "results" / "results.json").exists(),
                    reason="requiere ATT&CK v19.2 (aem fetch-data) y la corrida 2026-10-18-main")
def test_main_run_current_row_equals_results_json():
    """On the published run: the current configuration reproduces indicator 3 and the stored step 3 actions."""
    scenarios = load_scenarios(SCENARIOS_FILE)
    loaded = load_runs(MAIN_RUN, scenarios)
    cfg = load_model_config()
    rows = compute_sensitivity(loaded, scenarios, load_org(ORG_FILE), cfg, AttackData.load(ATTACK_FILE),
                               load_tree(SSVC_TREE_FILE))
    assert check_against_results(rows, loaded["results"]) == []
    checked = [r for r in rows if r["parameter"] == "actual" and r["failed_runs"] != NO_RUN_RECORDS]
    assert {r["scenario"] for r in checked} >= {"gunra", "interlock"}
    main = _model_rows(loaded["results"])
    for row in checked:
        for col, value in main[row["scenario"]].items():
            if col in row and col != "scenario":
                assert row[col] == value
        stored = {}
        for version in loaded["scenarios"][row["scenario"]]["records"].values():
            for rec in version:
                for t in rec["prioritization"]:
                    stored[t["action"]] = stored.get(t["action"], 0) + 1
        assert {a: row[f"step3_{a}"] for a in stored} == stored
