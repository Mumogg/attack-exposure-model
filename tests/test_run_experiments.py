import csv
import json

import pytest

from aem.boundaries import load_patterns
from aem.config import SCENARIOS_FILE, SSVC_TREE_FILE, ModelConfig, Settings
from aem.llm import CacheMiss, GeminiClient, LLMCache, TransportError
from aem.pipeline import PipelineContext
from aem.reports import ReferenceRow
from aem.scenarios import load_scenarios, write_reference_csv
from aem.step3_prioritize import load_tree
from eval.run_experiments import run_experiment
from fakes import FakeClock, as_real_transport
from helpers import make_org
from test_pipeline import RoutingTransport

ORIG = ("The actors exploited a public-facing VPN appliance from 45.61.136[.]10. "
        "They then used cmd.exe to run commands.")
MUT = ("The actors exploited a public-facing VPN appliance from 198.51.100[.]7. "
       "They then used cmd.exe to run commands.")
EXTRACTION = {"techniques": [
    {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application",
     "evidence_quote": "exploited a public-facing VPN appliance"},
    {"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter", "evidence_quote": "used cmd.exe"},
]}


@pytest.fixture
def setup(tmp_path, mini_attack):
    scenarios = {k: v.relocated(tmp_path / "data") for k, v in load_scenarios(SCENARIOS_FILE).items()}
    g = scenarios["gunra"]
    g.stripped.parent.mkdir(parents=True)
    g.stripped.write_text(ORIG, encoding="utf-8")
    g.variant.write_text(MUT, encoding="utf-8")
    g.anon.write_text(MUT.replace("The actors", "The ActorX actors"), encoding="utf-8")
    write_reference_csv(g.reference, [ReferenceRow("T1190", "Exploit Public-Facing Application", "Initial Access"),
                                      ReferenceRow("T1059.003", "Windows Command Shell", "Execution")], mini_attack)
    for other in ("interlock", "akira"):  # references exist, texts do not
        write_reference_csv(scenarios[other].reference, [ReferenceRow("T1190", "x", "Initial Access")], mini_attack)
    org = make_org(detections=[("T1190", 2, []), ("T1059.003", 5, ["Process Creation"])],
                   entries=[("T1190", "web")],
                   coverage_design=[{"technique_id": "T1190", "intended": "parcial"},
                                    {"technique_id": "T1059.003", "intended": "cubierta"}],
                   known_iocs=[{"type": "ipv4", "value": "45.61.136.10", "scenario": "gunra"}])

    def ctx(transport=None, demo=False, real=True):
        """`real=True` wraps the fake in a genuine GenaiTransport object, so results count as real."""
        clock = FakeClock()
        if transport is not None and real:
            transport = as_real_transport(transport)
        client = GeminiClient(Settings(None if demo else "k", "gemini-3.8-flash", "gemini-3.5-flash-lite", 600, 0),
                              LLMCache(tmp_path / "cache"), demo=demo, transport=transport,
                              sleep=clock.sleep, clock=clock.now, private_cache=LLMCache(tmp_path / "private"))
        return PipelineContext(attack=mini_attack, org=org, client=client, model_cfg=ModelConfig(),
                               tree=load_tree(SSVC_TREE_FILE), prevalence={}, patterns=load_patterns())

    return {"scenarios": scenarios, "ctx": ctx, "run": tmp_path / "runs" / "r1", "sheets": tmp_path / "sheets"}


def read_csv(path):
    with path.open(encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def test_full_experiment(setup):
    t = RoutingTransport(extraction=EXTRACTION)
    res = run_experiment(setup["ctx"](t), setup["scenarios"], setup["run"], setup["sheets"], replicates=2)
    assert set(res["skipped"]) == {f"{s}: {v}" for s in ("akira", "interlock") for v in ("orig", "mut", "anon")}
    # 3 versions x 2 replicates extraction calls + 2 summaries (cached per technique)
    assert len(t.calls) == 6 + 2
    out = setup["run"] / "gunra" / "orig" / "r0"
    assert (out / "gunra_aa26-222a_stripped_exposure.csv").exists() and (out / "global_review.json").exists()

    results = setup["run"] / "results"
    i1 = {(r["scenario"], r["version"], r["level"]): r for r in read_csv(results / "indicator1.csv")}
    exact = i1[("gunra", "orig", "exact")]
    assert float(exact["precision_mean_valid"]) == pytest.approx(50.0) and float(exact["recall_mean_valid"]) == pytest.approx(50.0)
    assert float(exact["precision_sd_valid"]) == 0.0 and exact["runs_valid"] == "2"
    parent = i1[("gunra", "orig", "parent")]
    assert float(parent["precision_mean_valid"]) == pytest.approx(100.0)
    assert i1[("interlock", "orig", "exact")]["precision_mean_valid"] == "sin dato disponible"

    i2 = {r["scenario"]: r for r in read_csv(results / "indicator2.csv")}
    assert float(i2["gunra"]["accuracy"]) == 100.0

    i3 = {(r["scenario"], r["approach"]): r for r in read_csv(results / "indicator3.csv")}
    assert float(i3[("gunra", "modelo")]["orig_mean_valid"]) == 100.0  # T1190 is the only gap and is found
    assert float(i3[("gunra", "modelo")]["mut_mean_valid"]) == 100.0
    assert float(i3[("gunra", "tradicional")]["orig_mean_valid"]) == 100.0
    assert float(i3[("gunra", "tradicional")]["mut_mean_valid"]) == 0.0

    sheet = read_csv(setup["sheets"] / "r1_indicator4_summaries.csv")
    assert {r["technique_id"] for r in sheet} == {"T1190", "T1059"}
    assert set(sheet[0]) >= {"source_description", "summary", "auto_check", "ok (si/no)", "observación"}
    assert all(r["ok (si/no)"] == "" for r in sheet)
    assert (setup["sheets"] / "r1_indicator5_sample.csv").exists()

    md = (results / "results.md").read_text(encoding="utf-8")
    for k in ("Indicador 1", "Indicador 2", "Indicador 3", "Indicador 4", "Indicador 5"):
        assert k in md
    assert json.loads((results / "results.json").read_text(encoding="utf-8"))["replicates"] == 2


def test_demo_reproduces_from_cache(setup):
    run_experiment(setup["ctx"](RoutingTransport(extraction=EXTRACTION)), setup["scenarios"], setup["run"],
                   setup["sheets"], replicates=2)
    first = (setup["run"] / "results" / "indicator1.csv").read_text(encoding="utf-8")
    again = setup["run"].parent / "r2"
    run_experiment(setup["ctx"](demo=True), setup["scenarios"], again, setup["sheets"], replicates=2)
    assert (again / "results" / "indicator1.csv").read_text(encoding="utf-8") == first


def test_demo_without_cache_stops_clearly(setup):
    with pytest.raises(CacheMiss):
        run_experiment(setup["ctx"](demo=True), setup["scenarios"], setup["run"], setup["sheets"], replicates=1)


def test_invalid_llm_output_is_recorded_as_failed_run(setup):
    class Bad(RoutingTransport):
        def generate(self, model, prompt, schema, temperature):
            if "extracting MITRE ATT&CK" in prompt:
                self.calls.append(prompt)
                return "not json", model
            return super().generate(model, prompt, schema, temperature)

    res = run_experiment(setup["ctx"](Bad()), setup["scenarios"], setup["run"], setup["sheets"], replicates=1)
    runs = [r for r in res["runs"] if r["scenario"] == "gunra"]
    assert {r["status"] for r in runs} == {"error"}
    i1 = {(r["scenario"], r["version"], r["level"]): r for r in read_csv(setup["run"] / "results" / "indicator1.csv")}
    assert i1[("gunra", "orig", "exact")]["failed_runs"] == "1"


def test_partial_failures_are_reported_both_ways(setup):
    """D-67: one of two orig runs fails → counts, reason, valid-only mean and failed-as-0 mean."""
    class SecondFails(RoutingTransport):
        n = 0

        def generate(self, model, prompt, schema, temperature):
            if "extracting MITRE ATT&CK" in prompt:
                self.n += 1
                if self.n == 2:
                    return "not json", model
            return super().generate(model, prompt, schema, temperature)

    run_experiment(setup["ctx"](SecondFails(extraction=EXTRACTION)), setup["scenarios"], setup["run"],
                   setup["sheets"], replicates=2)
    results = setup["run"] / "results"
    status = {(r["scenario"], r["version"]): r for r in read_csv(results / "runs.csv")}
    g = status[("gunra", "orig")]
    assert (g["runs_total"], g["runs_valid"], g["failed_runs"]) == ("2", "1", "1")
    assert g["failure_reasons"].startswith("r1: ")
    assert status[("gunra", "mut")]["failure_reasons"] == "ninguna"

    i1 = {(r["scenario"], r["version"], r["level"]): r for r in read_csv(results / "indicator1.csv")}
    e = i1[("gunra", "orig", "exact")]
    assert e["failed_runs"] == "1" and float(e["precision_mean_valid"]) == 50.0
    assert float(e["precision_mean_fail0"]) == 25.0 and float(e["recall_mean_fail0"]) == 25.0
    i3 = {(r["scenario"], r["approach"]): r for r in read_csv(results / "indicator3.csv")}
    m = i3[("gunra", "modelo")]
    assert float(m["orig_mean_valid"]) == 100.0 and float(m["orig_mean_fail0"]) == 50.0
    assert m["failed_runs"] == "orig 1, mut 0, anon 0"
    i5 = [r for r in read_csv(results / "indicator5.csv") if r["scenario"] == "gunra" and r["version"] == "orig"]
    assert i5[0]["failed_runs"] == "1" and "violations_mean_fail0" in i5[0]
    md = (results / "results.md").read_text(encoding="utf-8")
    assert "failed_runs" in md and "r1: " in md


def test_api_error_stops_the_experiment(setup):
    class Down(RoutingTransport):
        def generate(self, model, prompt, schema, temperature):
            raise TransportError(400, "bad request")

    from aem.llm import ApiError
    with pytest.raises(ApiError):
        run_experiment(setup["ctx"](Down()), setup["scenarios"], setup["run"], setup["sheets"], replicates=1)


AKIRA = "Akira actors exploited a public-facing VPN appliance and then used cmd.exe to run commands."


def _with_akira(setup):
    a = setup["scenarios"]["akira"]
    a.text.write_text("Raw Akira report placed by hand.", encoding="utf-8")
    a.stripped.write_text(AKIRA, encoding="utf-8")
    a.variant.write_text(AKIRA, encoding="utf-8")


def test_copyrighted_scenario_stays_private(setup, tmp_path):
    _with_akira(setup)
    run_experiment(setup["ctx"](RoutingTransport(extraction=EXTRACTION)), setup["scenarios"], setup["run"],
                   setup["sheets"], replicates=1)
    assert (setup["run"] / "private" / "akira" / "orig" / "r0" / "run_record.json").exists()
    assert not (setup["run"] / "akira").exists()
    public = read_csv(setup["sheets"] / "r1_indicator5_sample.csv")
    assert public and all(r["scenario"] != "akira" for r in public)
    private = read_csv(setup["sheets"] / "private" / "r1_indicator5_sample_private.csv")
    assert private and all(r["scenario"] == "akira" for r in private)
    # nothing in the public cache was built from the Akira text
    for f in (tmp_path / "cache").rglob("*.json"):
        assert "Akira actors" not in f.read_text(encoding="utf-8")


def test_demo_without_private_cache_skips_copyrighted_scenario(setup):
    run_experiment(setup["ctx"](RoutingTransport(extraction=EXTRACTION)), setup["scenarios"], setup["run"],
                   setup["sheets"], replicates=1)  # public cache only: Akira text absent
    _with_akira(setup)
    res = run_experiment(setup["ctx"](demo=True), setup["scenarios"], setup["run"].parent / "d", setup["sheets"],
                         replicates=1)
    assert any(s.startswith("akira: orig") and "caché privada" in s for s in res["skipped"])


# --- D-71: results from a fake LLM never pass as real -------------------------------------------


def test_fake_llm_results_never_reach_results_dir(setup):
    run_experiment(setup["ctx"](RoutingTransport(extraction=EXTRACTION), real=False), setup["scenarios"],
                   setup["run"], setup["sheets"], replicates=1)
    assert not (setup["run"] / "results").exists()
    fake = setup["run"] / "results_FAKE"
    assert all(p.name.startswith("FAKE_") for p in fake.iterdir())
    rows = read_csv(fake / "FAKE_indicator1.csv")
    assert rows and all(r["llm_source"].startswith("FAKE") for r in rows)
    assert (fake / "FAKE_results.md").read_text(encoding="utf-8").startswith("# FAKE")
    assert (setup["sheets"] / "FAKE_r1_indicator4_summaries.csv").exists()
    assert not (setup["sheets"] / "r1_indicator4_summaries.csv").exists()
    out = setup["run"] / "gunra" / "orig" / "r0"
    assert sorted(p.name for p in out.iterdir()) == ["FAKE_global_review.json",
                                                     "FAKE_gunra_aa26-222a_stripped_exposure.csv",
                                                     "FAKE_run_record.json"]


def test_real_results_carry_model_date_and_prompt_hash(setup):
    import hashlib
    from importlib import resources
    run_experiment(setup["ctx"](RoutingTransport(extraction=EXTRACTION)), setup["scenarios"], setup["run"],
                   setup["sheets"], replicates=1)
    extract_sha = hashlib.sha256(resources.files("aem.prompts").joinpath("extract_v1.txt").read_bytes()).hexdigest()
    for table in (setup["run"] / "results").glob("*.csv"):
        rows = read_csv(table)
        for r in rows:
            assert r["llm_source"] == "gemini-api" and r["model"] == "gemini-3.8-flash"
            assert r["model_version"] == "gemini-3.8-flash" and len(r["run_date"]) == 10
            assert f"extract_v1.txt={extract_sha}" in r["prompt_templates_sha256"]
    md = (setup["run"] / "results" / "results.md").read_text(encoding="utf-8")
    assert "FAKE" not in md and extract_sha in md


def test_fail0_is_the_primary_mean_for_indicators_1_and_3(setup):
    """D-67 (confirmed): `_fail0` columns come first in indicators 1 and 3; indicator 5 warns in its title."""
    run_experiment(setup["ctx"](RoutingTransport(extraction=EXTRACTION)), setup["scenarios"], setup["run"],
                   setup["sheets"], replicates=1)
    results = setup["run"] / "results"
    cols1 = list(read_csv(results / "indicator1.csv")[0])
    assert cols1.index("precision_mean_fail0") < cols1.index("precision_mean_valid")
    cols3 = list(read_csv(results / "indicator3.csv")[0])
    assert cols3.index("orig_mean_fail0") < cols3.index("orig_mean_valid")
    md = (results / "results.md").read_text(encoding="utf-8")
    assert "media principal: `_fail0`" in md
    i5_title = next(line for line in md.splitlines() if line.startswith("## Indicador 5"))
    assert "favorece al modelo" in i5_title


def test_anon_version_is_in_every_llm_table(setup):
    """D-72: anon rows in indicators 1 and 5, anon columns in indicator 3 (model and traditional)."""
    run_experiment(setup["ctx"](RoutingTransport(extraction=EXTRACTION)), setup["scenarios"], setup["run"],
                   setup["sheets"], replicates=1)
    results = setup["run"] / "results"
    assert {r["version"] for r in read_csv(results / "indicator1.csv") if r["scenario"] == "gunra"} == \
        {"orig", "mut", "anon"}
    assert {r["version"] for r in read_csv(results / "indicator5.csv") if r["scenario"] == "gunra"} == \
        {"orig", "mut", "anon"}
    assert {(r["scenario"], r["version"]) for r in read_csv(results / "runs.csv")} >= {("gunra", "anon")}
    i3 = {(r["scenario"], r["approach"]): r for r in read_csv(results / "indicator3.csv")}
    m, t = i3[("gunra", "modelo")], i3[("gunra", "tradicional")]
    assert float(m["anon_mean_fail0"]) == 100.0 and float(m["persistence_anon_over_orig_fail0"]) == 1.0
    assert m["failed_runs"] == "orig 0, mut 0, anon 0"
    assert float(t["anon_mean_fail0"]) == 0.0 and t["ioc_matches"] == "orig 1, mut 0, anon 0"


# --- D-73: copyrighted scenario without local text → partial run, completed later from the cache ---------


def test_missing_copyrighted_text_marks_run_partial(setup):
    a = setup["scenarios"]["akira"]
    a.stripped.write_text(AKIRA, encoding="utf-8")  # stale prepared text without the raw report: still omitted
    t = RoutingTransport(extraction=EXTRACTION)
    res = run_experiment(setup["ctx"](t), setup["scenarios"], setup["run"], setup["sheets"], replicates=1)
    assert res["partial"] and {"scenario": "akira", "reason": "sin texto local"} in res["omitted"]
    assert not any("Akira actors" in p for p in t.calls)
    results = setup["run"] / "results"
    meta = json.loads((results / "results.json").read_text(encoding="utf-8"))
    assert meta["partial"] is True
    assert {"scenario": "akira", "reason": "sin texto local"} in meta["escenarios_omitidos"]
    for table in results.glob("*.csv"):
        for r in read_csv(table):
            assert r["resultado_parcial"] == "sí" and "akira (sin texto local)" in r["escenarios_omitidos"]
    md = (results / "results.md").read_text(encoding="utf-8")
    assert "RESULTADO PARCIAL: faltan escenarios" in md and "akira (sin texto local)" in md
    history = json.loads((setup["run"] / "eval_history.json").read_text(encoding="utf-8"))
    assert len(history) == 1 and history[0]["partial"] is True


def test_partial_run_is_completed_later_from_the_cache(setup):
    """Same run id after placing the Akira text: Gunra comes from the cache; only Akira reaches the API."""
    first = RoutingTransport(extraction=EXTRACTION)
    run_experiment(setup["ctx"](first), setup["scenarios"], setup["run"], setup["sheets"], replicates=2)
    assert first.calls and not any("Akira actors" in p for p in first.calls)
    gunra_before = [r for r in read_csv(setup["run"] / "results" / "indicator1.csv") if r["scenario"] == "gunra"]

    _with_akira(setup)
    a = setup["scenarios"]["akira"]
    for v in ("mut", "anon"):  # distinct texts per version, as make-variants produces
        a.report_for(v).write_text(f"{AKIRA} ({v})", encoding="utf-8")
    second = RoutingTransport(extraction=EXTRACTION)
    res = run_experiment(setup["ctx"](second), setup["scenarios"], setup["run"], setup["sheets"], replicates=2)

    # 3 versions x 2 replicates of Akira extraction; summaries of the same techniques are already cached
    assert len(second.calls) == 3 * 2
    assert all("Akira actors" in p for p in second.calls)
    assert not any(ORIG in p or MUT in p for p in second.calls)
    assert {(r["scenario"], r["status"]) for r in res["runs"]} == {("gunra", "ok"), ("akira", "ok")}
    assert not any(o["scenario"] == "akira" for o in res["omitted"])

    gunra_after = [r for r in read_csv(setup["run"] / "results" / "indicator1.csv") if r["scenario"] == "gunra"]
    strip = lambda rows: [{k: v for k, v in r.items() if k not in ("resultado_parcial", "escenarios_omitidos")}
                          for r in rows]
    assert strip(gunra_after) == strip(gunra_before)
    history = json.loads((setup["run"] / "eval_history.json").read_text(encoding="utf-8"))
    assert [any(o["scenario"] == "akira" for o in h["escenarios_omitidos"]) for h in history] == [True, False]


def test_daily_quota_in_a_summary_stops_the_experiment(setup):
    """D-74: no run is written with «resumen no disponible» because of an exhausted quota."""
    from aem.llm import DailyQuotaExhausted

    body = {"error": {"code": 429, "status": "RESOURCE_EXHAUSTED", "message": "quota", "details": [
        {"@type": "type.googleapis.com/google.rpc.QuotaFailure",
         "violations": [{"quotaId": "GenerateRequestsPerDayPerProjectPerModel-FreeTier", "quotaValue": "20"}]}]}}

    class QuotaOnSummary(RoutingTransport):
        def generate(self, model, prompt, schema, temperature):
            if "extracting MITRE ATT&CK" not in prompt:
                self.calls.append(prompt)
                raise TransportError(429, "q", body)
            return super().generate(model, prompt, schema, temperature)

    with pytest.raises(DailyQuotaExhausted):
        run_experiment(setup["ctx"](QuotaOnSummary(extraction=EXTRACTION)), setup["scenarios"], setup["run"],
                       setup["sheets"], replicates=1)
    assert not (setup["run"] / "gunra" / "orig" / "r0" / "gunra_aa26-222a_stripped_exposure.csv").exists()
    assert not (setup["run"] / "results").exists()
