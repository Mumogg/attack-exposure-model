import csv
import json

import pytest

from aem.boundaries import load_patterns, violations
from aem.config import SSVC_TREE_FILE, ModelConfig, Settings
from aem.llm import GeminiClient, LLMCache
from aem.pipeline import EmptyExtraction, PipelineContext, run_pipeline, write_outputs
from aem.step3_prioritize import load_tree
from fakes import FakeClock
from helpers import make_org

REPORT = ("The actors exploited a public-facing VPN appliance to gain access. "
          "They then used cmd.exe to run commands.\n\nLater they moved laterally over RDP to other hosts.")

EXTRACTION = {"techniques": [
    {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application",
     "evidence_quote": "exploited a public-facing VPN appliance"},
    {"technique_id": "T1059.003", "technique_name": "Windows Command Shell", "evidence_quote": "used cmd.exe"},
    {"technique_id": "T1021.001", "technique_name": "Remote Desktop Protocol", "evidence_quote": "over RDP"},
    {"technique_id": "T9001", "technique_name": "Old", "evidence_quote": "nothing"},
]}


class RoutingTransport:
    """Fake Gemini: answers by prompt type, so call order does not matter."""

    def __init__(self, extraction=EXTRACTION, summary="Adversaries perform this behavior."):
        self.extraction = extraction
        self.summary = summary
        self.calls = []

    def get_model(self, model):
        pass

    def generate(self, model, prompt, schema, temperature):
        self.calls.append(prompt)
        body = self.extraction if "extracting MITRE ATT&CK" in prompt else {"summary": self.summary}
        return json.dumps(body), model


def mk_ctx(tmp_path, mini_attack, transport=None, demo=False):
    clock = FakeClock()
    settings = Settings(None if demo else "k", "gemini-3.8-flash", "gemini-3.5-flash-lite", 600, 0)
    client = GeminiClient(settings, LLMCache(tmp_path / "cache"), demo=demo, transport=transport,
                          sleep=clock.sleep, clock=clock.now, private_cache=LLMCache(tmp_path / "private"))
    org = make_org(detections=[("T1190", 2, []), ("T1059.003", 5, ["Process Creation"])],
                   entries=[("T1190", "web")])
    return PipelineContext(attack=mini_attack, org=org, client=client, model_cfg=ModelConfig(),
                           tree=load_tree(SSVC_TREE_FILE), prevalence={}, patterns=load_patterns())


def test_end_to_end_auto(tmp_path, mini_attack):
    ctx = mk_ctx(tmp_path, mini_attack, RoutingTransport())
    res = run_pipeline(REPORT, ctx, analyst_mode="auto")
    assert [t.technique_id for t in res.extraction.extracted_raw] == ["T1190", "T1059.003", "T1021.001", "T9001"]
    assert [t.technique_id for t in res.extraction.extracted_validated] == ["T1190", "T1059.003", "T1021.001"]
    assert {(r["technique_id"], r["action"]) for r in res.rows} == {
        ("T1190", "Act"), ("T1059.003", "Track"), ("T1021.001", "Attend")}
    assert [r["technique_id"] for r in res.rows] == ["T1190", "T1021.001", "T1059.003"]
    assert res.global_review.answer is None


def test_no_urgency_text_in_csv(tmp_path, mini_attack):
    """The LLM produced urgency text: it must not reach the CSV."""
    ctx = mk_ctx(tmp_path, mini_attack, RoutingTransport(summary="You should urgently patch this critical flaw."))
    res = run_pipeline(REPORT, ctx, analyst_mode="auto")
    patterns = load_patterns()
    for row in res.rows:
        assert row["summary"] == "resumen no disponible"
        assert not violations(row["summary"], "", patterns)
    assert {s.status for s in res.summaries} == {"boundary_violation"}


def test_summaries_are_cached_per_technique(tmp_path, mini_attack):
    t = RoutingTransport()
    ctx = mk_ctx(tmp_path, mini_attack, t)
    run_pipeline(REPORT, ctx, analyst_mode="auto", replicate=0)
    first = len(t.calls)
    run_pipeline(REPORT, ctx, analyst_mode="auto", replicate=1)
    # replicate 1 repeats only the extraction call; summaries come from the cache
    assert len(t.calls) == first + 1


def test_empty_extraction_fails_clearly(tmp_path, mini_attack):
    ctx = mk_ctx(tmp_path, mini_attack, RoutingTransport(extraction={"techniques": []}))
    with pytest.raises(EmptyExtraction) as exc:
        run_pipeline(REPORT, ctx, analyst_mode="auto")
    assert exc.value.extraction.extracted_raw == []


def test_demo_uses_only_cache(tmp_path, mini_attack):
    run_pipeline(REPORT, mk_ctx(tmp_path, mini_attack, RoutingTransport()), analyst_mode="auto")
    res = run_pipeline(REPORT, mk_ctx(tmp_path, mini_attack, transport=None, demo=True), analyst_mode="auto")
    assert len(res.rows) == 3
    assert all(c["from_cache"] for c in res.extraction.llm_calls)


def test_write_outputs(tmp_path, mini_attack):
    res = run_pipeline(REPORT, mk_ctx(tmp_path, mini_attack, RoutingTransport()), analyst_mode="auto")
    paths = write_outputs(res, tmp_path / "out", stem="gunra")
    assert res.meta["fake"] is True and res.meta["llm_sources"] == ["fake:RoutingTransport"]
    assert paths["csv"].name == "FAKE_gunra_exposure.csv"  # fake LLM → every output file says so (D-71)
    assert paths["global_review"].name == "FAKE_global_review.json"
    with paths["csv"].open(encoding="utf-8-sig", newline="") as fh:
        assert len(list(csv.DictReader(fh))) == 3
    record = json.loads(paths["record"].read_text(encoding="utf-8"))
    assert {"extraction", "coverage", "prioritization", "summaries", "meta"} <= set(record)
    assert record["meta"]["temperature"] == 0 and record["meta"]["model"] == "gemini-3.8-flash"
    assert record["meta"]["attack_version"] == mini_attack.version
    assert len(record["extraction"]["extracted_raw"]) == 4


def test_private_report_extraction_goes_to_private_cache(tmp_path, mini_attack):
    res = run_pipeline(REPORT, mk_ctx(tmp_path, mini_attack, RoutingTransport()), analyst_mode="auto", private=True)
    assert res.meta["private"] is True
    private = [json.loads(p.read_text(encoding="utf-8")) for p in (tmp_path / "private").rglob("*.json")]
    public = [json.loads(p.read_text(encoding="utf-8")) for p in (tmp_path / "cache").rglob("*.json")]
    assert {e["meta"]["purpose"].split("[")[0] for e in private} == {"step1_extract"}
    assert {e["meta"]["purpose"].split("[")[0] for e in public} == {"step4_summary"}
    assert not any(REPORT[:40] in e["prompt"] for e in public)


def test_real_outputs_have_no_fake_prefix(tmp_path, mini_attack):
    from fakes import as_real_transport
    res = run_pipeline(REPORT, mk_ctx(tmp_path, mini_attack, as_real_transport(RoutingTransport())), analyst_mode="auto")
    assert res.meta["fake"] is False and res.meta["llm_sources"] == ["gemini-api"]
    assert write_outputs(res, tmp_path / "out", stem="gunra")["csv"].name == "gunra_exposure.csv"
