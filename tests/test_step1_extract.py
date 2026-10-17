import json

import pytest

from aem.config import ExtractionConfig, Settings
from aem.llm import GeminiClient, LLMCache, LLMError
from aem.step1_extract import (
    EXTRACTION_SCHEMA, AutoReviewer, InteractiveReviewer, chunk_text, extract, parse_extraction, review,
    validate_candidates,
)
from fakes import FakeClock, FakeTransport

REPORT = ("The actors exploited a public-facing VPN appliance to gain access. "
          "They then used cmd.exe to run commands.\n\nLater they moved laterally over RDP to other hosts.")


def mk_client(tmp_path, responses):
    clock = FakeClock()
    s = Settings("k", "gemini-3.8-flash", "gemini-3.5-flash-lite", 600, 2)
    return GeminiClient(s, LLMCache(tmp_path), transport=FakeTransport(responses), sleep=clock.sleep, clock=clock.now)


def resp(*items):
    return {"techniques": [dict(technique_id=t, technique_name=n, evidence_quote=q) for t, n, q in items]}


def test_schema_has_only_three_fields():
    item = EXTRACTION_SCHEMA["properties"]["techniques"]["items"]
    assert set(item["properties"]) == {"technique_id", "technique_name", "evidence_quote"}
    assert set(item["required"]) == {"technique_id", "technique_name", "evidence_quote"}


def test_parse_flags_extra_fields_without_keeping_them():
    data = {"techniques": [{"technique_id": " T1190 ", "technique_name": "x", "evidence_quote": "q",
                            "priority": "high"}], "summary": "urgent"}
    items, extra = parse_extraction(data)
    assert items[0].technique_id == "T1190" and not hasattr(items[0], "priority")
    assert sorted(extra) == ["summary", "techniques[0].priority"]


def test_parse_rejects_wrong_shape():
    with pytest.raises(LLMError):
        parse_extraction({"items": []})


def test_chunking_disabled_below_threshold():
    assert chunk_text("abc", ExtractionConfig()) == ["abc"]


def test_chunking_with_overlap_on_paragraphs():
    paras = [f"P{i} " + "x" * 90 for i in range(10)]
    text = "\n\n".join(paras)
    cfg = ExtractionConfig(chunk_max_chars=200, chunk_size_chars=300, chunk_overlap_chars=100)
    chunks = chunk_text(text, cfg)
    assert len(chunks) > 1 and all(len(c) <= 300 for c in chunks)
    for p in paras:  # nothing lost
        assert any(p in c for c in chunks)
    assert chunks[1].startswith(chunks[0].split("\n\n")[-1])  # overlap carries the last paragraph


def test_prompt_forbids_evaluation_and_contains_report(tmp_path):
    client = mk_client(tmp_path, [resp()])
    extract(REPORT, client, ExtractionConfig(), "19.2")
    prompt = client.transport.calls[0]["prompt"]
    assert REPORT in prompt and "19.2" in prompt
    low = prompt.lower()
    assert "do not infer" in low and "do not evaluate" in low and "recommend" in low


def test_extract_merges_chunks_without_duplicates(tmp_path):
    text = "A" * 150 + "\n\n" + "B" * 150
    cfg = ExtractionConfig(chunk_max_chars=100, chunk_size_chars=160, chunk_overlap_chars=0)
    client = mk_client(tmp_path, [resp(("T1190", "Exploit", "AAA")),
                                  resp(("T1190", "Exploit", "BBB"), ("T1021.001", "RDP", "BBB"))])
    run = extract(text, client, cfg, "19.2", replicate=3)
    assert [t.technique_id for t in run.extracted_raw] == ["T1190", "T1021.001"]
    assert run.extracted_raw[0].evidence_quote == "AAA"  # first quote kept
    assert run.chunks == 2 and len(run.llm_calls) == 2 and run.llm_calls[0]["replicate"] == 3


def test_validation_marks_needs_review(mini_attack):
    from aem.models import ExtractedTechnique as E

    raw = [E(technique_id="T1190", technique_name="Exploit Public-Facing Application",
             evidence_quote="exploited a public-facing VPN appliance"),
           E(technique_id="T9001", technique_name="Old", evidence_quote="cmd.exe"),
           E(technique_id="T1234", technique_name="Nope", evidence_quote="invented quote"),
           E(technique_id="TA0001", technique_name="Initial Access", evidence_quote="x")]
    v = {c.technique_id: c for c in validate_candidates(raw, mini_attack, REPORT)}
    assert not v["T1190"].needs_review and v["T1190"].quote_found
    assert v["T1190"].official_name == "Exploit Public-Facing Application"
    assert v["T9001"].needs_review and v["T9001"].status == "revoked" and v["T9001"].replacement == "T1059"
    assert v["T1234"].needs_review and v["T1234"].status == "not_found" and not v["T1234"].quote_found
    assert v["TA0001"].needs_review and v["TA0001"].status == "malformed"


def test_quote_matching_normalizes_whitespace_and_quotes(mini_attack):
    from aem.models import ExtractedTechnique as E

    report = "They ran “cmd.exe /c  whoami”\nacross hosts."
    [c] = validate_candidates([E(technique_id="T1059", technique_name="x",
                                 evidence_quote='ran "cmd.exe /c whoami" across')], mini_attack, report)
    assert c.quote_found


def test_auto_review_keeps_valid_and_logs_exclusions(mini_attack):
    from aem.models import ExtractedTechnique as E

    cands = validate_candidates([E(technique_id="T1190", technique_name="a", evidence_quote="q"),
                                 E(technique_id="T1234", technique_name="b", evidence_quote="q")], mini_attack, "q")
    validated, actions = review(cands, AutoReviewer(), mini_attack)
    assert [t.technique_id for t in validated] == ["T1190"]
    assert {(a.action, a.technique_id) for a in actions} == {("accept", "T1190"), ("exclude_needs_review", "T1234")}


class Scripted:
    def __init__(self, answers):
        self.answers = list(answers)

    def __call__(self, prompt, default=None, choices=None):
        a = self.answers.pop(0)
        return default if a == "" else a


def test_interactive_review_replace_remove_add(mini_attack):
    from aem.models import ExtractedTechnique as E

    cands = validate_candidates([E(technique_id="T1190", technique_name="a", evidence_quote="q"),
                                 E(technique_id="T1059.003", technique_name="b", evidence_quote="q"),
                                 E(technique_id="T9001", technique_name="c", evidence_quote="q")], mini_attack, "q")
    # T9001 (revoked): use replacement; remove T1059.003; add T1234 (invalid, rejected) and T1021.001; "" ends
    ask = Scripted(["reemplazar", "T1059.003", "T1234, T1021.001", ""])
    validated, actions = review(cands, InteractiveReviewer(ask=ask, console=None), mini_attack)
    assert [t.technique_id for t in validated] == ["T1190", "T1059", "T1021.001"]
    kinds = [(a.action, a.technique_id) for a in actions]
    assert ("replace", "T9001") in kinds and ("remove", "T1059.003") in kinds and ("add", "T1021.001") in kinds
    assert ("reject_add_invalid", "T1234") in kinds
