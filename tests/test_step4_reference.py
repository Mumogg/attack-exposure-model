import pytest

from aem.boundaries import find_evaluative, load_patterns, violations
from aem.config import PREVALENCE_FILE
from aem.models import ReferenceInfo
from aem.step4_reference import (
    NO_PREVALENCE, NO_SUMMARY, SummaryOutcome, build_reference, clean_description, load_prevalence,
)


@pytest.fixture(scope="module")
def patterns():
    return load_patterns()


@pytest.mark.parametrize("text", [
    "This should be patched", "Es una técnica crítica", "high priority", "Se recomienda aplicar M1030",
    "We recommend MFA", "urgente", "Urgent action", "debería bloquearse", "critical systems", "la prioridad es",
    "act immediately",
])
def test_patterns_catch_evaluative_language(patterns, text):
    assert find_evaluative(text, patterns)


@pytest.mark.parametrize("text", [
    "Adversaries may exploit a weakness in an Internet-facing host.",
    "Los adversarios pueden usar RDP para moverse lateralmente.",
])
def test_patterns_ignore_neutral_text(patterns, text):
    assert find_evaluative(text, patterns) == []


def test_violation_only_if_absent_from_source(patterns):
    assert violations("Targets critical systems.", "Adversaries target critical systems.", patterns) == []
    assert violations("This is critical.", "Adversaries target hosts.", patterns)


def test_clean_description():
    raw = ("Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to log in. "
           "(Citation: Alperovitch Malware)(Citation: Other 2020) Done.")
    assert clean_description(raw) == "Adversaries may use Valid Accounts to log in. Done."


def test_prevalence_template_is_empty_and_has_header():
    assert PREVALENCE_FILE.read_text(encoding="utf-8").splitlines()[0] == "technique_id,rank,source_note"
    assert load_prevalence(PREVALENCE_FILE) == {}


def test_prevalence_parses_rows(tmp_path):
    p = tmp_path / "p.csv"
    p.write_text("technique_id,rank,source_note\nT1059.001,2,tabla p. 10\nT1190,5,\n", encoding="utf-8")
    prev = load_prevalence(p)
    assert prev["T1059.001"] == "Red Canary 2026: puesto 2 (tabla p. 10)"
    assert prev["T1190"] == "Red Canary 2026: puesto 5"


def test_prevalence_rejects_bad_rank(tmp_path):
    p = tmp_path / "p.csv"
    p.write_text("technique_id,rank,source_note\nT1190,primero,\n", encoding="utf-8")
    with pytest.raises(ValueError, match="T1190"):
        load_prevalence(p)


class FakeSummarizer:
    def __init__(self, texts):
        self.texts = texts
        self.seen = []

    def summarize(self, technique_id, description):
        self.seen.append((technique_id, description))
        text = self.texts.get(technique_id)
        return SummaryOutcome(text=text, raw=text, meta={"fake": True}, error=None if text else "fallo simulado")


def test_build_reference_fields(mini_attack, patterns):
    summ = FakeSummarizer({"T1190": "Adversaries exploit an Internet-facing host.",
                           "T1021.001": "Adversaries log in over RDP."})
    refs, log = build_reference(["T1190", "T1021.001"], mini_attack, {"T1190": "Red Canary 2026: puesto 5"},
                                summ, patterns)
    r = {x.technique_id: x for x in refs}
    assert r["T1190"].summary == "Adversaries exploit an Internet-facing host."
    assert r["T1190"].source_link == "https://attack.mitre.org/techniques/T1190/"
    assert r["T1190"].mitigations == ["M1030 Network Segmentation"]
    assert r["T1190"].groups == ["Fictional Group A"]
    assert r["T1190"].prevalence == "Red Canary 2026: puesto 5"
    assert r["T1021.001"].prevalence == NO_PREVALENCE == "sin dato disponible"
    assert r["T1021.001"].data_sources == ["Logon Session Creation", "Network Connection Creation"]
    # the LLM receives the cleaned description, never the raw one with citations
    assert "(Citation" not in summ.seen[0][1] and "](" not in summ.seen[0][1]
    assert [e.status for e in log] == ["ok", "ok"]


def test_llm_failure_keeps_link(mini_attack, patterns):
    refs, log = build_reference(["T1059"], mini_attack, {}, FakeSummarizer({}), patterns)
    assert refs[0].summary == NO_SUMMARY == "resumen no disponible"
    assert refs[0].source_link == "https://attack.mitre.org/techniques/T1059/"
    assert log[0].status == "llm_failed"


def test_evaluative_summary_is_discarded(mini_attack, patterns):
    summ = FakeSummarizer({"T1190": "Organizations should urgently patch this."})
    refs, log = build_reference(["T1190"], mini_attack, {}, summ, patterns)
    assert refs[0].summary == NO_SUMMARY
    assert log[0].status == "boundary_violation" and log[0].violations
    assert log[0].raw_summary == "Organizations should urgently patch this."


def test_reference_info_has_no_evaluative_fields():
    assert set(ReferenceInfo.model_fields) == {
        "technique_id", "summary", "source_link", "mitigations", "data_sources", "groups", "prevalence"}


def test_llm_summarizer_success_and_failure(tmp_path):
    from aem.config import Settings
    from aem.llm import GeminiClient, LLMCache, TransportError
    from aem.step4_reference import LLMSummarizer
    from fakes import FakeClock, FakeTransport

    clock = FakeClock()
    t = FakeTransport([{"summary": "Adversaries log in over RDP."}, TransportError(400, "bad")])
    client = GeminiClient(Settings("k", "gemini-3.8-flash", "gemini-3.5-flash-lite", 600, 0), LLMCache(tmp_path),
                          transport=t, sleep=clock.sleep, clock=clock.now)
    s = LLMSummarizer(client, max_sentences=3)
    ok = s.summarize("T1021.001", "Adversaries may use RDP to log into a computer.")
    assert ok.text == "Adversaries log in over RDP." and ok.meta["purpose"] == "step4_summary[T1021.001]"
    prompt = t.calls[0]["prompt"]
    assert "Adversaries may use RDP" in prompt and "3" in prompt and "do not add" in prompt.lower()
    bad = s.summarize("T1190", "Other description.")
    assert bad.text is None and "400" in bad.error


def test_quota_error_in_a_summary_stops_instead_of_degrading(tmp_path):
    """D-74: a daily-quota 429 must stop the run, not become «resumen no disponible»."""
    import pytest

    from aem.config import Settings
    from aem.llm import DailyQuotaExhausted, GeminiClient, LLMCache, TransportError
    from aem.step4_reference import LLMSummarizer
    from fakes import FakeClock, FakeTransport

    body = {"error": {"code": 429, "status": "RESOURCE_EXHAUSTED", "message": "quota", "details": [
        {"@type": "type.googleapis.com/google.rpc.QuotaFailure",
         "violations": [{"quotaId": "GenerateRequestsPerDayPerProjectPerModel-FreeTier", "quotaValue": "20"}]}]}}
    clock = FakeClock()
    client = GeminiClient(Settings("k", "gemini-3.8-flash", "gemini-3.5-flash-lite", 600, 3), LLMCache(tmp_path),
                          transport=FakeTransport([TransportError(429, "q", body)]), sleep=clock.sleep,
                          clock=clock.now)
    with pytest.raises(DailyQuotaExhausted):
        LLMSummarizer(client).summarize("T1190", "Adversaries may exploit a public-facing application.")
