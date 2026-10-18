import pytest

from aem.boundaries import load_patterns
from aem.config import CoverageConfig
from aem.models import SummaryRecord
from eval.metrics import (
    aggregate, boundary_violations_extraction, coverage_correctness, extraction_scores, model_persistence,
    summary_auto_check, traditional_persistence,
)
from helpers import make_org

REF = ["T1190", "T1059.003", "T1021.001", "T1486"]


def test_extraction_scores_exact_and_parent():
    raw = ["T1190", "T1059.001", "T1021.001", "T9999"]
    s = extraction_scores(raw, REF)
    assert s["exact"]["precision"] == pytest.approx(2 / 4)
    assert s["exact"]["recall"] == pytest.approx(2 / 4)
    assert s["exact"]["omitted"] == ["T1059.003", "T1486"]
    assert s["exact"]["erroneous"] == ["T1059.001", "T9999"]
    # parent level: T1059.001 counts as T1059 (correct parent)
    assert s["parent"]["precision"] == pytest.approx(3 / 4)
    assert s["parent"]["recall"] == pytest.approx(3 / 4)
    assert s["parent"]["omitted"] == ["T1486"]


def test_extraction_scores_empty_output():
    s = extraction_scores([], REF)
    assert s["exact"]["precision"] is None and s["exact"]["recall"] == 0.0


def test_duplicate_proposals_count_once():
    s = extraction_scores(["T1190", "T1190"], REF)
    assert s["exact"]["precision"] == 1.0


def test_aggregate_mean_sd():
    a = aggregate([0.5, 0.7, 0.6, None])
    assert a["n"] == 3 and a["mean"] == pytest.approx(0.6) and a["sd"] == pytest.approx(0.1)
    assert aggregate([None])["mean"] is None
    assert aggregate([0.4])["sd"] is None


def test_aggregate_with_failures_reports_valid_only_and_failed_as_zero():
    from eval.metrics import aggregate_with_failures
    a = aggregate_with_failures([0.5, 0.7, None], failed=1)
    assert a["valid"]["n"] == 2 and a["valid"]["mean"] == pytest.approx(0.6)
    assert a["fail0"]["n"] == 3 and a["fail0"]["mean"] == pytest.approx(0.4)
    assert aggregate_with_failures([], failed=2)["fail0"]["mean"] == 0.0
    assert aggregate_with_failures([], failed=0)["fail0"]["mean"] is None


def org_with(design, detections):
    return make_org(detections=detections, coverage_design=[dict(technique_id=t, intended=c) for t, c in design])


def test_coverage_correctness_matches_design():
    org = org_with([("T1190", "parcial"), ("T1486", "cubierta"), ("T1021.001", "sin cobertura")],
                   [("T1190", 2, []), ("T1486", 5, [])])
    r = coverage_correctness(["T1190", "T1486", "T1021.001"], org, CoverageConfig())
    assert r["accuracy"] == 1.0 and r["mismatches"] == []


def test_coverage_correctness_reports_bug_and_missing_design():
    org = org_with([("T1190", "cubierta")], [("T1190", 2, [])])
    r = coverage_correctness(["T1190", "T1486"], org, CoverageConfig())
    assert r["accuracy"] == 0.0
    assert {m["technique_id"] for m in r["mismatches"]} == {"T1190", "T1486"}


def test_model_persistence_uses_gap_techniques_only():
    gaps = ["T1190", "T1021.001"]  # T1059.003 covered -> not in the denominator
    assert model_persistence(["T1190", "T1059.003"], gaps) == pytest.approx(0.5)
    assert model_persistence([], gaps) == 0.0
    assert model_persistence(["T1190"], []) is None


def test_traditional_persistence():
    assert traditional_persistence(True, False) == {"orig": 1.0, "mut": 0.0, "ratio": 0.0}
    assert traditional_persistence(False, False)["ratio"] is None


def test_summary_auto_check():
    src = "Adversaries may use RDP (port 3389) to log in. Adversaries may move laterally."
    ok = summary_auto_check("Adversaries use RDP on port 3389 to log in.", src, max_sentences=3)
    assert ok["ok"] and ok["issues"] == []
    bad = summary_auto_check("Adversaries use T1021 and port 445. A. B. C.", src, max_sentences=3)
    assert not bad["ok"]
    assert any("T1021" in i for i in bad["issues"]) and any("445" in i for i in bad["issues"])
    assert any("oraciones" in i for i in bad["issues"])


def test_boundary_violations_extraction():
    patterns = load_patterns()
    report = "The actors targeted critical infrastructure using RDP."
    quotes = [("T1021.001", "Remote Desktop Protocol", "targeted critical infrastructure using RDP"),
              ("T1190", "Exploit", "This is urgent and should be patched")]
    v = boundary_violations_extraction(quotes, report, extra_fields=["techniques[0].priority"], patterns=patterns)
    assert v["extra_fields"] == 1
    assert v["evaluative_text"] == 2  # "urgent" and "should" are absent from the report; "critical" is present
    assert v["total"] == 3


def test_review_a3_abbreviations_are_not_sentence_ends():
    from eval.metrics import count_sentences
    assert count_sentences("Uses e.g. PowerShell. Stops U.S. hosts. Done v1.2 ok.") == 3


def test_review_a4_numbers_and_ids_are_compared_as_tokens():
    src = "In 2023 adversaries used T1059.001 and 1000 hosts."
    r = summary_auto_check("They used 3 tools and T1059.", src, max_sentences=3)
    assert "cifra ausente en la fuente: 3" in r["issues"] and "ID ausente en la fuente: T1059" in r["issues"]
    assert summary_auto_check("They hit 1,000 hosts.", src, max_sentences=3)["ok"]
