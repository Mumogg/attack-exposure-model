import pytest

from aem.config import CoverageConfig
from aem.step2_coverage import assess_coverage, classify_score
from helpers import make_org

CFG = CoverageConfig()


@pytest.mark.parametrize("score,expected", [
    (None, "sin cobertura"), (0, "sin cobertura"), (1, "parcial"), (2, "parcial"), (3, "parcial"),
    (4, "cubierta"), (5, "cubierta"),
])
def test_default_thresholds(score, expected):
    assert classify_score(score, CFG) == expected


def test_custom_thresholds():
    cfg = CoverageConfig(partial_min=2, covered_min=5)
    assert classify_score(1, cfg) == "sin cobertura"
    assert classify_score(4, cfg) == "parcial"
    assert classify_score(5, cfg) == "cubierta"


def test_assess_uses_own_entry_and_data_sources():
    org = make_org(detections=[("T1059.003", 4, ["Process Creation"])])
    [r] = assess_coverage(["T1059.003"], org, CFG)
    assert (r.coverage, r.score, r.basis, r.data_sources) == ("cubierta", 4, "own_entry", ["Process Creation"])


def test_missing_entry_is_no_coverage():
    [r] = assess_coverage(["T1486"], make_org(), CFG)
    assert (r.coverage, r.score, r.basis) == ("sin cobertura", None, "no_entry")


def test_subtechnique_does_not_inherit_parent_by_default():
    org = make_org(detections=[("T1021", 5, [])])
    [r] = assess_coverage(["T1021.001"], org, CFG)
    assert (r.coverage, r.basis, r.inherited_from) == ("sin cobertura", "no_entry", None)


def test_subtechnique_inherits_parent_only_when_configured():
    org = make_org(detections=[("T1021", 3, ["Logon Session"])])
    cfg = CoverageConfig(subtechnique_policy="inherit_parent")
    [r] = assess_coverage(["T1021.001"], org, cfg)
    assert (r.coverage, r.basis, r.inherited_from, r.score) == ("parcial", "inherited_parent", "T1021", 3)


def test_parent_never_aggregates_subtechniques():
    org = make_org(detections=[("T1021.001", 5, [])])
    for cfg in (CFG, CoverageConfig(subtechnique_policy="inherit_parent")):
        [r] = assess_coverage(["T1021"], org, cfg)
        assert r.coverage == "sin cobertura"


def test_deterministic_and_order_preserving():
    org = make_org(detections=[("T1059.003", 2, []), ("T1190", 0, [])])
    ids = ["T1190", "T1059.003", "T1486"]
    a = assess_coverage(ids, org, CFG)
    b = assess_coverage(ids, org, CFG)
    assert a == b
    assert [r.technique_id for r in a] == ids
    assert [r.coverage for r in a] == ["sin cobertura", "parcial", "sin cobertura"]


def test_duplicates_in_input_are_collapsed():
    assert len(assess_coverage(["T1190", "T1190"], make_org(), CFG)) == 1
