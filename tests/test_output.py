import csv
import json

import pytest

from aem.boundaries import find_evaluative, load_patterns
from aem.models import GlobalReview, PrioritizedTechnique, ReferenceInfo
from aem.output import CSV_COLUMNS, build_rows, write_csv, write_global_review

FIXED = ("technique_id", "technique_name", "tactics", "coverage_validated", "criticality", "exposure", "action",
         "summary", "source_link", "mitigations", "data_sources", "groups", "prevalence")


def pt(tid, name, tactics, action, cov="parcial", crit="media", exposure=None):
    return PrioritizedTechnique(technique_id=tid, technique_name=name, tactics=tactics, coverage_original=cov,
                                coverage_validated=cov, asset_id="ws", criticality=crit, exposure=exposure,
                                action=action, context_source="analyst_context")


def ref(tid, **kw):
    base = dict(technique_id=tid, summary=f"Summary of {tid}.", source_link=f"https://attack.mitre.org/techniques/{tid}/",
                mitigations=["M1030 Network Segmentation", "M1032 Multi-factor Authentication"],
                data_sources=["Process Creation"], groups=["Fictional Group A"], prevalence="sin dato disponible")
    base.update(kw)
    return ReferenceInfo(**base)


@pytest.fixture
def items():
    return [
        pt("T1021.001", "Remote Desktop Protocol", ["lateral-movement"], "Track"),
        pt("T1059.003", "Windows Command Shell", ["execution"], "Act"),
        pt("T1190", "Exploit Public-Facing Application", ["initial-access"], "Act", exposure="internet"),
        pt("T1059", "Command and Scripting Interpreter", ["execution"], "Track*"),
    ]


def test_columns_are_fixed_and_ordered():
    assert CSV_COLUMNS == FIXED


def test_no_new_evaluative_column():
    """Fails if an evaluative column is ever added to the CSV (only `action`, from the analyst, is allowed)."""
    patterns = load_patterns()
    extra_words = ("priority", "prioridad", "risk", "riesgo", "urgency", "urgencia", "severity", "severidad",
                   "score", "relevance", "relevancia", "recommend", "confidence")
    for col in CSV_COLUMNS:
        if col == "action":
            continue
        assert not find_evaluative(col.replace("_", " "), patterns), col
        assert not any(w in col for w in extra_words), col


def test_rows_ordered_by_action_then_matrix(mini_attack, items):
    refs = [ref(i.technique_id) for i in items]
    rows = build_rows(items, refs, mini_attack)
    assert [r["technique_id"] for r in rows] == ["T1190", "T1059.003", "T1059", "T1021.001"]
    assert [r["action"] for r in rows] == ["Act", "Act", "Track*", "Track"]


def test_row_content(mini_attack, items):
    rows = {r["technique_id"]: r for r in build_rows(items, [ref(i.technique_id) for i in items], mini_attack)}
    r = rows["T1190"]
    assert r["tactics"] == "Initial Access"
    assert r["exposure"] == "internet"
    assert r["mitigations"] == "M1030 Network Segmentation; M1032 Multi-factor Authentication"
    assert r["source_link"] == "https://attack.mitre.org/techniques/T1190/"
    assert rows["T1059"]["exposure"] == ""  # only Initial Access carries exposure


def test_empty_lists_are_explicit(mini_attack):
    rows = build_rows([pt("T1059", "x", ["execution"], "Track")], [ref("T1059", groups=[], mitigations=[])],
                      mini_attack)
    assert rows[0]["groups"] == "sin dato disponible"
    assert rows[0]["mitigations"] == "sin dato disponible"


def test_missing_reference_is_an_error(mini_attack, items):
    with pytest.raises(KeyError, match="T1059"):
        build_rows(items, [ref("T1190"), ref("T1021.001"), ref("T1059.003")], mini_attack)


def test_csv_is_utf8_with_bom(tmp_path, mini_attack, items):
    rows = build_rows(items, [ref(i.technique_id, summary="Ataque vía «RDP» — ñ") for i in items], mini_attack)
    path = tmp_path / "out.csv"
    write_csv(path, rows)
    raw = path.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")
    with path.open(encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        assert tuple(reader.fieldnames) == FIXED
        data = list(reader)
    assert len(data) == 4 and data[0]["summary"] == "Ataque vía «RDP» — ñ"


def test_global_review_file(tmp_path):
    review = GlobalReview(question="¿…?", answer=None, mode="auto", techniques_shown=[], timestamp="2026-10-17T00:00:00+00:00")
    path = tmp_path / "global_review.json"
    write_global_review(path, review)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["answer"] is None and data["mode"] == "auto"
