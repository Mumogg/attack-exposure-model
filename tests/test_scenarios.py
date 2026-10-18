import csv

import pytest

from aem.config import DATA_DIR, SCENARIOS_FILE
from aem.reports import ReferenceRow
from aem.scenarios import (
    REFERENCE_COLUMNS, extract_plain_reference, load_reference, load_scenarios, prepare_cisa, prepare_plain,
    write_reference_csv,
)
from test_reports import HTML


def test_catalog_has_three_scenarios():
    sc = load_scenarios(SCENARIOS_FILE)
    assert list(sc) == ["gunra", "interlock", "akira"]
    assert sc["gunra"].source == "cisa" and sc["gunra"].advisory == "AA26-222A"
    assert sc["interlock"].advisory == "AA25-203A"
    assert sc["akira"].source == "dfir" and sc["akira"].text.name == "akira_dfir_2026.txt"
    for s in sc.values():
        assert s.stripped.name.endswith("_stripped.txt")
        assert s.variant.name.endswith("_mut_stripped.txt")


def test_reference_csv_validates_against_attack(tmp_path, mini_attack):
    rows = [ReferenceRow("T1190", "Exploit Public-Facing Application", "Initial Access"),
            ReferenceRow("T9001", "Old Revoked Technique", "Execution"),
            ReferenceRow("T1078", "Valid Accounts", "Persistence"),
            ReferenceRow("T1078", "Valid Accounts", "Privilege Escalation")]
    path = tmp_path / "ref.csv"
    write_reference_csv(path, rows, mini_attack)
    with path.open(encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        assert tuple(reader.fieldnames) == REFERENCE_COLUMNS
        data = list(reader)
    by = {r["technique_id"]: r for r in data}
    assert len(data) == 3  # duplicates merged
    assert by["T1078"]["tactic"] == "Persistence; Privilege Escalation"
    assert by["T1190"]["valid_in_v19_2"] == "si" and by["T1190"]["v19_2_status"] == "valid"
    assert by["T9001"]["valid_in_v19_2"] == "no" and by["T9001"]["v19_2_status"] == "revoked"
    ref = load_reference(path)
    assert [r.technique_id for r in ref if r.valid] == ["T1190", "T1078"]


def test_committed_reference_mappings_are_valid():
    for name, expected in (("gunra", 36), ("interlock", 25), ("akira", 38)):
        ref = load_reference(DATA_DIR / "reference_mappings" / f"{name}.csv")
        assert len(ref) == expected, name
        assert all(r.valid for r in ref), name


def test_prepare_cisa_writes_text_stripped_and_reference(tmp_path, mini_attack):
    sc = load_scenarios(SCENARIOS_FILE)["gunra"].relocated(tmp_path)
    log = prepare_cisa(sc, HTML, mini_attack)
    assert sc.text.exists() and sc.stripped.exists() and sc.reference.exists()
    assert "[T1190]" in sc.text.read_text(encoding="utf-8")
    assert "T1190" not in sc.stripped.read_text(encoding="utf-8")
    assert log["tactic_rows_excluded"] == [{"id": "TA0009", "name": "Collection", "table": "Initial Access"}]


AKIRA_LIKE = "Intro\n\nThe actor used T1059.001 here.\n\nMITRE ATT&CK\nCreate Account - T1136\nPowerShell - T1059.001\n"


def test_extract_plain_reference():
    assert extract_plain_reference(AKIRA_LIKE, "MITRE ATT&CK", []) == ["T1136", "T1059.001"]


def test_prepare_plain(tmp_path):
    sc = load_scenarios(SCENARIOS_FILE)["akira"].relocated(tmp_path)
    sc.text.parent.mkdir(parents=True, exist_ok=True)
    sc.text.write_text(AKIRA_LIKE, encoding="utf-8")
    log = prepare_plain(sc, expected_ids=["T1136", "T1059.001"])
    out = sc.stripped.read_text(encoding="utf-8")
    assert "Create Account" not in out and "T1059" not in out
    assert log["reference_check"] == "coincide"


def test_prepare_plain_reports_mismatch(tmp_path):
    sc = load_scenarios(SCENARIOS_FILE)["akira"].relocated(tmp_path)
    sc.text.parent.mkdir(parents=True, exist_ok=True)
    sc.text.write_text(AKIRA_LIKE, encoding="utf-8")
    log = prepare_plain(sc, expected_ids=["T1136"])
    assert log["reference_check"].startswith("NO coincide")


def test_prepare_plain_missing_text(tmp_path):
    sc = load_scenarios(SCENARIOS_FILE)["akira"].relocated(tmp_path)
    with pytest.raises(FileNotFoundError, match="akira_dfir_2026.txt"):
        prepare_plain(sc, expected_ids=[])
