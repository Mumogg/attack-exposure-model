import pytest

from aem.attack_data import AttackData, IdStatus


def test_version_read_from_collection(mini_attack):
    assert mini_attack.version == "19.2"


def test_tactic_order_comes_from_matrix(mini_attack):
    assert mini_attack.tactic_order == ["initial-access", "execution", "lateral-movement"]
    assert mini_attack.tactic_names["lateral-movement"] == "Lateral Movement"


def test_lookup_active_technique(mini_attack):
    rec = mini_attack.get("T1021.001")
    assert rec.name == "Remote Desktop Protocol"
    assert rec.is_subtechnique and rec.parent_id == "T1021"
    assert rec.tactics == ("lateral-movement",)
    assert rec.url == "https://attack.mitre.org/techniques/T1021/001/"


def test_tactics_sorted_by_matrix_order(mini_attack):
    assert mini_attack.get("T1078").tactics == ("initial-access", "lateral-movement")


@pytest.mark.parametrize("tid,status", [
    ("T1190", IdStatus.VALID),
    ("T1059.003", IdStatus.VALID),
    ("T9001", IdStatus.REVOKED),
    ("T9002", IdStatus.DEPRECATED),
    ("T1234", IdStatus.NOT_FOUND),
    ("t1190", IdStatus.MALFORMED),
    ("T1190.1", IdStatus.MALFORMED),
    ("TA0001", IdStatus.MALFORMED),
])
def test_validate_id(mini_attack, tid, status):
    assert mini_attack.validate_id(tid).status is status


def test_revoked_reports_replacement(mini_attack):
    v = mini_attack.validate_id("T9001")
    assert v.replacement == "T1059"


def test_is_initial_access(mini_attack):
    assert mini_attack.is_initial_access("T1190")
    assert mini_attack.is_initial_access("T1078")
    assert not mini_attack.is_initial_access("T1059")


def test_first_tactic_index(mini_attack):
    assert mini_attack.first_tactic_index("T1078") == 0
    assert mini_attack.first_tactic_index("T1021.001") == 2


def test_reference_bundle_batch(mini_attack):
    refs = mini_attack.reference_bundle(["T1190", "T1021.001", "T1059"])
    assert refs["T1190"].mitigations == [("M1030", "Network Segmentation")]
    assert refs["T1190"].groups == ["Fictional Group A"]  # revoked group excluded
    assert refs["T1021.001"].mitigations == [("M1026", "Privileged Account Management"),
                                              ("M1030", "Network Segmentation")]
    assert refs["T1021.001"].data_components == ["Logon Session Creation", "Network Connection Creation"]
    assert refs["T1059"].mitigations == [] and refs["T1059"].groups == [] and refs["T1059"].data_components == []
    assert "Internet-facing" in refs["T1190"].description


def test_reference_bundle_rejects_unknown(mini_attack):
    with pytest.raises(KeyError):
        mini_attack.reference_bundle(["T1234"])


def test_load_missing_file_gives_clear_error(tmp_path):
    with pytest.raises(FileNotFoundError, match="aem fetch-data"):
        AttackData.load(tmp_path / "nope.json")
