import pytest

from aem.config import ATTACK_FILE, ORG_FILE, load_model_config
from aem.org import load_org
from aem.step2_coverage import assess_coverage


@pytest.fixture(scope="module")
def org():
    return load_org(ORG_FILE)


def test_org_file_is_marked_as_draft():
    assert ORG_FILE.read_text(encoding="utf-8").startswith("# BORRADOR: Sebas decide las brechas")


def test_step2_matches_declared_design(org):
    cfg = load_model_config().coverage
    design = {c.technique_id: c.intended for c in org.coverage_design}
    derived = {r.technique_id: r.coverage for r in assess_coverage(list(design), org, cfg)}
    assert derived == design


def test_draft_has_all_three_levels(org):
    levels = {c.intended for c in org.coverage_design}
    assert levels == {"cubierta", "parcial", "sin cobertura"}


@pytest.mark.skipif(not ATTACK_FILE.exists(), reason="ATT&CK v19.2 no descargado")
def test_org_data_sources_are_attack_data_components(org):
    import json

    bundle = json.loads(ATTACK_FILE.read_text(encoding="utf-8"))
    names = {o["name"] for o in bundle["objects"] if o["type"] == "x-mitre-data-component"}
    assert {d.name for d in org.data_sources} <= names


def test_known_iocs_file_is_merged(tmp_path):
    import yaml

    data = yaml.safe_load(ORG_FILE.read_text(encoding="utf-8"))
    data["known_iocs"] = [{"type": "ipv4", "value": "198.51.100.7", "scenario": "x"}]
    data["known_iocs_file"] = "gen.yaml"
    (tmp_path / "org.yaml").write_text(yaml.safe_dump(data), encoding="utf-8")
    (tmp_path / "gen.yaml").write_text(
        yaml.safe_dump({"known_iocs": [{"type": "md5", "value": "0" * 32, "scenario": "y"}]}), encoding="utf-8")
    org = load_org(tmp_path / "org.yaml")
    assert [i.value for i in org.known_iocs] == ["198.51.100.7", "0" * 32]


def test_missing_known_iocs_file_is_tolerated(tmp_path):
    import yaml

    data = yaml.safe_load(ORG_FILE.read_text(encoding="utf-8"))
    data["known_iocs_file"] = "absent.yaml"
    (tmp_path / "org.yaml").write_text(yaml.safe_dump(data), encoding="utf-8")
    assert load_org(tmp_path / "org.yaml").known_iocs == []
