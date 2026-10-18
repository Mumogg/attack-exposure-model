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


def test_private_known_iocs_file_is_merged_too(tmp_path):
    import yaml

    data = yaml.safe_load(ORG_FILE.read_text(encoding="utf-8"))
    data.update(known_iocs=[], known_iocs_file="gen.yaml", known_iocs_private_file="private/p.yaml")
    (tmp_path / "org.yaml").write_text(yaml.safe_dump(data), encoding="utf-8")
    (tmp_path / "gen.yaml").write_text(
        yaml.safe_dump({"known_iocs": [{"type": "md5", "value": "0" * 32, "scenario": "y"}]}), encoding="utf-8")
    assert [i.value for i in load_org(tmp_path / "org.yaml").known_iocs] == ["0" * 32]  # private file absent
    (tmp_path / "private").mkdir()
    (tmp_path / "private" / "p.yaml").write_text(
        yaml.safe_dump({"known_iocs": [{"type": "ipv4", "value": "203.0.113.9", "scenario": "z"}]}), encoding="utf-8")
    assert [i.value for i in load_org(tmp_path / "org.yaml").known_iocs] == ["0" * 32, "203.0.113.9"]


def test_versioned_known_iocs_have_no_copyrighted_scenario():
    """D-76: the IoCs of a copyrighted scenario (Akira) never go to the versioned file."""
    import yaml
    from aem.config import KNOWN_IOCS_FILE, KNOWN_IOCS_PRIVATE_FILE, REPO_ROOT, SCENARIOS_FILE
    from aem.scenarios import load_scenarios

    copyrighted = {n for n, sc in load_scenarios(SCENARIOS_FILE).items() if sc.copyrighted}
    assert copyrighted
    assert not {k["scenario"] for k in yaml.safe_load(KNOWN_IOCS_FILE.read_text(encoding="utf-8"))["known_iocs"]} \
        & copyrighted
    assert "private" in KNOWN_IOCS_PRIVATE_FILE.relative_to(REPO_ROOT).parts


def test_missing_known_iocs_file_is_tolerated(tmp_path):
    import yaml

    data = yaml.safe_load(ORG_FILE.read_text(encoding="utf-8"))
    data["known_iocs_file"] = "absent.yaml"
    (tmp_path / "org.yaml").write_text(yaml.safe_dump(data), encoding="utf-8")
    assert load_org(tmp_path / "org.yaml").known_iocs == []
