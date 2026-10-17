import pytest
import yaml
from pydantic import ValidationError

from aem.config import ModelConfig, Settings, load_model_config
from aem.models import ExtractedTechnique, OrgProfile

ORG = {
    "organization": "Org Ficticia S.A.",
    "assets": [
        {"id": "web", "name": "Portal web", "criticality": "alta", "processes_regulated_data": True, "exposure": "internet"},
        {"id": "ws", "name": "Estaciones", "criticality": "media", "processes_regulated_data": False, "exposure": "interna"},
    ],
    "data_sources": [{"name": "Process Creation", "quality": 4}],
    "detections": [{"technique_id": "T1059.003", "score": 4, "data_sources": ["Process Creation"]}],
    "analyst_context": {"default_asset_id": "ws", "entries": [{"technique_id": "T1190", "asset_id": "web"}]},
    "known_iocs": [{"type": "sha256", "value": "a" * 64}],
}


def org(**over):
    data = yaml.safe_load(yaml.safe_dump(ORG))
    data.update(over)
    return data


def test_org_valid():
    o = OrgProfile.model_validate(org())
    assert o.asset_for("T1190").id == "web"
    assert o.asset_for("T1059").id == "ws"  # default asset


def test_org_rejects_unknown_asset_in_context():
    bad = org(analyst_context={"default_asset_id": "ws", "entries": [{"technique_id": "T1190", "asset_id": "nope"}]})
    with pytest.raises(ValidationError, match="nope"):
        OrgProfile.model_validate(bad)


def test_org_rejects_unknown_default_asset():
    with pytest.raises(ValidationError, match="zzz"):
        OrgProfile.model_validate(org(analyst_context={"default_asset_id": "zzz", "entries": []}))


@pytest.mark.parametrize("score", [-1, 6])
def test_org_rejects_score_out_of_range(score):
    with pytest.raises(ValidationError):
        OrgProfile.model_validate(org(detections=[{"technique_id": "T1059", "score": score, "data_sources": []}]))


def test_org_rejects_undeclared_data_source():
    with pytest.raises(ValidationError, match="Sysmon"):
        OrgProfile.model_validate(org(detections=[{"technique_id": "T1059", "score": 2, "data_sources": ["Sysmon"]}]))


def test_org_rejects_duplicate_detection():
    dets = [{"technique_id": "T1059", "score": 2, "data_sources": []}] * 2
    with pytest.raises(ValidationError, match="T1059"):
        OrgProfile.model_validate(org(detections=dets))


def test_org_rejects_bad_criticality():
    assets = [dict(ORG["assets"][0], criticality="critica"), ORG["assets"][1]]
    with pytest.raises(ValidationError):
        OrgProfile.model_validate(org(assets=assets))


def test_extracted_technique_schema_has_no_evaluative_fields():
    assert set(ExtractedTechnique.model_fields) == {"technique_id", "technique_name", "evidence_quote"}


def test_extracted_technique_forbids_extra_fields():
    with pytest.raises(ValidationError):
        ExtractedTechnique.model_validate(
            {"technique_id": "T1190", "technique_name": "x", "evidence_quote": "y", "priority": "high"}
        )


def test_model_config_defaults():
    cfg = ModelConfig()
    assert (cfg.coverage.partial_min, cfg.coverage.covered_min) == (1, 4)
    assert cfg.coverage.subtechnique_policy == "no_inherit"
    assert cfg.experiment.replicates == 5


def test_model_config_rejects_inverted_thresholds():
    with pytest.raises(ValidationError):
        ModelConfig.model_validate({"coverage": {"partial_min": 4, "covered_min": 2}})


def test_repo_model_config_loads():
    cfg = load_model_config()
    assert cfg.coverage.covered_min == 4


def test_settings_from_env(monkeypatch):
    monkeypatch.setenv("GEMINI_MODEL", "gemini-test")
    monkeypatch.setenv("GEMINI_RPM", "7")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    s = Settings.from_env(load_dotenv_file=False)
    assert s.gemini_model == "gemini-test" and s.gemini_rpm == 7 and s.gemini_api_key is None
    assert s.gemini_fallback_model == "gemini-3.5-flash-lite"
