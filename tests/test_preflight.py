"""`aem preflight`: checks before spending API calls (OK / FALTA / AVISO)."""

import hashlib
import shutil
import subprocess

import pytest

from aem.config import ModelConfig, REPO_ROOT, SCENARIOS_FILE, Settings
from aem.preflight import estimate_calls, run_preflight
from aem.scenarios import VERSIONS, load_scenarios
from fakes import FakeTransport


def settings(key="k"):
    return Settings(key, "gemini-3.8-flash", "gemini-3.5-flash-lite", 10, 0)


@pytest.fixture
def env(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    shutil.copy(REPO_ROOT / ".gitignore", repo / ".gitignore")
    data = repo / "data"
    scenarios = {k: v.relocated(data) for k, v in load_scenarios(SCENARIOS_FILE).items()}
    shutil.copytree(SCENARIOS_FILE.parent / "reference_mappings", data / "reference_mappings")
    for sc in scenarios.values():
        sc.text.parent.mkdir(parents=True, exist_ok=True)
        sc.text.write_text("Raw report text.", encoding="utf-8")
        for v in VERSIONS:
            sc.report_for(v).write_text(f"The actors used cmd.exe ({v}).", encoding="utf-8")
    attack = data / "attack" / "enterprise-attack-19.2.json"
    attack.parent.mkdir(parents=True)
    attack.write_bytes(b"{}")
    sums = attack.parent / "CHECKSUMS.sha256"
    sums.write_text(f"{hashlib.sha256(b'{}').hexdigest()}  enterprise-attack-19.2.json\n", encoding="utf-8")
    prevalence = data / "prevalence.csv"
    prevalence.write_text("technique_id,rank,source_note\nT1059.001,1,\n", encoding="utf-8")
    return {"repo": repo, "scenarios": scenarios, "attack": attack, "sums": sums, "prevalence": prevalence}


def run(env, demo=False, key="k", transport=None, **kw):
    args = dict(settings=settings(key), demo=demo, attack_path=env["attack"], checksums_path=env["sums"],
                scenarios=env["scenarios"], prevalence_path=env["prevalence"], repo_root=env["repo"],
                model_cfg=ModelConfig(), replicates=5, transport=transport or FakeTransport())
    args.update(kw)
    return run_preflight(**args)


def statuses(checks, word):
    return [c for c in checks if word in c.item]


def test_all_good_has_no_falta(env):
    checks = run(env)
    assert not [c for c in checks if c.status == "FALTA"], [c for c in checks if c.status == "FALTA"]
    assert all(c.status in ("OK", "AVISO", "INFO") for c in checks)


def test_missing_key_is_falta_unless_demo(env):
    assert statuses(run(env, key=None), "GEMINI_API_KEY")[0].status == "FALTA"
    assert statuses(run(env, key=None, demo=True), "GEMINI_API_KEY")[0].status == "OK"


def test_unknown_model_is_falta(env):
    check = statuses(run(env, transport=FakeTransport(models=())), "Modelo")[0]
    assert check.status == "FALTA" and "gemini-3.5-flash-lite" in check.detail


def test_bad_attack_checksum_is_falta(env):
    env["attack"].write_bytes(b"[]")
    assert statuses(run(env), "ATT&CK")[0].status == "FALTA"


def test_akira_text_and_ids_in_stripped(env):
    akira = env["scenarios"]["akira"]
    akira.stripped.write_text("They used T1059.001 and TA0002.", encoding="utf-8")
    check = [c for c in run(env) if "sin IDs" in c.item and "akira" in c.item][0]
    assert check.status == "FALTA" and "T1059.001" in check.detail
    akira.text.unlink()
    assert [c for c in run(env) if "Texto de akira" in c.item][0].status == "FALTA"
    assert [c for c in run(env, demo=True) if "Texto de akira" in c.item][0].status == "AVISO"


def test_empty_prevalence_is_aviso(env):
    env["prevalence"].write_text("technique_id,rank,source_note\n", encoding="utf-8")
    check = statuses(run(env), "Prevalencia")[0]
    assert check.status == "AVISO" and "sin dato disponible" in check.detail


def test_missing_version_is_falta(env):
    env["scenarios"]["interlock"].anon.unlink()
    check = [c for c in run(env) if c.item == "Versiones de interlock"][0]
    assert check.status == "FALTA" and "anon" in check.detail


def test_gitignore_rules_are_checked(env):
    (env["repo"] / ".gitignore").write_text("# nothing\n", encoding="utf-8")
    bad = [c for c in run(env) if c.item.startswith("Ignorado por git") and c.status == "FALTA"]
    assert {c.item for c in bad} >= {"Ignorado por git: .env", "Ignorado por git: runs/llm_cache_private/"}


def test_estimate_counts_chunks_versions_and_replicates(env):
    est = estimate_calls(env["scenarios"], ModelConfig(), replicates=5, rpm=10)
    assert est["extraction_calls"] == 3 * 3 * 5
    assert est["summary_calls_min"] > 0 and est["minutes_min"] == pytest.approx(
        (est["extraction_calls"] + est["summary_calls_min"]) * 6 / 60)
    assert any("Estimación" in c.item for c in run(env))
