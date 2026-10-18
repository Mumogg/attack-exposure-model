"""Version `anon`: everything `mut` does + threat names replaced consistently (D-72)."""

import json

import pytest

from aem.config import ANON_NAMES_FILE, SCENARIOS_FILE, load_model_config
from aem.scenarios import load_scenarios
from eval.make_variants import (
    AnonName, VariantLeak, anonymize, build_variants, check_anon, check_variant, load_anon_names, make_variant,
    variant_ioc_config,
)

GUNRA = [AnonName("Golden Community", "ActorY", "alias"), AnonName("Gunra", "ActorX", "actor"),
         AnonName("Conti", "RansomwareW", "familia")]


def test_names_replaced_everywhere_but_not_inside_other_words():
    text = ("#StopRansomware: Gunra Ransomware\nGunra actors continually reuse Conti1 code (Golden Community).\n"
            "https://www.cloudsek.com/blog/inside-gunra-raas-from-affiliate GUNRA-designated\n")
    new, log = anonymize(text, GUNRA)
    assert "ActorX Ransomware" in new and "continually" in new and "RansomwareW1" in new and "ActorY" in new
    assert "inside-ActorX-raas" in new and "ActorX-designated" in new
    assert check_anon(new, GUNRA) == []
    assert {e["name"]: e["occurrences"] for e in log}["Gunra"] == 4


def test_longest_name_wins_and_multiword_names_match_url_slugs():
    names = [AnonName("Interlock", "ActorX", "actor"), AnonName("Interlock RAT", "RatX", "malware"),
             AnonName("Lumma Stealer", "StealerX", "malware"), AnonName("Lumma", "StealerX", "malware")]
    new, _ = anonymize("Interlock actors used Interlock RAT and Lumma Stealer; see /lumma-stealer-takedown", names)
    assert new == "ActorX actors used RatX and StealerX; see /StealerX-takedown"


def test_check_anon_names_value_and_line():
    assert check_anon("ok\nstill Gunra here\n", GUNRA) == [{"name": "Gunra", "line": 2}]


def test_every_scenario_has_a_name_list():
    names = load_anon_names(ANON_NAMES_FILE)
    assert set(names) == set(load_scenarios(SCENARIOS_FILE))
    assert all(names[s] for s in names)


def test_build_variants_writes_anon_and_fails_on_a_surviving_name(tmp_path, monkeypatch):
    import eval.make_variants as mv
    scenarios = {k: v.relocated(tmp_path) for k, v in load_scenarios(SCENARIOS_FILE).items()}
    g = scenarios["gunra"]
    g.stripped.parent.mkdir(parents=True)
    g.stripped.write_text("Gunra actors\nC2 45.61.136[.]10\n", encoding="utf-8")
    build_variants(scenarios, load_model_config(), tmp_path / "known.yaml")
    assert g.anon.read_text(encoding="utf-8").startswith("ActorX actors")
    assert "45.61.136" not in g.anon.read_text(encoding="utf-8") and g.anon_diff.exists()
    log = json.loads(g.anon_log.read_text(encoding="utf-8"))
    assert log["names"][0]["name"] == "Gunra" and log["names"][0]["replacement"] == "ActorX"
    monkeypatch.setattr(mv, "anonymize", lambda text, names: (text, []))
    with pytest.raises(VariantLeak, match=r"Gunra.*línea 1"):
        build_variants(scenarios, load_model_config(), tmp_path / "known.yaml")


def _prepared():
    return [sc for sc in load_scenarios(SCENARIOS_FILE).values() if sc.stripped.exists()]


@pytest.mark.parametrize("sc", _prepared(), ids=lambda s: s.name)
def test_no_original_name_or_ioc_survives_in_anon(sc):
    cfg = load_model_config()
    names = load_anon_names(ANON_NAMES_FILE)[sc.name]
    original = sc.stripped.read_text(encoding="utf-8")
    mut, _ = make_variant(original, variant_ioc_config(cfg), seed=cfg.variants.seed, salt=sc.name)
    anon, log = anonymize(mut, names)
    assert check_anon(anon, names) == [] and check_variant(original, anon, cfg.ioc) == []
    assert sum(e["occurrences"] for e in log) > 0


@pytest.mark.parametrize("sc", [s for s in _prepared() if s.anon.exists()], ids=lambda s: s.name)
def test_committed_anon_text_is_clean(sc):
    names = load_anon_names(ANON_NAMES_FILE)[sc.name]
    anon = sc.anon.read_text(encoding="utf-8")
    assert check_anon(anon, names) == []
    assert check_variant(sc.stripped.read_text(encoding="utf-8"), anon, load_model_config().ioc) == []


def test_legitimate_tools_are_kept():
    names = load_anon_names(ANON_NAMES_FILE)
    listed = {n.name.lower() for ns in names.values() for n in ns}
    assert not listed & {"powershell", "rdp", "anydesk", "impacket", "rclone", "filezilla", "psexec", "cobalt strike"}
