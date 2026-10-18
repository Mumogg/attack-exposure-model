import ipaddress
import re

import pytest

from aem.config import BaselineConfig, IocConfig, load_model_config
from eval.baseline_ioc import baseline_recognizes, extract_iocs, select_known_iocs
from eval.make_variants import DOC_NETWORKS, make_variant

DEFAULT = load_model_config().ioc
CFG = DEFAULT.model_copy(update={"require_defang": False})  # mixed fanged/defanged sample below

TEXT = """The actors used main.exe and secretsdump.py, then contacted 45.61.136[.]10 and 8.8.4.4:443.
Payloads came from hxxps://evil-updates[.]com/a/b.ps1 and http://cdn.badhost.net/x.zip.
They used dropper.top and visited https://www.cisa.gov/stopransomware (reference).
Email: gunra@onionmail.org. Version 19.1 and CVE-2024-21762.
| SHA256 | 9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08 |
MD5 d41d8cd98f00b204e9800998ecf8427e and SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709."""


def values(iocs, kind):
    return sorted({i.value for i in iocs if i.type == kind})


def test_extract_iocs_types_and_normalization():
    iocs = extract_iocs(TEXT, CFG)
    assert values(iocs, "ipv4") == ["45.61.136.10", "8.8.4.4"]
    assert values(iocs, "url") == ["http://cdn.badhost.net/x.zip", "https://evil-updates.com/a/b.ps1"]
    assert values(iocs, "domain") == ["dropper.top"]
    assert values(iocs, "email") == ["gunra@onionmail.org"]
    assert values(iocs, "sha256") == ["9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"]
    assert values(iocs, "md5") == ["d41d8cd98f00b204e9800998ecf8427e"]
    assert values(iocs, "sha1") == ["da39a3ee5e6b4b0d3255bfef95601890afd80709"]


def test_filenames_and_reference_domains_are_not_iocs():
    found = {i.value for i in extract_iocs(TEXT, CFG)}
    assert not {"main.exe", "secretsdump.py", "cisa.gov", "www.cisa.gov", "19.1"} & found
    assert not any("cisa.gov" in v for v in found)


def test_variant_replaces_every_ioc_with_safe_values():
    new, mapping = make_variant(TEXT, CFG, seed=7, salt="t")
    assert not ({i.value for i in extract_iocs(TEXT, CFG)} & {i.value for i in extract_iocs(new, CFG)})
    for m in mapping:
        if m["type"] == "ipv4":
            ip = ipaddress.ip_address(m["replacement"].replace("[.]", "."))
            assert any(ip in net for net in DOC_NETWORKS)
        if m["type"] == "domain":
            assert m["replacement"].endswith(".invalid") or ".example." in m["replacement"]
        if m["type"] in ("md5", "sha1", "sha256"):
            assert len(m["replacement"]) == len(m["original"])
            assert re.fullmatch(r"[0-9a-fA-F]+", m["replacement"])
            assert m["replacement"].isupper() == m["original"].isupper()


def test_variant_keeps_behavior_text_intact():
    new, mapping = make_variant(TEXT, CFG, seed=7, salt="t")
    restored = new
    for m in sorted(mapping, key=lambda m: -len(m["replacement"])):
        restored = restored.replace(m["replacement"], m["original"])
    assert restored == TEXT
    for kept in ("main.exe", "secretsdump.py", "https://www.cisa.gov/stopransomware", "CVE-2024-21762", "/a/b.ps1"):
        assert kept in new


def test_variant_defang_style_and_consistency():
    text = "C2 at 45.61.136[.]10, again 45.61.136[.]10 and 45.61.136.10"
    new, mapping = make_variant(text, CFG, seed=1, salt="x")
    parts = re.findall(r"\d+\.\d+\.\d+(?:\[\.\]|\.)\d+", new)
    assert parts[0] == parts[1] and "[.]" in parts[0]
    assert parts[2] == parts[0].replace("[.]", ".")


def test_variant_is_deterministic():
    assert make_variant(TEXT, CFG, seed=7, salt="t") == make_variant(TEXT, CFG, seed=7, salt="t")
    assert make_variant(TEXT, CFG, seed=7, salt="t")[0] != make_variant(TEXT, CFG, seed=8, salt="t")[0]


def test_known_ioc_selection_is_fixed_and_proportional():
    iocs = extract_iocs(TEXT, CFG)
    cfg = BaselineConfig(known_ioc_fraction=0.5, min_matches=1, seed=3)
    a = select_known_iocs(iocs, cfg, scenario="gunra")
    assert a == select_known_iocs(iocs, cfg, scenario="gunra")
    assert len(a) == (len({(i.type, i.value) for i in iocs}) + 1) // 2
    assert all(k.scenario == "gunra" for k in a)


def test_baseline_recognizes_orig_but_not_mut():
    cfg = BaselineConfig(known_ioc_fraction=0.5, min_matches=1, seed=3)
    known = select_known_iocs(extract_iocs(TEXT, CFG), cfg, scenario="gunra")
    ok, matches = baseline_recognizes(TEXT, known, CFG, cfg)
    assert ok and matches
    mut, _ = make_variant(TEXT, CFG, seed=7, salt="t")
    ok, matches = baseline_recognizes(mut, known, CFG, cfg)
    assert not ok and matches == []


def test_baseline_min_matches_threshold():
    known = select_known_iocs(extract_iocs(TEXT, CFG), BaselineConfig(known_ioc_fraction=1.0, seed=1), "g")
    ok, _ = baseline_recognizes("only 8.8.4.4 here", known, CFG, BaselineConfig(min_matches=2))
    assert not ok


def test_default_requires_defanged_network_iocs():
    """Reference links in a bulletin's Notes are not IoCs; CISA/DFIR write real ones defanged (D-63)."""
    text = ("See https://www.trendmicro.com/research/x.html and cisecurity.org. "
            "C2 45.61.136[.]10, hxxps://evil[.]com/a, mail a1@proton[.]me, plain 8.8.4.4, hash "
            "d41d8cd98f00b204e9800998ecf8427e")
    found = {(i.type, i.value) for i in extract_iocs(text, DEFAULT)}
    assert found == {("ipv4", "45.61.136.10"), ("url", "https://evil.com/a"), ("email", "a1@proton.me"),
                     ("md5", "d41d8cd98f00b204e9800998ecf8427e")}


def test_variant_email_changes_local_part_and_domain():
    new, mapping = make_variant("contact a1@proton[.]me now", DEFAULT, seed=1, salt="e")
    m = next(x for x in mapping if x["type"] == "email")
    assert not m["replacement"].startswith("a1@") and m["replacement"].endswith("[.]invalid")


def test_build_variants_writes_variant_diff_log_and_known_iocs(tmp_path):
    import json
    import yaml
    from aem.config import SCENARIOS_FILE
    from aem.scenarios import load_scenarios
    from eval.make_variants import build_variants

    scenarios = {k: v.relocated(tmp_path) for k, v in load_scenarios(SCENARIOS_FILE).items()}
    g = scenarios["gunra"]
    g.stripped.parent.mkdir(parents=True)
    g.stripped.write_text("Actors used 45.61.136[.]10 and evil[.]com to deliver main.exe.\n", encoding="utf-8")
    known = tmp_path / "known.yaml"
    logs = build_variants(scenarios, load_model_config(), known)
    assert [l["scenario"] for l in logs] == ["gunra"]  # interlock/akira texts absent here: skipped
    assert "main.exe" in g.variant.read_text(encoding="utf-8")
    assert "45.61.136[.]10" not in g.variant.read_text(encoding="utf-8")
    assert g.variant_diff.read_text(encoding="utf-8").startswith("---")
    log = json.loads(g.variant_log.read_text(encoding="utf-8"))
    assert log["seed"] == load_model_config().variants.seed and len(log["mapping"]) == 2
    data = yaml.safe_load(known.read_text(encoding="utf-8"))
    assert {k["scenario"] for k in data["known_iocs"]} == {"gunra"} and len(data["known_iocs"]) == 1
    assert data["policy"]["known_ioc_fraction"] == 0.5


def test_build_variants_keeps_copyrighted_iocs_out_of_the_versioned_file(tmp_path):
    import yaml
    from aem.config import SCENARIOS_FILE
    from aem.scenarios import load_scenarios
    from eval.make_variants import build_variants

    scenarios = {k: v.relocated(tmp_path) for k, v in load_scenarios(SCENARIOS_FILE).items()}
    g, a = scenarios["gunra"], scenarios["akira"]
    assert a.copyrighted and not g.copyrighted
    g.stripped.parent.mkdir(parents=True)
    g.stripped.write_text("Gunra actors used 45.61.136[.]10 to deliver main.exe.\n", encoding="utf-8")
    a.stripped.write_text("Akira actors used 203.0.113[.]5 to deliver run.exe.\n", encoding="utf-8")
    known, private = tmp_path / "known.yaml", tmp_path / "private" / "known_private.yaml"
    with pytest.raises(ValueError, match="D-76"):
        build_variants(scenarios, load_model_config(), known)
    build_variants(scenarios, load_model_config(), known, private_known_iocs_path=private)
    public = yaml.safe_load(known.read_text(encoding="utf-8"))["known_iocs"]
    assert {k["scenario"] for k in public} == {"gunra"} and "203.0.113.5" not in known.read_text(encoding="utf-8")
    assert [(k["scenario"], k["value"]) for k in yaml.safe_load(private.read_text(encoding="utf-8"))["known_iocs"]] \
        == [("akira", "203.0.113.5")]


# --- D-70: IoC types listed by the bulletins themselves (fair baseline) -------------------------

QTOX = "2507312EC10BB44ED9DAA04E3C5C27E8C13154649B1A02E73ACFAE1681EE0208D05133A8FB22"
QTOX_TYPO = "47829AF1C943D4C296C910706923AS199BDA4995B076ED9A9016F7DEF161D445DF00F13E6900"  # as printed by CISA
ACCOUNTS = ("| Username | Details |\n| forticloud-sync | creates a new, malicious persistent user forticloud-sync |\n\n"
            "Later the actors logged in as forticloud-sync again.")


def test_qtox_ids_are_iocs():
    found = {(i.type, i.value) for i in extract_iocs(f"- {QTOX}\n- {QTOX_TYPO}\n", DEFAULT)}
    assert found == {("qtox", QTOX.lower()), ("qtox", QTOX_TYPO.lower())}


def test_accounts_from_username_column_and_every_mention():
    iocs = [i for i in extract_iocs(ACCOUNTS, DEFAULT) if i.type == "account"]
    assert {i.value for i in iocs} == {"forticloud-sync"} and len(iocs) == 3


def test_extra_types_can_be_disabled():
    cfg = DEFAULT.model_copy(update={"extra_types": []})
    assert not extract_iocs(f"- {QTOX}\n" + ACCOUNTS, cfg)


# --- complete mut variants ------------------------------------------------------------------------


def test_hash_inside_a_url_is_replaced():
    from eval.make_variants import check_variant
    text = "See https://www.virustotal.com/gui/file/91f8fc7a3290611e28a35a403fd815554d9d856006cc2ee91ccdb64057ae53b0/x"
    loose = DEFAULT.model_copy(update={"require_defang": False})
    new, _ = make_variant(text, loose, seed=1, salt="u")
    assert "91f8fc7a3290611e28a35a403fd815554d9d856006cc2ee91ccdb64057ae53b0" not in new
    assert check_variant(text, new, DEFAULT) == []


def test_check_variant_names_value_and_line():
    from eval.make_variants import check_variant
    original = "intro\nC2 45.61.136[.]10 here\n"
    leaks = check_variant(original, "intro\nstill 45.61.136.10\n", DEFAULT)
    assert leaks == [{"type": "ipv4", "value": "45.61.136.10", "line": 2}]


def test_build_variants_fails_on_leak(tmp_path, monkeypatch):
    import eval.make_variants as mv
    from aem.config import SCENARIOS_FILE
    from aem.scenarios import load_scenarios

    scenarios = {k: v.relocated(tmp_path) for k, v in load_scenarios(SCENARIOS_FILE).items()}
    g = scenarios["gunra"]
    g.stripped.parent.mkdir(parents=True)
    g.stripped.write_text("x\nC2 45.61.136[.]10\n", encoding="utf-8")
    monkeypatch.setattr(mv, "make_variant", lambda text, cfg, seed, salt: (text, []))  # simulate a missed IoC
    with pytest.raises(mv.VariantLeak, match=r"45\.61\.136\.10.*línea 2"):
        mv.build_variants(scenarios, load_model_config(), tmp_path / "known.yaml")


def _prepared_scenarios():
    from aem.config import SCENARIOS_FILE
    from aem.scenarios import load_scenarios
    return [sc for sc in load_scenarios(SCENARIOS_FILE).values() if sc.stripped.exists()]


@pytest.mark.parametrize("sc", _prepared_scenarios(), ids=lambda s: s.name)
def test_no_original_ioc_survives_in_mut(sc):
    """Every IoC of the original (defanged or not, prose, tables, notes) is gone from the mut text."""
    from eval.make_variants import check_variant, variant_ioc_config
    cfg = load_model_config()
    original = sc.stripped.read_text(encoding="utf-8")
    variant, mapping = make_variant(original, variant_ioc_config(cfg), seed=cfg.variants.seed, salt=sc.name)
    assert mapping
    assert check_variant(original, variant, cfg.ioc) == []


def test_fanged_mention_of_a_detected_ioc_is_replaced():
    """A domain listed defanged in a table is also replaced where the prose writes it plainly."""
    from eval.make_variants import check_variant
    text = "They mirrored the DLS at datapub.news.\n\n| Domain |\n| datapub[.]news |\n"
    new, _ = make_variant(text, DEFAULT, seed=1, salt="d")
    assert check_variant(text, new, DEFAULT) == []
    assert new.replace("[.]", ".").count(".invalid") == 2


def test_mapping_counts_every_occurrence():
    text = "| Domain |\n| datapub[.]news |\nmirror at datapub.news and datapub[.]news\n"
    _, mapping = make_variant(text, DEFAULT, seed=1, salt="o")
    assert sum(m["occurrences"] for m in mapping) == 3


# --- independent review (docs/REVISION_EVAL.md) ---------------------------------------------------


def test_review_a1_plain_tokens_that_are_not_iocs_stay_in_mut():
    """A1: file names, services and version numbers written plainly are behavior, not IoCs."""
    from eval.make_variants import variant_ioc_config
    text = "Actors ran backdoor.pl and exfiltrated to mega.io. Version 5.1.2.3 installed. C2 45.61.136[.]10\n"
    new, _ = make_variant(text, variant_ioc_config(load_model_config()), seed=1, salt="a1")
    assert "backdoor.pl" in new and "mega.io" in new and "5.1.2.3" in new
    assert "45.61.136" not in new


def test_review_a1_hash_in_plain_reference_url_is_still_replaced():
    from eval.make_variants import check_variant, variant_ioc_config
    h = "91f8fc7a3290611e28a35a403fd815554d9d856006cc2ee91ccdb64057ae53b0"
    text = f"| cryptor.exe | {h} |\n\n11 VirusTotal, https://www.virustotal.com/gui/file/{h}/detection\n"
    new, _ = make_variant(text, variant_ioc_config(load_model_config()), seed=1, salt="a1b")
    assert h not in new and "https://www.virustotal.com/gui/file/" in new
    assert check_variant(text, new, DEFAULT) == []


def test_review_a2_generic_accounts_are_not_iocs():
    text = "| Username |\n| Administrator |\n| forticloud-sync |\nused the built-in Administrator account"
    vals = {i.value for i in extract_iocs(text, DEFAULT) if i.type == "account"}
    assert vals == {"forticloud-sync"}


def test_review_a5_sha512_is_an_ioc_and_is_replaced():
    from eval.make_variants import check_variant
    h = "ab" * 64
    assert [(i.type, i.value) for i in extract_iocs(f"hash {h}\n", DEFAULT)] == [("sha512", h)]
    new, _ = make_variant(f"hash {h}\n", DEFAULT, seed=1, salt="a5")
    assert h not in new and check_variant(f"hash {h}\n", new, DEFAULT) == []


def test_review_a5_check_flags_any_long_hex_run():
    from eval.make_variants import check_variant
    h = "cd" * 48  # 96 hex: no known hash type, still an indicator if it survives
    assert check_variant(f"x {h}", f"x {h}", DEFAULT) != []


def test_review_a6_email_local_part_is_replaced():
    new, _ = make_variant("contact ilovemycubscout@gmail[.]com now", DEFAULT, seed=1, salt="a6")
    assert "ilovemycubscout" not in new and "@" in new and "[.]invalid" in new


def test_review_a7_mapping_is_keyed_by_type_and_value():
    text = "| Domain |\n| Datapub[.]news |\nmirror at datapub.news\n"
    _, mapping = make_variant(text, DEFAULT, seed=1, salt="a7")
    doms = [m for m in mapping if m["type"] == "domain"]
    assert len(doms) == 1 and doms[0]["occurrences"] == 2
    assert sorted(doms[0]["spellings"]) == ["Datapub[.]news", "datapub.news"]
