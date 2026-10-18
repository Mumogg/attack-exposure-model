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


def test_variant_email_keeps_local_part_and_changes_domain():
    new, mapping = make_variant("contact a1@proton[.]me now", DEFAULT, seed=1, salt="e")
    m = next(x for x in mapping if x["type"] == "email")
    assert m["replacement"].startswith("a1@") and m["replacement"].endswith("[.]invalid")


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
