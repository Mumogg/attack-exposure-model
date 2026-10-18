"""`aem suggest-anon-names`: candidate threat names for data/anon_names.yaml.

Only synthetic text written for these tests (never fragments of the DFIR report), plus the
public-domain CISA texts already in the repository for the coverage check.
"""

import pytest

from aem.config import ANON_NAMES_FILE, SCENARIOS_FILE
from aem.scenarios import load_scenarios
from eval.anon_suggest import THREAT, LEGIT, coverage, suggest, write_candidates
from eval.make_variants import AnonName, load_anon_names

SYNTH = """# Quillfeather Ransomware Analysis

The Quillfeather actors gained access through a fake installer that dropped the GlimmerLoader loader.
Quillfeather operators then deployed the Mossback RAT and used PowerShell and AnyDesk for remote access.
Later the affiliates staged the ZephyrC2 framework, also known under the alias Velvet Orchard group, on a server.
Analysts compared the encryptor to the older Tarnwick3 ransomware family.
Windows hosts were enumerated. Windows logs were cleared by the Quillfeather actors.
Network shares were mapped; the network team saw the traffic.
"""


def by_name(cands):
    return {c.name: c for c in cands}


def test_finds_threat_names_of_every_shape():
    c = by_name(suggest(SYNTH))
    for name in ("Quillfeather", "GlimmerLoader", "Mossback RAT", "ZephyrC2", "Velvet Orchard", "Tarnwick"):
        assert name in c, name
        assert c[name].label == THREAT, (name, c[name].reason)
    assert c["Quillfeather"].count == 4


def test_legit_tools_and_ordinary_words():
    c = by_name(suggest(SYNTH))
    assert c["PowerShell"].label == LEGIT and c["AnyDesk"].label == LEGIT and c["Windows"].label == LEGIT
    assert "Network" not in c  # more often lower case in the text: an ordinary word
    assert "Later" not in c and "Analysts" not in c  # only at the start of a sentence


def test_contexts_are_short_and_at_most_two():
    ctx = by_name(suggest(SYNTH))["Quillfeather"].contexts
    assert 1 <= len(ctx) <= 2 and all(len(x.split()) <= 11 for x in ctx)


def test_coverage_reports_listed_names_missing_from_candidates():
    names = [AnonName("Quillfeather", "ActorX"), AnonName("Mossback RAT", "RatX"),
             AnonName("silentwren", "MalwareX"), AnonName("Nowhere", "MalwareY")]
    cov = coverage(SYNTH + "the silentwren tool\n", suggest(SYNTH + "the silentwren tool\n"), names)
    assert cov["covered"] == ["Quillfeather", "Mossback RAT"]
    assert cov["missing_in_text"] == ["silentwren"]  # in the text but not proposed: warn
    assert cov["absent"] == ["Nowhere"]
    assert "GlimmerLoader" in cov["threats_not_listed"]


def test_write_candidates_is_private_and_never_touches_the_yaml(tmp_path):
    before = ANON_NAMES_FILE.read_text(encoding="utf-8")
    out = write_candidates(tmp_path / "private", "demo", SYNTH, suggest(SYNTH), [AnonName("Quillfeather", "ActorX")])
    assert out == tmp_path / "private" / "demo_anon_candidates.md"
    md = out.read_text(encoding="utf-8")
    assert "probable amenaza" in md and "anon_names.yaml" in md and "- {name: GlimmerLoader" in md
    assert ANON_NAMES_FILE.read_text(encoding="utf-8") == before


@pytest.mark.parametrize("name", ["gunra", "interlock"])
def test_every_listed_cisa_name_is_proposed(name):
    sc = load_scenarios(SCENARIOS_FILE)[name]
    text = sc.text.read_text(encoding="utf-8")
    cov = coverage(text, suggest(text), load_anon_names(ANON_NAMES_FILE)[name])
    assert cov["missing_in_text"] == [] and cov["absent"] == []


def test_cli_writes_private_file_and_warns_about_unproposed_names(tmp_path, monkeypatch):
    import shutil
    import yaml
    from typer.testing import CliRunner
    from aem.cli import app

    data = tmp_path / "data"
    (data / "reports").mkdir(parents=True)
    shutil.copy(SCENARIOS_FILE, data / "scenarios.yaml")
    (data / "reports" / "akira_dfir_2026.txt").write_text(SYNTH + "the silentwren tool ran\n", encoding="utf-8")
    names = data / "anon_names.yaml"
    names.write_text(yaml.safe_dump({"akira": [{"name": "Quillfeather", "replacement": "ActorX"},
                                               {"name": "silentwren", "replacement": "MalwareX"}]}),
                     encoding="utf-8")
    monkeypatch.setattr("aem.cli.SCENARIOS_FILE", data / "scenarios.yaml")
    monkeypatch.setattr("aem.cli.ANON_NAMES_FILE", names)
    before = names.read_text(encoding="utf-8")
    res = CliRunner().invoke(app, ["suggest-anon-names", "--scenario", "akira"])
    out = res.output.replace("\n", " ")
    assert res.exit_code == 0, res.output
    assert "1. " in out and "GlimmerLoader" in out and "probable amenaza" in out
    assert "silentwren" in out and "AVISO" in out  # listed, in the text, but not proposed
    assert (data / "reports" / "private" / "akira_anon_candidates.md").exists()
    assert names.read_text(encoding="utf-8") == before


def test_sequences_starting_with_an_article_are_not_candidates():
    c = by_name(suggest(SYNTH + "The Quillfeather actors returned. The Quillfeather actors left.\n"))
    assert "The Quillfeather" not in c and "Quillfeather" in c
