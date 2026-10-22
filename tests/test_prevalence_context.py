"""Red Canary context tables (D-78): format, and that no pipeline code reads them."""
import csv
import re

import pytest

from aem.config import DATA_DIR, PREVALENCE_FILE, REPO_ROOT
from aem.models import TECHNIQUE_ID_PATTERN
from aem.step4_reference import load_prevalence

CONTEXT = DATA_DIR / "prevalence" / "context"
RANKED = CONTEXT / "red_canary_2019_2020.csv"
TOP10 = CONTEXT / "red_canary_2026_top10.csv"
ND = "sin dato"


def _rows(path):
    with path.open(encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        return reader.fieldnames, list(reader)


def test_pipeline_does_not_read_context_folder():
    assert PREVALENCE_FILE == DATA_DIR / "prevalence" / "red_canary_2026.csv"
    assert load_prevalence(PREVALENCE_FILE) == {}
    names = ("prevalence/context", "red_canary_2019_2020", "red_canary_2026_top10", "LICENSE-red-canary")
    for folder in ("src/aem", "eval"):
        for path in (REPO_ROOT / folder).rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            assert not any(n in text for n in names), path
            assert not re.search(r"""["']context["']""", text), path


def test_ranked_table_format():
    fields, rows = _rows(RANKED)
    assert fields == ["technique_id", "technique_name", "ranking_2019", "ranking_2020", "attack_v19_2_id",
                      "attack_v19_2_status", "source_url", "retrieved_date", "note"]
    assert len(rows) == 121
    for year in ("ranking_2019", "ranking_2020"):
        ranks = [int(r[year]) for r in rows if r[year] != ND]
        assert all(r[year] == ND or r[year].isdigit() for r in rows)
        assert sorted(ranks) == list(range(1, len(ranks) + 1))
    assert sum(r["ranking_2020"] != ND for r in rows) == 115 and sum(r["ranking_2019"] != ND for r in rows) == 67
    for r in rows:
        assert re.match(TECHNIQUE_ID_PATTERN, r["technique_id"])
        assert r["attack_v19_2_id"] == ND or re.match(TECHNIQUE_ID_PATTERN, r["attack_v19_2_id"])
        assert r["source_url"].startswith("https://github.com/redcanaryco/public-research/blob/")
        assert r["retrieved_date"] == "2026-10-21"
        assert "no es una tasa" in r["note"]


def test_top10_table_format():
    fields, rows = _rows(TOP10)
    assert fields == ["rank", "technique_id", "technique_name", "data_year", "report", "source_url",
                      "retrieved_date", "note"]
    assert [r["rank"] for r in rows] == [str(i) for i in range(1, 11)]
    assert [r["technique_id"] for r in rows] == ["T1078.004", "T1059.001", "T1059.003", "T1530", "T1105",
                                                 "T1114.003", "T1047", "T1204.004", "T1564.008", "T1027"]
    assert {r["data_year"] for r in rows} == {"2025"}
    assert all("no es una tasa" in r["note"] for r in rows)


@pytest.mark.parametrize("name", ["LICENSE-red-canary-public-research.txt", "README.md"])
def test_context_attribution_files(name):
    text = (CONTEXT / name).read_text(encoding="utf-8")
    assert "Red Canary" in text
    if name.startswith("LICENSE"):
        assert "MIT License" in text and "Copyright (c) 2020 Red Canary, Inc." in text
