"""README.md (English, primary) and README.es.md (Spanish) must stay in step."""

import re

from aem.config import REPO_ROOT

EN = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
ES = (REPO_ROOT / "README.es.md").read_text(encoding="utf-8")
BIBTEX = re.compile(r"```bibtex\n.*?```", re.S)


def _outside_bibtex(text):
    return BIBTEX.sub("", text)


def test_each_links_to_the_other():
    assert EN.splitlines()[0] == "Español: [README.es.md](README.es.md)"
    assert ES.splitlines()[0] == "English: [README.md](README.md)"


def test_same_pending_marks():
    en = re.findall(r"\[PENDING: ([^\]]+)\]", _outside_bibtex(EN))
    es = re.findall(r"\[PENDIENTE: ([^\]]+)\]", _outside_bibtex(ES))
    assert en == es  # may be empty once every pending item is resolved
    assert "[PENDIENTE" not in _outside_bibtex(EN) and "[PENDING" not in ES


def test_same_bibtex_and_repo_url():
    assert BIBTEX.findall(EN) == BIBTEX.findall(ES) and BIBTEX.findall(EN)
    url = "https://github.com/Mumogg/attack-exposure-model"
    assert EN.count(url) == ES.count(url) > 0


def test_same_section_structure():
    def levels(text):
        lines, fenced = [], False
        for line in text.splitlines():
            if line.startswith("```"):
                fenced = not fenced
            elif not fenced and line.startswith("#"):
                lines.append(len(line) - len(line.lstrip("#")))
        return lines
    assert levels(EN) == levels(ES)


def test_ai_declaration_keeps_its_review_line():
    assert EN.rstrip().endswith("Reviewed by the author on 2026-10-18.")
    assert ES.rstrip().endswith("Revisada por el autor el 2026-10-18.")
