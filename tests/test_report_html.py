"""`aem report --html`: self-contained page, public and private versions. Written only to temporary folders."""

from __future__ import annotations

import json
import re
import subprocess
from html.parser import HTMLParser

import pytest
from typer.testing import CliRunner

from aem import cli
from aem.config import DATA_DIR, REPO_ROOT, RUNS_DIR, SCENARIOS_FILE, load_model_config
from aem.repo_check import copied_windows, ioc_values
from aem.scenarios import load_scenarios
from eval.baseline_ioc import extract_iocs
from eval.report_html import LeakError, build_html, leak_findings, violation_ticks, visible_text
from eval.run_experiments import run_experiment
from test_pipeline import RoutingTransport
from test_run_experiments import EXTRACTION, _with_akira, setup  # noqa: F401  (fixture)

SENTINEL = "SENTINELA privada de la cita de Akira"
DFIR_TEXT = DATA_DIR / "reports" / "akira_dfir_2026.txt"
MAIN_RUN = RUNS_DIR / "2026-10-18-main"


@pytest.fixture
def run(setup):  # noqa: F811
    _with_akira(setup)
    run_experiment(setup["ctx"](RoutingTransport(extraction=EXTRACTION)), setup["scenarios"], setup["run"],
                   setup["sheets"], replicates=2)
    for rec_path in (setup["run"] / "private" / "akira").rglob("run_record.json"):
        rec = json.loads(rec_path.read_text(encoding="utf-8"))
        for t in rec["extraction"]["extracted_raw"]:
            t["evidence_quote"] = SENTINEL
        rec_path.write_text(json.dumps(rec), encoding="utf-8")
    return setup


def _build(run, tmp_path, **kw):
    out = build_html(run["run"], tmp_path / "out" / "report.html", run["sheets"], run["scenarios"], **kw)
    return out.read_text(encoding="utf-8")


def test_minimal_structure(run, tmp_path):
    html = _build(run, tmp_path)
    assert html.startswith("<!doctype html>")
    assert '<meta name="viewport"' in html and '<html lang="en" data-lang="en">' in html
    for section in ("run", "indicators", "comparison", "distribution", "techniques", "limits"):
        assert f'<section id="{section}"' in html and f'href="#{section}"' in html
    for i in range(1, 6):
        assert f"Indicator {i}" in html and f"Indicador {i}" in html
    assert 'id="lang"' in html and '<span lang="es">' in html
    assert all(f'data-filter="{f}"' in html for f in ("scenario", "version", "tactics", "actions"))
    assert "RESULTADO PARCIAL" in html  # interlock has no text in the fixture
    assert "sin dato disponible" in html  # manual review not done
    assert "_fail0" in html and "_valid" in html
    assert "<svg" in html and "<title>" in html  # charts with an accessible name


def test_only_attack_urls_and_nothing_external(run, tmp_path):
    html = _build(run, tmp_path)
    hosts = set(re.findall(r"(?:https?:)?//([A-Za-z0-9.-]+\.[A-Za-z]{2,})", html))
    assert hosts == {"attack.mitre.org"}
    assert not re.search(r"<script[^>]+src=|<link[^>]+href=|@import|url\(\s*['\"]?http", html)


def test_no_absolute_paths_or_keys(run, tmp_path):
    html = _build(run, tmp_path)
    assert str(REPO_ROOT) not in html and str(tmp_path) not in html
    assert "AIza" not in html and "private/" not in html


def test_copyrighted_quotes_only_in_the_private_page(run, tmp_path):
    public = _build(run, tmp_path)
    assert SENTINEL not in public and 'data-scenario="akira"' in public
    assert "used cmd.exe" in public  # public quotes (gunra) are shown
    private = build_html(run["run"], tmp_path / "priv" / "report_full.html", run["sheets"], run["scenarios"],
                         private=True).read_text(encoding="utf-8")
    assert SENTINEL in private and "PRIVADA" in private


def test_word_window_and_ioc_check_stop_the_public_page(run, tmp_path):
    with pytest.raises(LeakError, match="frase del reporte"):
        _build(run, tmp_path, dfir_text="Shared: the design of the model, the technical decisions of this text.")
    with pytest.raises(LeakError, match="IoC"):
        _build(run, tmp_path, iocs=["cmd.exe"])
    assert not (tmp_path / "out" / "report.html").exists()


def test_copied_windows_ignore_case_and_punctuation():
    src = "One two three, four FIVE six seven eight nine."
    assert copied_windows("x one TWO three four five six seven eight y", src) == [
        "one two three four five six seven eight"]
    assert copied_windows("one two three four five six seven", src) == []


def test_private_needs_html():
    res = CliRunner().invoke(cli.app, ["report", "--run-id", "x", "--private"])
    assert res.exit_code != 0 and "--html" in res.output


@pytest.mark.skipif(not DFIR_TEXT.exists() or not (MAIN_RUN / "results" / "results.json").exists(),
                    reason="requiere la copia local del reporte de DFIR y la corrida 2026-10-18-main")
def test_main_run_public_page_has_no_dfir_text_or_iocs(tmp_path):
    """Same sources as check-repo (local DFIR copy and its IoC values), 8-word windows; output in a temp folder."""
    text = DFIR_TEXT.read_text(encoding="utf-8")
    iocs = ioc_values(extract_iocs(text, load_model_config().ioc))
    out = build_html(MAIN_RUN, tmp_path / "report.html", cli.REVIEW_SHEETS_DIR, load_scenarios(SCENARIOS_FILE),
                     dfir_text=text, iocs=iocs)
    html = out.read_text(encoding="utf-8")
    assert leak_findings(html, text, iocs) == []
    assert copied_windows(visible_text(html), text) == []
    assert str(REPO_ROOT) not in html


def test_provenance_block_in_the_page(run, tmp_path):
    from eval import provenance

    (run["run"] / "results" / "provenance.json").unlink()  # aem eval wrote one
    assert "sin dato disponible" in _build(run, tmp_path).split('class="prov"', 1)[1][:400]
    data = provenance.live(REPO_ROOT, json.loads((run["run"] / "results" / "results.json").read_text(encoding="utf-8")))
    provenance.write(run["run"] / "results", data)
    html = _build(run, tmp_path)
    block = html.split('class="prov"', 1)[1].split("</details>", 1)[0]
    assert "Provenance" in block and "Procedencia" in block and data["code"]["commit"][:12] in block
    assert str(REPO_ROOT) not in html


# --- presentation: one language per view, readable charts, navigation ------------------------------

VOID = {"meta", "br", "img", "input", "hr", "link", "col", "wbr"}
OTHER_LANGUAGE = {
    "en": ["ninguna", "ninguno", "revisión", "reconstruido", "reconstruida", "coincide", "no registrado", "sin dato",
           "sí", "True", "False", "todos", "paso", "Procedencia", "Mostrar"],
    "es": ["none", "review", "reconstructed", "matches", "not recorded", "no data", "Frozen", "True", "False",
           "Provenance", "Show more", "step", "yes"],
}


class _View(HTMLParser):
    """Text a reader sees in one language: drops the other language's spans, scripts, styles and the
    language-neutral data (`translate="no"`: scenario names, ATT&CK names, quotes; <code>: identifiers)."""

    def __init__(self, lang: str):
        super().__init__()
        self.lang, self.stack, self.out = lang, [], []

    def handle_starttag(self, tag, attrs):
        if tag in VOID:
            return
        a = dict(attrs)
        self.stack.append(tag in ("script", "style", "head", "code") or a.get("translate") == "no"
                          or (tag != "html" and a.get("lang") not in (None, self.lang)))

    def handle_endtag(self, tag):
        if tag not in VOID and self.stack:
            self.stack.pop()

    def handle_data(self, data):
        if not any(self.stack):
            self.out.append(data)


def language_view(html: str, lang: str) -> str:
    view = _View(lang)
    view.feed(html)
    return re.sub(r"\s+", " ", " ".join(view.out))


def other_language_words(html: str) -> list[tuple[str, str, str]]:
    found = []
    for lang, words in OTHER_LANGUAGE.items():
        text = language_view(html, lang)
        for w in words:
            flags = 0 if w in ("True", "False") else re.IGNORECASE
            for m in re.finditer(r"(?<!\w)" + re.escape(w) + r"(?!\w)", text, flags):
                found.append((lang, w, text[max(0, m.start() - 40):m.end() + 40]))
    return found


def test_each_language_view_shows_only_that_language(run, tmp_path):
    html = _build(run, tmp_path)
    assert other_language_words(html) == []
    assert "Show more" not in language_view(html, "es") and "revisión" in language_view(html, "es")


def test_language_check_catches_a_leftover():
    html = '<html lang="en"><body><p>reconstructed</p><p>ninguna</p><span lang="es">ninguna</span></body></html>'
    assert [(lang, w) for lang, w, _ in other_language_words(html)] == [("en", "ninguna"), ("es", "reconstructed")]


@pytest.mark.skipif(not (MAIN_RUN / "results" / "results.json").exists(), reason="sin la corrida 2026-10-18-main")
def test_main_run_page_language_labels_and_axis(tmp_path):
    html = build_html(MAIN_RUN, tmp_path / "report.html", cli.REVIEW_SHEETS_DIR,
                      load_scenarios(SCENARIOS_FILE)).read_text(encoding="utf-8")
    assert other_language_words(html) == []
    # value labels of indicators 1 and 3 (real data): estimated boxes (9 px font) never overlap
    charts = re.findall(r'<svg class="chart".*?</svg>', html, re.S)
    named = [c for c in charts if re.search(r'aria-label="Indicator [13]:', c)]
    assert len(named) == 3
    for chart in named:
        labels = [(float(x), float(y), len(v)) for x, y, v in
                  re.findall(r'<text x="([\d.]+)" y="([\d.]+)" class="val"[^>]*>([^<]*)</text>', chart)]
        boxes = [(x - n * 2.75, x + n * 2.75, y - 9, y) for x, y, n in labels]
        for i, a in enumerate(boxes):
            for b in boxes[i + 1:]:
                assert a[1] <= b[0] or b[1] <= a[0] or a[3] <= b[2] or b[3] <= a[2], (a, b)
        assert re.search(r'<g class="bar-g" tabindex="0" role="img" aria-label="[^"]+ · orig: [\d.]+ % ± [\d.]+"', chart)
    # indicator 5: every value is 0 → integer axis 0–1 and the note
    assert "0 violations in all 45 runs" in html and "0 violaciones en todas las 45 corridas" in html
    i5 = [c for c in charts if 'aria-label="Indicator 5:' in c]
    assert i5 and all(re.findall(r'class="tick"[^>]*>([^<]*)<', c) == ["0", "1"] for c in i5)
    # the model appears once in the run facts; numbering starts at 1
    assert '<dd><span translate="no">gemini-3.8-flash</span></dd>' in html
    assert re.search(r'<section id="run"[^>]*><details><summary><h2[^>]*><span lang="en">1\. ', html)
    # frozen file whose YAML data did not change (needs the run's commit: not in a shallow clone)
    shallow = subprocess.run(["git", "-C", str(REPO_ROOT), "rev-parse", "--is-shallow-repository"],
                             capture_output=True, text=True).stdout.strip() == "true"
    status = "changed; not verifiable" if shallow else "comments only; data identical"
    assert f'data/org/fictional_org.yaml</code> (<span lang="en">{status}' in html


def test_violation_axis_uses_integers():
    assert violation_ticks([0, 0, None]) == (0, 1)
    assert violation_ticks([0.4]) == (0, 1)
    assert violation_ticks([2.3, 1]) == (0, 1, 2, 3)
    assert violation_ticks([9]) == (0, 3, 6, 9)
    assert all(isinstance(x, int) for x in violation_ticks([5.5]))


def test_navigation_folding_and_show_more(run, tmp_path):
    html = _build(run, tmp_path)
    nav = html.split('<nav class="toc"', 1)[1].split("</nav>", 1)[0]
    assert re.findall(r'href="#(\w+)"', nav) == ["run", "indicators", "comparison", "distribution", "techniques",
                                                  "limits"]
    opened = re.findall(r'<section id="(\w+)"[^>]*><details( open)?>', html)
    assert [sid for sid, o in opened if o] == ["indicators"] and len(opened) == 6
    assert "<script src" not in html and "<summary>" in html
    # many techniques: 25 shown by script, a keyboard button, and the filters still read every row
    from eval import report_html

    d = {"techniques": {}, "valid_runs": {}, "private": False}
    for n in range(30):
        d["techniques"][n] = {"scenario": "gunra", "version": "orig", "technique_id": f"T{1000 + n}", "name": "x",
                              "tactics": ["execution"], "actions": report_html.Counter({"monitor": 1}),
                              "coverage": ["parcial"], "copyrighted": False, "quote": "", "quote_run": "",
                              "in_reference": True, "runs": 1, "link": "https://attack.mitre.org/techniques/T1000/"}
    table = report_html._technique_table(d)
    assert '<button id="more" type="button" aria-controls="tech" aria-expanded="false" data-limit="25">' in table
    assert table.count("<tr data-scenario=") == 30 and " hidden" not in table  # without JS every row is visible
    assert "sels.every" in report_html.JS and "'#tech tbody tr'" in report_html.JS


def test_table_of_contents_has_no_list_markers_and_separate_links(run, tmp_path):
    from eval import report_html

    html = _build(run, tmp_path)
    css = re.search(r"\.toc ol\{([^}]*)\}", report_html.CSS)[1]
    assert "list-style:none" in css and "display:flex" in css and "flex-wrap:wrap" in css and "gap:" in css
    assert re.search(r"@media \(max-width:600px\)\{[^@]*\.toc ol\{flex-direction:column", report_html.CSS)
    nav = html.split('<nav class="toc"', 1)[1].split("</nav>", 1)[0]
    assert 'aria-label="Contents / Contenido"' in html and len(re.findall(r'<a href="#\w+">', nav)) == 6

    class Text(HTMLParser):  # like the DOM's textContent: no space added between elements
        def __init__(self, lang):
            super().__init__()
            self.lang, self.stack, self.out = lang, [], ""

        def handle_starttag(self, tag, attrs):
            self.stack.append(dict(attrs).get("lang") not in (None, self.lang))

        def handle_endtag(self, tag):
            self.stack.pop()

        def handle_data(self, data):
            if not any(self.stack):
                self.out += data

    for lang in ("en", "es"):
        parser = Text(lang)
        parser.feed("<nav" + nav + "</nav>")
        text = parser.out
        for n in range(2, 7):
            assert re.search(rf"\s{n}\. ", text), (lang, text)  # each title starts after whitespace
