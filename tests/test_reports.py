import re
from pathlib import Path

import pytest

from aem.config import DATA_DIR
from aem.reports import (
    AttackSectionNotFound, extract_cisa_reference, html_to_text, scrub_attack_ids, strip_cisa, strip_plain,
)

ID_PATTERNS = (re.compile(r"\bT\d{4}(\.\d{3})?\b"), re.compile(r"\bTA\d{4}\b"))

HTML = """<html><body>
<h1 class="c-page-title__title"> #StopRansomware: Test </h1>
<nav><h2>Menu</h2><p>Not content</p></nav>
<div class="l-page-section l-page-section--rich-text csaf-imported"><div class="l-constrain">
<h2><strong>Technical Details</strong></h2>
<p>Note: This advisory uses the MITRE ATT&amp;CK® Matrix for Enterprise framework, version 17. See the table.</p>
<h3>Initial Access</h3>
<p>The actors exploited devices [T1190], including firewalls.<sup>3</sup></p>
<script>var x = 1;</script>
<h2><a class="ck-anchor" id="MITRE"><strong>MITRE ATT&amp;CK Tactics and Techniques</strong></a></h2>
<p>See Table 1.</p>
<p><strong>Table 1. Initial Access</strong></p>
<table><tr><th>Technique Title</th><th>ID</th><th>Use</th></tr>
<tr><td>Drive-By Compromise</td><td>T1189</td><td><p>Payloads such as:</p><ul><li>a.exe</li><li>b.exe</li></ul></td></tr>
<tr><td>Collection</td><td>TA0009</td><td>Collected data.</td></tr>
</table>
<table><caption><a class="ck-anchor" id="Table2"></a>Table 2. Lateral Movement</caption>
<tr><th>Technique Title</th><th>ID</th><th>Use</th></tr>
<tr><td>Remote Services: SMB/Windows Admin Shares</td><td>T1021.002, T1021.001</td><td>Moved.</td></tr>
</table>
<h2>Mitigations</h2>
<p>Patch things.</p>
</div></div>
<div class="l-page-section--rich-text"><p>Footer outside content</p></div>
</body></html>"""


@pytest.fixture
def text():
    return html_to_text(HTML)


def test_html_to_text_keeps_only_advisory_content(text):
    assert text.startswith("# #StopRansomware: Test\n")
    assert "## Technical Details" in text and "### Initial Access" in text
    assert "Not content" not in text and "Footer outside" not in text and "var x" not in text


def test_table_cells_with_lists_stay_on_one_row(text):
    row = next(line for line in text.splitlines() if "T1189" in line)
    assert row.startswith("| Drive-By Compromise | T1189 |")
    assert "a.exe" in row and "b.exe" in row


def test_extract_cisa_reference(text):
    techniques, tactic_rows = extract_cisa_reference(text)
    assert [(t.technique_id, t.technique_name, t.tactic) for t in techniques] == [
        ("T1189", "Drive-By Compromise", "Initial Access"),
        ("T1021.002", "Remote Services: SMB/Windows Admin Shares", "Lateral Movement"),
        ("T1021.001", "Remote Services: SMB/Windows Admin Shares", "Lateral Movement"),
    ]
    assert tactic_rows == [("TA0009", "Collection", "Initial Access")]


@pytest.mark.parametrize("raw,expected", [
    ("exploited devices [T1190], including firewalls.", "exploited devices, including firewalls."),
    ("not present [T1078.001][T1078.002]. Then", "not present. Then"),
    ("internal email [TA0009][T1114]. Gunra", "internal email. Gunra"),
    ("dumping [T1003.003, T1003.001] against", "dumping against"),
    ("tools (T1219) were used", "tools were used"),
    ("Sigma tag attack.t1059.001 here", "Sigma tag attack. here"),
    ("technique T1059.003 ran", "technique ran"),
    ("hash 9f86d081884c7d659a2feaa0c55ad015 stays", "hash 9f86d081884c7d659a2feaa0c55ad015 stays"),
])
def test_scrub_attack_ids(raw, expected):
    assert scrub_attack_ids(raw)[0] == expected


def test_strip_cisa_removes_section_note_and_ids(text):
    stripped, log = strip_cisa(text)
    assert "MITRE ATT&CK Tactics and Techniques" not in stripped
    assert "Drive-By Compromise" not in stripped and "Table 1." not in stripped
    assert "uses the MITRE ATT&CK" not in stripped
    assert "exploited devices, including firewalls." in stripped
    assert "## Mitigations" in stripped and "Patch things." in stripped
    assert not any(p.search(stripped) for p in ID_PATTERNS)
    kinds = {e["kind"] for e in log}
    assert {"section", "note", "ids"} <= kinds


def test_strip_plain_removes_heading_to_next_heading():
    raw = "Intro text T1190 here.\n\nIndicators\n1.2.3.4\n\nMITRE ATT&CK\nCreate Account - T1136\nData Encrypted - T1486\n\nEnd"
    stripped, log = strip_plain(raw, heading="MITRE ATT&CK", end_headings=["End"])
    assert "Create Account" not in stripped and "MITRE ATT&CK" not in stripped
    assert "1.2.3.4" in stripped and stripped.rstrip().endswith("End")
    assert "Intro text here." in stripped
    assert log[0]["kind"] == "section" and log[0]["lines"] == 3


def test_strip_plain_requires_section():
    with pytest.raises(AttackSectionNotFound):
        strip_plain("no section here", heading="MITRE ATT&CK", end_headings=[])


def test_no_attack_ids_in_any_stripped_report():
    """D-10: fails if any *_stripped.txt (including a locally placed Akira text) still contains an ID."""
    files = sorted((DATA_DIR / "reports").glob("*_stripped.txt"))
    for f in files:
        content = f.read_text(encoding="utf-8")
        for p in ID_PATTERNS:
            m = p.search(content)
            assert m is None, f"{f.name} contiene {m.group(0)}"
