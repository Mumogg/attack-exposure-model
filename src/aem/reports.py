"""Report preparation: CISA HTML → text, reference mapping extraction and ATT&CK stripping (D-10).

The text given to the LLM (`*_stripped.txt`) must not contain the ATT&CK mapping
section or any technique/tactic ID, otherwise step 1 would copy the answer.
Only IDs are removed from body sentences; the sentences themselves stay readable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from html import unescape
from html.parser import HTMLParser

# --- HTML → text ------------------------------------------------------------------

_BLOCK_TAGS = {"p", "li", "ul", "ol", "div", "br", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote", "pre"}
_SKIP_TAGS = {"script", "style", "noscript"}


class _CisaParser(HTMLParser):
    """Keeps the page title and the imported advisory body (`div.l-page-section--rich-text.csaf-imported`)."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title: list[str] = []
        self.in_title = False
        self.depth = 0  # div depth inside the content region (0 = outside)
        self.skip = 0
        self.blocks: list[tuple[str, str]] = []  # (kind, text) with kind in {"text", "row"}
        self.buf: list[str] = []
        self.table = 0
        self.cells: list[str] | None = None
        self.cell: list[str] | None = None
        self.caption: list[str] | None = None

    def handle_starttag(self, tag, attrs):
        cls = (dict(attrs).get("class") or "").split()
        if tag == "h1" and "c-page-title__title" in cls:
            self.in_title = True
        if tag == "div":
            if self.depth:
                self.depth += 1
            elif "l-page-section--rich-text" in cls and "csaf-imported" in cls:
                self.depth = 1
                return
        if not self.depth:
            return
        if tag in _SKIP_TAGS:
            self.skip += 1
        elif tag == "table":
            self._flush()
            self.table += 1
        elif self.table and tag == "caption":
            self.caption = []
        elif self.table and tag == "tr":
            self.cells = []
        elif self.table and tag in ("td", "th"):
            self.cell = []
        elif self.table and self.cell is not None and tag in _BLOCK_TAGS:
            self.cell.append(" - " if tag == "li" else " ")
        elif not self.table and tag in _BLOCK_TAGS:
            self._flush()
            if tag[0] == "h" and tag[1:].isdigit():
                self.buf.append("#" * int(tag[1]) + " ")
            elif tag == "li":
                self.buf.append("- ")

    def handle_endtag(self, tag):
        if tag == "h1" and self.in_title:
            self.in_title = False
        if not self.depth:
            return
        if tag == "div":
            self.depth -= 1
        if tag in _SKIP_TAGS:
            self.skip -= 1
        elif tag == "table":
            self.table -= 1
            self.blocks.append(("text", ""))
        elif self.table and tag == "caption" and self.caption is not None:
            self.blocks.append(("text", _squash("".join(self.caption))))
            self.caption = None
        elif self.table and tag in ("td", "th") and self.cell is not None and self.cells is not None:
            self.cells.append(_squash("".join(self.cell)))
            self.cell = None
        elif self.table and tag == "tr" and self.cells is not None:
            if any(self.cells):
                self.blocks.append(("row", "| " + " | ".join(self.cells) + " |"))
            self.cells = None
        elif not self.table and tag in _BLOCK_TAGS:
            self._flush()

    def handle_data(self, data):
        if self.in_title:
            self.title.append(data)
        if not self.depth or self.skip:
            return
        if self.caption is not None:
            self.caption.append(data)
        elif self.cell is not None:
            self.cell.append(data)
        elif not self.table:
            self.buf.append(data)

    def _flush(self):
        text = _squash("".join(self.buf))
        if text and text not in ("-", "#", "##", "###"):
            self.blocks.append(("text", text))
        self.buf = []


def _squash(text: str) -> str:
    return re.sub(r"\s+", " ", unescape(text).replace("\xa0", " ")).strip()


def html_to_text(html: str) -> str:
    p = _CisaParser()
    p.feed(html)
    p.close()
    p._flush()
    out: list[str] = []
    title = _squash("".join(p.title))
    if title:
        out.append(f"# {title}\n")
    prev = None
    for kind, text in p.blocks:
        if not text:
            prev = None
            continue
        if kind == "row" and prev == "row":
            out[-1] += "\n" + text
        else:
            out.append(text)
        prev = kind
    return "\n\n".join(s.strip("\n") for s in out).strip() + "\n"


# --- ATT&CK IDs ---------------------------------------------------------------------

_ID = r"(?:TA\d{4}|T\d{4}(?:\.\d{3})?)"
_ID_LIST = rf"{_ID}(?:[ \t]*[,;/][ \t]*{_ID})*"
_BRACKETED = re.compile(rf"[ \t]*(?:\[[ \t]*{_ID_LIST}[ \t]*\])+", re.IGNORECASE)
_PARENS = re.compile(rf"[ \t]*\([ \t]*{_ID_LIST}[ \t]*\)", re.IGNORECASE)
_BARE = re.compile(rf"[ \t]*\b{_ID}\b", re.IGNORECASE)
_ANY_ID = re.compile(rf"\b{_ID}\b", re.IGNORECASE)


def scrub_attack_ids(text: str) -> tuple[str, list[str]]:
    """Remove every technique/sub-technique/tactic ID; keep the sentence around it."""
    found = [m.group(0) for m in _ANY_ID.finditer(text)]
    for rx in (_BRACKETED, _PARENS, _BARE):
        text = rx.sub("", text)
    text = re.sub(r"[ \t]{2,}", " ", text)
    text = "\n".join(line.rstrip() for line in text.split("\n"))
    return text, found


# --- sections -------------------------------------------------------------------------

_HEADING = re.compile(r"^(#{1,6}) (.+)$")
_CISA_ATTACK_HEADING = re.compile(r"^MITRE ATT&CK®? Tactics and Techniques$", re.IGNORECASE)
_CISA_NOTE = re.compile(r"^Note: This advisory uses the MITRE ATT&CK", re.IGNORECASE)
_TABLE_CAPTION = re.compile(r"^Table \d+[.:]\s*(.+?)\s*$")


class AttackSectionNotFound(ValueError):
    pass


def _section_bounds(lines: list[str], is_heading) -> tuple[int, int]:
    for i, line in enumerate(lines):
        m = _HEADING.match(line)
        if m and is_heading(m.group(2).strip()):
            level = len(m.group(1))
            for j in range(i + 1, len(lines)):
                n = _HEADING.match(lines[j])
                if n and len(n.group(1)) <= level:
                    return i, j
            return i, len(lines)
    raise AttackSectionNotFound("No se encontró la sección del mapeo ATT&CK en el reporte")


def _tidy(text: str) -> str:
    return re.sub(r"\n{3,}", "\n\n", text).strip() + "\n"


def strip_cisa(text: str) -> tuple[str, list[dict]]:
    lines = text.split("\n")
    i, j = _section_bounds(lines, _CISA_ATTACK_HEADING.match)
    log = [{"kind": "section", "heading": lines[i].lstrip("# ").strip(), "lines": sum(bool(x.strip()) for x in lines[i:j])}]
    lines = lines[:i] + lines[j:]
    kept = []
    for line in lines:
        if _CISA_NOTE.match(line.strip()):
            log.append({"kind": "note", "text": line.strip()})
        else:
            kept.append(line)
    scrubbed, ids = scrub_attack_ids("\n".join(kept))
    log.append({"kind": "ids", "count": len(ids), "distinct": sorted(set(ids))})
    return _tidy(scrubbed), log


def norm_heading(line: str) -> str:
    return re.sub(r"[®:]", "", line.lstrip("#").strip()).strip().lower()


def strip_plain(text: str, heading: str, end_headings: list[str]) -> tuple[str, list[dict]]:
    """For plain-text reports (DFIR): drop the ATT&CK section from its heading line to the next end heading."""
    lines = text.split("\n")
    target = norm_heading(heading)
    ends = {norm_heading(h) for h in end_headings}
    start = next((i for i, line in enumerate(lines) if norm_heading(line) == target), None)
    if start is None:
        raise AttackSectionNotFound(
            f"No se encontró una línea con el encabezado «{heading}» en el reporte. Colóquela sola en una línea "
            "antes del listado de técnicas (ver docs/report_preparation.md).")
    end = next((j for j in range(start + 1, len(lines)) if norm_heading(lines[j]) in ends), len(lines))
    log = [{"kind": "section", "heading": lines[start].strip(), "lines": sum(bool(x.strip()) for x in lines[start:end])}]
    scrubbed, ids = scrub_attack_ids("\n".join(lines[:start] + lines[end:]))
    log.append({"kind": "ids", "count": len(ids), "distinct": sorted(set(ids))})
    return _tidy(scrubbed), log


# --- reference mapping from CISA tables -----------------------------------------------


@dataclass
class ReferenceRow:
    technique_id: str
    technique_name: str
    tactic: str


def extract_cisa_reference(text: str) -> tuple[list[ReferenceRow], list[tuple[str, str, str]]]:
    """Technique rows of the ATT&CK tables (+ tactic-ID rows, which are excluded from the reference, D-61)."""
    lines = text.split("\n")
    i, j = _section_bounds(lines, _CISA_ATTACK_HEADING.match)
    techniques: list[ReferenceRow] = []
    tactic_rows: list[tuple[str, str, str]] = []
    tactic = ""
    for line in lines[i + 1:j]:
        cap = _TABLE_CAPTION.match(line.strip())
        if cap:
            tactic = cap.group(1)
            continue
        if not line.startswith("| "):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split(" | ")]
        if len(cells) < 2:
            continue
        for tid in re.findall(_ID, cells[1]):
            if tid.startswith("TA"):
                tactic_rows.append((tid, cells[0], tactic))
            else:
                techniques.append(ReferenceRow(tid, cells[0], tactic))
    return techniques, tactic_rows
