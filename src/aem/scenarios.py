"""Scenario catalog (`data/scenarios.yaml`), report preparation and reference mappings."""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass, field, replace
from pathlib import Path

from aem.attack_data import AttackData
from aem.config import DATA_DIR, load_yaml
from aem.output import write_json
from aem.reports import (
    ReferenceRow, norm_heading, extract_cisa_reference, html_to_text, strip_cisa, strip_plain,
)

REFERENCE_COLUMNS = ("technique_id", "technique_name", "tactic", "valid_in_v19_2", "v19_2_status",
                     "v19_2_replacement")
VERSIONS = ("orig", "mut")


@dataclass(frozen=True)
class Scenario:
    name: str
    title: str
    source: str  # cisa | dfir
    url: str
    text_rel: str
    reference_rel: str
    published: str = ""
    advisory: str = ""
    attack_heading: str = "MITRE ATT&CK"
    end_headings: tuple[str, ...] = field(default_factory=tuple)
    data_dir: Path = DATA_DIR

    @property
    def text(self) -> Path:
        return self.data_dir / self.text_rel

    def _sibling(self, suffix: str) -> Path:
        return self.text.with_name(self.text.stem + suffix)

    @property
    def stripped(self) -> Path:
        return self._sibling("_stripped.txt")

    @property
    def variant(self) -> Path:
        return self._sibling("_mut_stripped.txt")

    @property
    def variant_diff(self) -> Path:
        return self._sibling("_mut.diff")

    @property
    def preparation_log(self) -> Path:
        return self._sibling("_preparation.json")

    @property
    def raw_html(self) -> Path:
        return self.text.parent / "raw" / (self.text.stem + ".html")

    @property
    def reference(self) -> Path:
        return self.data_dir / self.reference_rel

    def report_for(self, version: str) -> Path:
        if version not in VERSIONS:
            raise ValueError(f"Versión desconocida: {version!r} (use orig o mut)")
        return self.stripped if version == "orig" else self.variant

    def relocated(self, data_dir: Path) -> "Scenario":
        return replace(self, data_dir=Path(data_dir))


def load_scenarios(path: Path) -> dict[str, Scenario]:
    out = {}
    for name, d in load_yaml(path).items():
        out[name] = Scenario(
            name=name, title=d["title"], source=d["source"], url=d["url"], text_rel=d["text"],
            reference_rel=d["reference"], published=str(d.get("published", "")), advisory=d.get("advisory", ""),
            attack_heading=d.get("attack_heading", "MITRE ATT&CK"), end_headings=tuple(d.get("end_headings") or ()),
            data_dir=Path(path).parent,
        )
    return out


# --- reference mappings -----------------------------------------------------------------


@dataclass(frozen=True)
class ReferenceEntry:
    technique_id: str
    technique_name: str
    tactic: str
    valid: bool


def write_reference_csv(path: Path, rows: list[ReferenceRow], attack: AttackData) -> None:
    merged: dict[str, dict] = {}
    for r in rows:
        if r.technique_id in merged:
            tactics = merged[r.technique_id]["tactic"].split("; ")
            if r.tactic and r.tactic not in tactics:
                merged[r.technique_id]["tactic"] = "; ".join(tactics + [r.tactic])
            continue
        v = attack.validate_id(r.technique_id)
        merged[r.technique_id] = {
            "technique_id": r.technique_id, "technique_name": r.technique_name, "tactic": r.tactic,
            "valid_in_v19_2": "si" if v.is_valid else "no", "v19_2_status": v.status.value,
            "v19_2_replacement": v.replacement or "",
        }
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=REFERENCE_COLUMNS)
        writer.writeheader()
        writer.writerows(merged.values())


def load_reference(path: Path) -> list[ReferenceEntry]:
    if not Path(path).exists():
        raise FileNotFoundError(f"No existe el mapeo de referencia {path}")
    with Path(path).open(encoding="utf-8-sig", newline="") as fh:
        return [ReferenceEntry(r["technique_id"], r["technique_name"], r["tactic"], r["valid_in_v19_2"] == "si")
                for r in csv.DictReader(fh)]


# --- preparation ----------------------------------------------------------------------------


def prepare_cisa(sc: Scenario, html: str, attack: AttackData) -> dict:
    """HTML → full text, stripped text (D-10) and reference mapping (D-61)."""
    text = html_to_text(html)
    stripped, removed = strip_cisa(text)
    techniques, tactic_rows = extract_cisa_reference(text)
    sc.text.parent.mkdir(parents=True, exist_ok=True)
    sc.text.write_text(text, encoding="utf-8")
    sc.stripped.write_text(stripped, encoding="utf-8")
    write_reference_csv(sc.reference, techniques, attack)
    log = {
        "scenario": sc.name, "source_url": sc.url, "removed": removed,
        "reference_techniques": len({t.technique_id for t in techniques}),
        "tactic_rows_excluded": [{"id": i, "name": n, "table": t} for i, n, t in tactic_rows],
    }
    write_json(sc.preparation_log, log)
    return log


def extract_plain_reference(text: str, heading: str, end_headings: list[str]) -> list[str]:
    lines = text.split("\n")
    target = norm_heading(heading)
    ends = {norm_heading(h) for h in end_headings}
    start = next((i for i, line in enumerate(lines) if norm_heading(line) == target), None)
    if start is None:
        return []
    ids: list[str] = []
    for line in lines[start + 1:]:
        if norm_heading(line) in ends:
            break
        ids += [t for t in re.findall(r"\bT\d{4}(?:\.\d{3})?\b", line) if t not in ids]
    return ids


def prepare_plain(sc: Scenario, expected_ids: list[str]) -> dict:
    """For the DFIR text that Sebas places locally: strip the ATT&CK section and every ID."""
    if not sc.text.exists():
        raise FileNotFoundError(
            f"Falta el texto del reporte en {sc.text}. Descárguelo de {sc.url} y guárdelo ahí como texto plano "
            "(ver docs/report_preparation.md). No se incluye en el repositorio por derechos de autor.")
    text = sc.text.read_text(encoding="utf-8")
    found = extract_plain_reference(text, sc.attack_heading, list(sc.end_headings))
    stripped, removed = strip_plain(text, sc.attack_heading, list(sc.end_headings))
    sc.stripped.write_text(stripped, encoding="utf-8")
    missing, extra = sorted(set(expected_ids) - set(found)), sorted(set(found) - set(expected_ids))
    check = "coincide" if not (missing or extra) else f"NO coincide: faltan {missing}, sobran {extra}"
    log = {"scenario": sc.name, "source_url": sc.url, "removed": removed, "reference_check": check}
    write_json(sc.preparation_log, log)
    return log
