"""Step 4 — reference information (code + AI only for the summary).

All five fields come from ATT&CK STIX data (batch lookup) or the prevalence CSV.
The only AI call condenses the technique description; if it fails or produces
evaluative language not present in the source, the CSV shows `resumen no disponible`.
"""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from aem.attack_data import AttackData
from aem.boundaries import violations
from aem.models import TECHNIQUE_ID_PATTERN, ReferenceInfo, SummaryRecord

NO_SUMMARY = "resumen no disponible"
NO_PREVALENCE = "sin dato disponible"

_CITATION_RE = re.compile(r"\s*\(Citation:[^)]*\)")
_MD_LINK_RE = re.compile(r"\[([^\]]+)\]\([^)]+\)")


def clean_description(description: str) -> str:
    text = _CITATION_RE.sub("", description or "")
    text = _MD_LINK_RE.sub(r"\1", text)
    return re.sub(r"[ \t]+", " ", text).replace(" .", ".").strip()


def load_prevalence(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not Path(path).exists():
        return out
    with Path(path).open(encoding="utf-8-sig", newline="") as fh:
        for row in csv.DictReader(fh):
            tid = (row.get("technique_id") or "").strip()
            if not tid:
                continue
            if not re.match(TECHNIQUE_ID_PATTERN, tid):
                raise ValueError(f"ID inválido en el CSV de prevalencia: {tid!r}")
            rank = (row.get("rank") or "").strip()
            if not rank.isdigit():
                raise ValueError(f"Puesto inválido para {tid} en el CSV de prevalencia: {rank!r}")
            note = (row.get("source_note") or "").strip()
            out[tid] = f"Red Canary 2026: puesto {int(rank)}" + (f" ({note})" if note else "")
    return out


@dataclass
class SummaryOutcome:
    text: str | None
    raw: str | None = None
    meta: dict = field(default_factory=dict)
    error: str | None = None


class Summarizer(Protocol):
    def summarize(self, technique_id: str, description: str) -> SummaryOutcome: ...


def build_reference(technique_ids: list[str], attack: AttackData, prevalence: dict[str, str],
                    summarizer: Summarizer, patterns: list) -> tuple[list[ReferenceInfo], list[SummaryRecord]]:
    raw_refs = attack.reference_bundle(technique_ids)  # one batch lookup for all techniques
    refs, log = [], []
    for tid in technique_ids:
        raw = raw_refs[tid]
        source = clean_description(raw.description)
        outcome = summarizer.summarize(tid, source)
        status, found, summary = "ok", [], outcome.text
        if not outcome.text:
            status, summary = "llm_failed", NO_SUMMARY
        else:
            found = violations(outcome.text, source, patterns)
            if found:
                status, summary = "boundary_violation", NO_SUMMARY
        log.append(SummaryRecord(technique_id=tid, source_description=source, raw_summary=outcome.raw or outcome.text,
                                 status=status, violations=found, error=outcome.error, llm_meta=outcome.meta))
        refs.append(ReferenceInfo(
            technique_id=tid, summary=summary.strip(), source_link=raw.url,
            mitigations=[f"{mid} {name}" for mid, name in raw.mitigations],
            data_sources=raw.data_components, groups=raw.groups,
            prevalence=prevalence.get(tid, NO_PREVALENCE),
        ))
    return refs, log
