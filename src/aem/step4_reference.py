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


SUMMARY_PROMPT = "summary_v1.txt"
SUMMARY_SCHEMA = {"type": "object", "properties": {"summary": {"type": "string"}}, "required": ["summary"]}


class LLMSummarizer:
    """The only AI use in step 4: condensing the (cleaned) ATT&CK description."""

    def __init__(self, client, max_sentences: int = 3, replicate: int = 0):
        from importlib import resources

        self.client = client
        self.max_sentences = max_sentences
        self.replicate = replicate
        self.template = resources.files("aem.prompts").joinpath(SUMMARY_PROMPT).read_text(encoding="utf-8")

    def summarize(self, technique_id: str, description: str) -> SummaryOutcome:
        from aem.llm import LLMError

        prompt = self.template.format(max_sentences=self.max_sentences, description=description)
        try:
            res = self.client.generate_json(prompt, SUMMARY_SCHEMA, purpose=f"step4_summary[{technique_id}]",
                                            replicate=self.replicate)
        except LLMError as exc:
            return SummaryOutcome(text=None, error=str(exc))
        text = res.data.get("summary") if isinstance(res.data, dict) else None
        meta = dict(res.meta, prompt_template=SUMMARY_PROMPT)
        return SummaryOutcome(text=text if isinstance(text, str) and text.strip() else None, raw=res.raw_text,
                              meta=meta, error=None if text else "respuesta sin campo summary")
