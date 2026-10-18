"""The five thesis indicators (CLAUDE.md §8) as pure functions over run records."""

from __future__ import annotations

import re
import statistics

from aem.attack_data import parent_of
from aem.boundaries import violations
from aem.config import CoverageConfig
from aem.models import OrgProfile
from aem.step2_coverage import assess_coverage

GAP_LEVELS = ("parcial", "sin cobertura")


def _ratio(num: int, den: int) -> float | None:
    return num / den if den else None


def aggregate(values: list[float | None]) -> dict:
    """Mean and sample standard deviation (n-1) over the defined values."""
    vals = [v for v in values if v is not None]
    return {
        "n": len(vals),
        "mean": statistics.mean(vals) if vals else None,
        "sd": statistics.stdev(vals) if len(vals) >= 2 else None,
    }


# --- indicator 1 ------------------------------------------------------------------------


def _level_scores(proposed: set[str], reference: set[str]) -> dict:
    tp = proposed & reference
    return {
        "proposed": len(proposed), "reference": len(reference), "correct": len(tp),
        "precision": _ratio(len(tp), len(proposed)),
        "recall": _ratio(len(tp), len(reference)) if reference else None,
        "omitted": sorted(reference - proposed),
        "erroneous": sorted(proposed - reference),
    }


def extraction_scores(raw_ids: list[str], reference_ids: list[str]) -> dict:
    """Precision/recall of `extracted_raw` at exact sub-technique and at parent-technique level."""
    raw, ref = set(raw_ids), set(reference_ids)
    return {
        "exact": _level_scores(raw, ref),
        "parent": _level_scores({parent_of(t) for t in raw}, {parent_of(t) for t in ref}),
    }


# --- indicator 2 ------------------------------------------------------------------------


def coverage_correctness(reference_ids: list[str], org: OrgProfile, cfg: CoverageConfig) -> dict:
    """Step 2 over the reference list vs. the gaps the author declared in `coverage_design`."""
    design = {c.technique_id: c.intended for c in org.coverage_design}
    mismatches = []
    results = assess_coverage(reference_ids, org, cfg)
    for r in results:
        intended = design.get(r.technique_id)
        if intended != r.coverage:
            mismatches.append({"technique_id": r.technique_id, "step2": r.coverage,
                               "intended": intended or "sin diseño"})
    return {"total": len(results), "matches": len(results) - len(mismatches),
            "accuracy": _ratio(len(results) - len(mismatches), len(results)), "mismatches": mismatches,
            "coverage": {r.technique_id: r.coverage for r in results}}


def gap_techniques(reference_ids: list[str], org: OrgProfile, cfg: CoverageConfig) -> list[str]:
    return [r.technique_id for r in assess_coverage(reference_ids, org, cfg) if r.coverage in GAP_LEVELS]


# --- indicator 3 ------------------------------------------------------------------------


def model_persistence(raw_ids: list[str], gap_ids: list[str]) -> float | None:
    """Share of the scenario's gap techniques that the model flags (exact ID in `extracted_raw`)."""
    gaps = set(gap_ids)
    return _ratio(len(gaps & set(raw_ids)), len(gaps))


def traditional_persistence(recognized_orig: bool, recognized_mut: bool) -> dict:
    orig, mut = float(recognized_orig), float(recognized_mut)
    return {"orig": orig, "mut": mut, "ratio": mut / orig if orig else None}


# --- indicator 4 ------------------------------------------------------------------------

_SENTENCE_END = re.compile(r"[.!?](?:\s|$)")
_ATTACK_LIKE_ID = re.compile(r"\b(?:T\d{4}(?:\.\d{3})?|TA\d{4}|M\d{4}|G\d{4}|S\d{4}|C\d{4}|DS\d{4}|DC\d{4})\b")
_NUMBER = re.compile(r"\b\d+(?:[.,]\d+)?\b")


def count_sentences(text: str) -> int:
    return len(_SENTENCE_END.findall(text.strip() + " "))


def summary_auto_check(summary: str, source: str, max_sentences: int) -> dict:
    """Basic automatic fidelity check; the manual review sheet is the real measure."""
    issues = []
    for tok in sorted(set(_ATTACK_LIKE_ID.findall(summary))):
        if tok not in source:
            issues.append(f"ID ausente en la fuente: {tok}")
    for num in sorted(set(_NUMBER.findall(summary))):
        if num not in source:
            issues.append(f"cifra ausente en la fuente: {num}")
    n = count_sentences(summary)
    if n > max_sentences:
        issues.append(f"{n} oraciones (máximo {max_sentences})")
    return {"ok": not issues, "issues": issues, "sentences": n}


# --- indicator 5 ------------------------------------------------------------------------


def boundary_violations_extraction(items: list[tuple[str, str, str]], report_text: str, extra_fields: list[str],
                                   patterns: list[re.Pattern], official_names: dict[str, str] | None = None) -> dict:
    """Violations in step 1 output: extra schema fields + evaluative text absent from the source.

    `items` are (technique_id, technique_name, evidence_quote) as returned by the LLM.
    """
    official_names = official_names or {}
    found = []
    for tid, name, quote in items:
        source = report_text + "\n" + official_names.get(tid, "")
        for field_name, text in (("technique_name", name), ("evidence_quote", quote)):
            for match in violations(text, source, patterns):
                found.append({"technique_id": tid, "field": field_name, "match": match})
    return {"extra_fields": len(extra_fields), "evaluative_text": len(found), "total": len(extra_fields) + len(found),
            "details": found, "extra_field_names": list(extra_fields)}
