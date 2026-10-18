"""Orchestration of the four steps (used by `aem run`, `aem demo` and `aem eval`)."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from aem.attack_data import AttackData
from aem.config import ModelConfig
from aem.llm import TEMPERATURE, GeminiClient, LLMError
from aem.models import CoverageResult, ExtractionRecord, GlobalReview, OrgProfile, PrioritizedTechnique, SummaryRecord
from aem.output import build_rows, write_csv, write_global_review, write_json
from aem.step1_extract import AutoReviewer, InteractiveReviewer, extract, review, validate_candidates
from aem.step2_coverage import assess_coverage
from aem.step3_prioritize import AutoAnalyst, InteractiveAnalyst, SsvcTree, chain_order, prioritize
from aem.step4_reference import LLMSummarizer, Summarizer, build_reference

# Step 4 summaries depend only on the technique description, so they always use
# replicate 0: one cached summary per technique, shared by every scenario and run (D-44).
SUMMARY_REPLICATE = 0


class EmptyExtraction(LLMError):
    """Step 1 produced no usable technique; the record is attached so it can still be saved."""

    def __init__(self, message: str, extraction: ExtractionRecord):
        super().__init__(message)
        self.extraction = extraction


@dataclass
class PipelineContext:
    attack: AttackData
    org: OrgProfile
    client: GeminiClient
    model_cfg: ModelConfig
    tree: SsvcTree
    prevalence: dict[str, str]
    patterns: list[re.Pattern]
    summarizer: Summarizer | None = None
    console: object | None = None

    def get_summarizer(self) -> Summarizer:
        if self.summarizer is None:
            self.summarizer = LLMSummarizer(self.client, self.model_cfg.summary.max_sentences,
                                            replicate=SUMMARY_REPLICATE)
        return self.summarizer


@dataclass
class PipelineResult:
    extraction: ExtractionRecord
    coverage: list[CoverageResult]
    prioritized: list[PrioritizedTechnique]
    summaries: list[SummaryRecord]
    global_review: GlobalReview
    rows: list[dict]
    meta: dict = field(default_factory=dict)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def run_step1(report_text: str, ctx: PipelineContext, analyst_mode: str, replicate: int = 0,
              private: bool = False) -> ExtractionRecord:
    run = extract(report_text, ctx.client, ctx.model_cfg.extraction, ctx.attack.version, replicate=replicate,
                  private=private)
    candidates = validate_candidates(run.extracted_raw, ctx.attack, report_text)
    reviewer = AutoReviewer() if analyst_mode == "auto" else InteractiveReviewer(console=ctx.console)
    validated, actions = review(candidates, reviewer, ctx.attack)
    return ExtractionRecord(
        report_sha256=_sha256(report_text), attack_version=ctx.attack.version, chunks=run.chunks,
        extracted_raw=run.extracted_raw, extra_fields=run.extra_fields, candidates=candidates,
        analyst_mode=analyst_mode, analyst_actions=actions, extracted_validated=validated, llm_calls=run.llm_calls,
    )


def run_pipeline(report_text: str, ctx: PipelineContext, analyst_mode: str = "auto",
                 replicate: int = 0, private: bool = False) -> PipelineResult:
    """`private=True` for copyrighted reports: step 1 requests use the git-ignored private cache."""
    if analyst_mode not in ("auto", "interactive"):
        raise ValueError(f"Modo de analista desconocido: {analyst_mode!r} (use interactive o auto)")
    started = datetime.now(timezone.utc).isoformat(timespec="seconds")

    extraction = run_step1(report_text, ctx, analyst_mode, replicate, private)
    if not extraction.extracted_validated:
        raise EmptyExtraction(
            "El paso 1 no produjo ninguna técnica válida (respuesta vacía del LLM o todas rechazadas). "
            "Revise la respuesta cruda guardada.", extraction)
    ids = [t.technique_id for t in extraction.extracted_validated]

    coverage = assess_coverage(ids, ctx.org, ctx.model_cfg.coverage)
    analyst = AutoAnalyst(ctx.org) if analyst_mode == "auto" else InteractiveAnalyst(ctx.org, console=ctx.console)
    prioritized = prioritize(coverage, ctx.attack, analyst, ctx.tree)
    global_review = analyst.global_review(chain_order(prioritized, ctx.attack), ctx.attack)

    refs, summaries = build_reference(ids, ctx.attack, ctx.prevalence, ctx.get_summarizer(), ctx.patterns)
    rows = build_rows(prioritized, refs, ctx.attack)

    meta = {
        "started": started, "finished": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "model": ctx.client.model, "temperature": TEMPERATURE, "demo": ctx.client.demo,
        "attack_version": ctx.attack.version, "analyst_mode": analyst_mode, "replicate": replicate,
        "private": private,
        "summary_replicate": SUMMARY_REPLICATE, "report_sha256": extraction.report_sha256,
        "prompt_sha256": sorted({c["prompt_sha256"] for c in extraction.llm_calls}),
    }
    return PipelineResult(extraction=extraction, coverage=coverage, prioritized=prioritized, summaries=summaries,
                          global_review=global_review, rows=rows, meta=meta)


def write_record(path: Path, extraction: ExtractionRecord, meta: dict, **parts) -> None:
    data = {"meta": meta, "extraction": extraction.model_dump(mode="json")}
    for key, items in parts.items():
        data[key] = [i.model_dump(mode="json") for i in items]
    write_json(path, data)


def write_outputs(result: PipelineResult, out_dir: Path, stem: str) -> dict[str, Path]:
    out_dir = Path(out_dir)
    paths = {
        "csv": out_dir / f"{stem}_exposure.csv",
        "global_review": out_dir / "global_review.json",
        "record": out_dir / "run_record.json",
    }
    write_csv(paths["csv"], result.rows)
    write_global_review(paths["global_review"], result.global_review)
    write_record(paths["record"], result.extraction, result.meta, coverage=result.coverage,
                 prioritization=result.prioritized, summaries=result.summaries)
    return paths
