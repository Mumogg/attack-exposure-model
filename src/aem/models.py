"""Pydantic schemas shared by every step of the pipeline."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

TECHNIQUE_ID_PATTERN = r"^T\d{4}(\.\d{3})?$"

Criticality = Literal["alta", "media", "baja"]
Exposure = Literal["internet", "interna", "aislada"]
Coverage = Literal["cubierta", "parcial", "sin cobertura"]
Action = Literal["Track", "Track*", "Attend", "Act"]

ACTION_ORDER: tuple[Action, ...] = ("Track", "Track*", "Attend", "Act")
COVERAGE_LEVELS: tuple[Coverage, ...] = ("cubierta", "parcial", "sin cobertura")


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# --- Organization profile (DeTT&CT-style, simplified) --------------------------


class Asset(Strict):
    id: str
    name: str
    criticality: Criticality
    processes_regulated_data: bool
    exposure: Exposure


class DataSourceEntry(Strict):
    name: str
    quality: int = Field(ge=0, le=5)


class Detection(Strict):
    technique_id: str = Field(pattern=TECHNIQUE_ID_PATTERN)
    score: int = Field(ge=0, le=5)
    data_sources: list[str] = Field(default_factory=list)
    comment: str = ""


class AnalystContextEntry(Strict):
    technique_id: str = Field(pattern=TECHNIQUE_ID_PATTERN)
    asset_id: str


class AnalystContext(Strict):
    default_asset_id: str
    entries: list[AnalystContextEntry] = Field(default_factory=list)


class KnownIoc(Strict):
    type: Literal["md5", "sha1", "sha256", "sha512", "ipv4", "domain", "url", "email", "qtox", "account"]
    value: str
    scenario: str = ""


class CoverageDesign(Strict):
    """Gap that the author intends for a technique (ground truth for indicator 2)."""

    technique_id: str = Field(pattern=TECHNIQUE_ID_PATTERN)
    intended: Coverage


class OrgProfile(Strict):
    organization: str
    assets: list[Asset]
    data_sources: list[DataSourceEntry] = Field(default_factory=list)
    detections: list[Detection] = Field(default_factory=list)
    analyst_context: AnalystContext
    known_iocs: list[KnownIoc] = Field(default_factory=list)
    known_iocs_file: str | None = None
    known_iocs_private_file: str | None = None  # git-ignored (D-76)
    coverage_design: list[CoverageDesign] = Field(default_factory=list)

    @model_validator(mode="after")
    def _cross_checks(self) -> "OrgProfile":
        asset_ids = [a.id for a in self.assets]
        dupes = {a for a in asset_ids if asset_ids.count(a) > 1}
        if dupes:
            raise ValueError(f"Activos duplicados: {sorted(dupes)}")
        unknown = {self.analyst_context.default_asset_id} | {e.asset_id for e in self.analyst_context.entries}
        unknown -= set(asset_ids)
        if unknown:
            raise ValueError(f"analyst_context referencia activos inexistentes: {sorted(unknown)}")
        for field_name, ids in (
            ("detections", [d.technique_id for d in self.detections]),
            ("analyst_context.entries", [e.technique_id for e in self.analyst_context.entries]),
            ("coverage_design", [c.technique_id for c in self.coverage_design]),
        ):
            dupes = {i for i in ids if ids.count(i) > 1}
            if dupes:
                raise ValueError(f"IDs duplicados en {field_name}: {sorted(dupes)}")
        declared = {d.name for d in self.data_sources}
        for det in self.detections:
            missing = set(det.data_sources) - declared
            if missing:
                raise ValueError(
                    f"La detección de {det.technique_id} usa fuentes no declaradas en data_sources: {sorted(missing)}"
                )
        return self

    def asset(self, asset_id: str) -> Asset:
        return next(a for a in self.assets if a.id == asset_id)

    def context_entry(self, technique_id: str) -> AnalystContextEntry | None:
        return next((e for e in self.analyst_context.entries if e.technique_id == technique_id), None)

    def asset_for(self, technique_id: str) -> Asset:
        entry = self.context_entry(technique_id)
        return self.asset(entry.asset_id if entry else self.analyst_context.default_asset_id)

    def detection_for(self, technique_id: str) -> Detection | None:
        return next((d for d in self.detections if d.technique_id == technique_id), None)


# --- Step 1: LLM extraction schema (fixed; no evaluative fields) ----------------


class ExtractedTechnique(Strict):
    technique_id: str
    technique_name: str
    evidence_quote: str


class ExtractionResponse(Strict):
    techniques: list[ExtractedTechnique]

    @field_validator("techniques")
    @classmethod
    def _strip(cls, v: list[ExtractedTechnique]) -> list[ExtractedTechnique]:
        return [t.model_copy(update={"technique_id": t.technique_id.strip()}) for t in v]


# --- Step 2: coverage --------------------------------------------------------------


class CoverageResult(Strict):
    technique_id: str
    coverage: Coverage
    score: int | None
    data_sources: list[str]
    basis: Literal["own_entry", "no_entry", "inherited_parent"]
    inherited_from: str | None = None


# --- Step 3: prioritization (analyst + adapted SSVC tree) -----------------------


class PrioritizedTechnique(Strict):
    technique_id: str
    technique_name: str
    tactics: list[str]
    coverage_original: Coverage
    coverage_validated: Coverage
    coverage_change_reason: str = ""
    asset_id: str
    criticality: Criticality
    exposure: Exposure | None
    action: Action
    context_source: Literal["analyst_context", "default_asset", "interactive"]


class ChainItem(Strict):
    technique_id: str
    technique_name: str
    tactics: list[str]
    coverage_validated: Coverage


class GlobalReview(Strict):
    question: str
    answer: bool | None
    tactics: list[str] = Field(default_factory=list)
    note: str = ""
    mode: Literal["interactive", "auto"]
    techniques_shown: list[ChainItem]
    timestamp: str


# --- Step 4: reference information (exactly five reference fields + link) ------------


class ReferenceInfo(Strict):
    technique_id: str
    summary: str
    source_link: str
    mitigations: list[str]
    data_sources: list[str]
    groups: list[str]
    prevalence: str


class SummaryRecord(Strict):
    """Audit trail of one summary call (not part of the CSV)."""

    technique_id: str
    source_description: str
    raw_summary: str | None
    status: Literal["ok", "llm_failed", "boundary_violation"]
    violations: list[str] = Field(default_factory=list)
    error: str | None = None
    llm_meta: dict = Field(default_factory=dict)


# --- Step 1: validation and analyst review ----------------------------------------


class Candidate(Strict):
    technique_id: str
    llm_name: str
    official_name: str | None
    evidence_quote: str
    status: Literal["valid", "not_found", "revoked", "deprecated", "malformed"]
    replacement: str | None = None
    needs_review: bool
    quote_found: bool


class ValidatedTechnique(Strict):
    technique_id: str
    technique_name: str
    evidence_quote: str = ""
    origin: Literal["llm", "replacement", "analyst"]


class AnalystAction(Strict):
    action: Literal["accept", "remove", "add", "replace", "exclude_needs_review", "reject_add_invalid"]
    technique_id: str
    note: str = ""


class ExtractionRecord(Strict):
    """Everything step 1 produced; `extracted_raw` is what metrics use."""

    report_sha256: str
    attack_version: str
    chunks: int
    extracted_raw: list[ExtractedTechnique]
    extra_fields: list[str]
    candidates: list[Candidate]
    analyst_mode: str
    analyst_actions: list[AnalystAction]
    extracted_validated: list[ValidatedTechnique]
    llm_calls: list[dict]
