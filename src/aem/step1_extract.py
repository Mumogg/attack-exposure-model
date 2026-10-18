"""Step 1 — technique extraction and mapping (AI) + validation by code + analyst review.

The LLM only returns (technique_id, technique_name, evidence_quote). IDs are then
validated against ATT&CK; invalid, revoked or deprecated IDs are flagged
`needs_review` and shown to the analyst, never dropped silently.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from importlib import resources
from typing import Callable

from aem.attack_data import AttackData, IdStatus
from aem.config import ExtractionConfig
from aem.llm import GeminiClient, InvalidResponse
from aem.models import AnalystAction, Candidate, ExtractedTechnique, ValidatedTechnique

PROMPT_NAME = "extract_v1.txt"
_FIELDS = ("technique_id", "technique_name", "evidence_quote")
EXTRACTION_SCHEMA = {
    "type": "object",
    "properties": {
        "techniques": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {f: {"type": "string"} for f in _FIELDS},
                "required": list(_FIELDS),
            },
        }
    },
    "required": ["techniques"],
}


def prompt_template() -> str:
    return resources.files("aem.prompts").joinpath(PROMPT_NAME).read_text(encoding="utf-8")


def parse_extraction(data: dict) -> tuple[list[ExtractedTechnique], list[str]]:
    """Keep only the three schema fields; report any extra field (counted by indicator 5)."""
    if not isinstance(data, dict) or not isinstance(data.get("techniques"), list):
        raise InvalidResponse("La respuesta del LLM no tiene la forma {'techniques': [...]}")
    extra = [k for k in data if k != "techniques"]
    items = []
    for i, raw in enumerate(data["techniques"]):
        if not isinstance(raw, dict) or not all(isinstance(raw.get(f), str) for f in _FIELDS):
            raise InvalidResponse(f"Elemento {i} de la respuesta del LLM no cumple el esquema: {raw!r}")
        extra += [f"techniques[{i}].{k}" for k in raw if k not in _FIELDS]
        items.append(ExtractedTechnique(**{f: raw[f].strip() for f in _FIELDS}))
    return items, extra


def chunk_text(text: str, cfg: ExtractionConfig) -> list[str]:
    """Whole text if short enough; otherwise paragraph-aligned chunks with overlap (D-11)."""
    if len(text) <= cfg.chunk_max_chars:
        return [text]
    paras = [p for p in re.split(r"\n\s*\n", text) if p.strip()]
    chunks: list[str] = []
    current: list[str] = []
    for p in paras:
        while len(p) > cfg.chunk_size_chars:  # a single huge paragraph is split hard
            head, p = p[: cfg.chunk_size_chars], p[cfg.chunk_size_chars - cfg.chunk_overlap_chars:]
            if current:
                chunks.append("\n\n".join(current))
                current = []
            chunks.append(head)
        if current and len("\n\n".join(current + [p])) > cfg.chunk_size_chars:
            chunks.append("\n\n".join(current))
            overlap: list[str] = []
            for q in reversed(current):  # trailing paragraphs that fit in the overlap budget
                candidate = [q] + overlap
                if len("\n\n".join(candidate)) > cfg.chunk_overlap_chars or \
                        len("\n\n".join(candidate + [p])) > cfg.chunk_size_chars:
                    break
                overlap = candidate
            current = overlap
        current.append(p)
    if current:
        chunks.append("\n\n".join(current))
    return chunks


@dataclass
class ExtractionRun:
    extracted_raw: list[ExtractedTechnique]
    extra_fields: list[str]
    chunks: int
    llm_calls: list[dict] = field(default_factory=list)


def extract(report_text: str, client: GeminiClient, cfg: ExtractionConfig, attack_version: str,
            replicate: int = 0, private: bool = False) -> ExtractionRun:
    template = prompt_template()
    chunks = chunk_text(report_text, cfg)
    merged: dict[str, ExtractedTechnique] = {}
    extra: list[str] = []
    calls = []
    for i, chunk in enumerate(chunks, 1):
        prompt = template.format(attack_version=attack_version, chunk_index=i, chunk_count=len(chunks), report=chunk)
        res = client.generate_json(prompt, EXTRACTION_SCHEMA, purpose=f"step1_extract[{i}/{len(chunks)}]",
                                   replicate=replicate, private=private)
        items, chunk_extra = parse_extraction(res.data)
        extra += [f"chunk{i}:{e}" for e in chunk_extra]
        calls.append(dict(res.meta, prompt_template=PROMPT_NAME, raw_response=res.raw_text))
        for it in items:
            merged.setdefault(it.technique_id, it)  # first occurrence (and quote) wins
    return ExtractionRun(extracted_raw=list(merged.values()), extra_fields=extra, chunks=len(chunks), llm_calls=calls)


# --- validation by code ---------------------------------------------------------------

_QUOTES = str.maketrans({"“": '"', "”": '"', "‘": "'", "’": "'", "«": '"', "»": '"'})


def _norm(text: str) -> str:
    text = unicodedata.normalize("NFKC", text or "").translate(_QUOTES)
    return re.sub(r"\s+", " ", text).strip().lower()


def validate_candidates(raw: list[ExtractedTechnique], attack: AttackData, report_text: str) -> list[Candidate]:
    report_norm = _norm(report_text)
    out = []
    for t in raw:
        v = attack.validate_id(t.technique_id)
        rec = attack.get(t.technique_id) if v.status is not IdStatus.MALFORMED else None
        out.append(Candidate(
            technique_id=t.technique_id, llm_name=t.technique_name, official_name=rec.name if rec else None,
            evidence_quote=t.evidence_quote, status=v.status.value, replacement=v.replacement,
            needs_review=not v.is_valid, quote_found=bool(t.evidence_quote) and _norm(t.evidence_quote) in report_norm,
        ))
    return out


# --- analyst review -------------------------------------------------------------------


class AutoReviewer:
    """Experiments only: accepts every valid candidate; needs_review ones are excluded and logged."""

    mode = "auto"

    def resolve(self, cand: Candidate, attack: AttackData) -> tuple[str | None, AnalystAction]:
        return None, AnalystAction(action="exclude_needs_review", technique_id=cand.technique_id,
                                   note=f"modo auto: estado {cand.status}")

    def removals(self, current: list[str]) -> list[str]:
        return []

    def additions(self) -> list[str]:
        return []


AskFn = Callable[..., str]


def _rich_ask(prompt: str, default: str | None = None, choices: list[str] | None = None) -> str:
    from rich.prompt import Prompt

    return Prompt.ask(prompt, default=default, choices=choices)


def _split_ids(raw: str) -> list[str]:
    return [x.strip() for x in (raw or "").split(",") if x.strip()]


class InteractiveReviewer:
    mode = "interactive"

    def __init__(self, ask: AskFn = _rich_ask, console=None):
        self.ask = ask
        self.console = console
        self._pending_adds: list[str] | None = None

    def _print(self, *a) -> None:
        if self.console is not None:
            self.console.print(*a)

    def show(self, candidates: list[Candidate]) -> None:
        if self.console is None:
            return
        from rich.table import Table

        table = Table(title="Técnicas propuestas por el LLM (paso 1)")
        for col in ("ID", "Nombre (ATT&CK)", "Estado", "Cita encontrada", "Cita"):
            table.add_column(col)
        for c in candidates:
            state = "needs_review: " + c.status if c.needs_review else "válido"
            table.add_row(c.technique_id, c.official_name or c.llm_name, state, "sí" if c.quote_found else "NO",
                          c.evidence_quote[:80])
        self.console.print(table)

    def resolve(self, cand: Candidate, attack: AttackData) -> tuple[str | None, AnalystAction]:
        self._print(f"[yellow]{cand.technique_id}[/yellow] requiere revisión ({cand.status}).")
        if cand.replacement:
            choice = self.ask(f"Reemplazar por {cand.replacement} o quitar", choices=["reemplazar", "quitar"])
            if choice == "reemplazar":
                return cand.replacement, AnalystAction(action="replace", technique_id=cand.technique_id,
                                                       note=f"→ {cand.replacement}")
            return None, AnalystAction(action="remove", technique_id=cand.technique_id, note="needs_review")
        corrected = self.ask("ID corregido (vacío = quitar)", default="").strip()
        if corrected and attack.validate_id(corrected).is_valid:
            return corrected, AnalystAction(action="replace", technique_id=cand.technique_id, note=f"→ {corrected}")
        return None, AnalystAction(action="remove", technique_id=cand.technique_id, note="needs_review")

    def removals(self, current: list[str]) -> list[str]:
        return _split_ids(self.ask("IDs a quitar (separados por coma, vacío = ninguno)", default=""))

    def additions(self) -> list[str]:
        return _split_ids(self.ask("IDs a agregar (separados por coma, vacío = terminar)", default=""))


def review(candidates: list[Candidate], reviewer, attack: AttackData) -> tuple[list[ValidatedTechnique],
                                                                              list[AnalystAction]]:
    if hasattr(reviewer, "show"):
        reviewer.show(candidates)
    validated: list[ValidatedTechnique] = []
    actions: list[AnalystAction] = []

    def present(tid: str) -> bool:
        return any(v.technique_id == tid for v in validated)

    for c in candidates:
        if not c.needs_review:
            if not present(c.technique_id):
                validated.append(ValidatedTechnique(technique_id=c.technique_id, technique_name=c.official_name,
                                                    evidence_quote=c.evidence_quote, origin="llm"))
            continue
        new_id, action = reviewer.resolve(c, attack)
        actions.append(action)
        if new_id and not present(new_id):
            validated.append(ValidatedTechnique(technique_id=new_id, technique_name=attack.get(new_id).name,
                                                evidence_quote=c.evidence_quote, origin="replacement"))

    for tid in reviewer.removals([v.technique_id for v in validated]):
        if present(tid):
            validated = [v for v in validated if v.technique_id != tid]
            actions.append(AnalystAction(action="remove", technique_id=tid))

    while True:
        adds = reviewer.additions()
        if not adds:
            break
        for tid in adds:
            if not attack.validate_id(tid).is_valid:
                actions.append(AnalystAction(action="reject_add_invalid", technique_id=tid,
                                             note=attack.validate_id(tid).status.value))
            elif not present(tid):
                validated.append(ValidatedTechnique(technique_id=tid, technique_name=attack.get(tid).name,
                                                    origin="analyst"))
                actions.append(AnalystAction(action="add", technique_id=tid))

    removed = {a.technique_id for a in actions if a.action == "remove"}
    for v in validated:
        if v.origin == "llm" and v.technique_id not in removed:
            actions.insert(0, AnalystAction(action="accept", technique_id=v.technique_id))
    return validated, actions
