"""Step 3 — contextual prioritization by the analyst with an adapted SSVC tree.

The action is computed only from the editable table in `data/ssvc_tree.yaml`
and the analyst's inputs. This module has no AI dependency by design.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, ConfigDict, field_validator

from aem.attack_data import AttackData
from aem.config import load_yaml
from aem.models import (
    ACTION_ORDER, COVERAGE_LEVELS, Action, Asset, ChainItem, Coverage, CoverageResult, Criticality, Exposure,
    GlobalReview, OrgProfile, PrioritizedTechnique,
)

GLOBAL_QUESTION = (
    "¿Existe algún punto de la cadena en el que la organización cuente con cobertura suficiente "
    "para interrumpir el ataque?"
)
CRITICALITIES = ("baja", "media", "alta")
EXPOSURES = ("internet", "interna", "aislada")
OUTPUT_ACTION_ORDER = tuple(reversed(ACTION_ORDER))  # Act, Attend, Track*, Track


class SsvcTree(BaseModel):
    model_config = ConfigDict(extra="forbid")
    base_table: dict[Coverage, dict[Criticality, Action]]
    initial_access_exposure_shift: dict[Exposure, int]

    @field_validator("base_table")
    @classmethod
    def _complete_table(cls, v):
        for cov in COVERAGE_LEVELS:
            if cov not in v or set(v[cov]) != set(CRITICALITIES):
                raise ValueError(f"base_table incompleta para la cobertura «{cov}»")
        return v

    @field_validator("initial_access_exposure_shift")
    @classmethod
    def _complete_shift(cls, v):
        if set(v) != set(EXPOSURES):
            raise ValueError("initial_access_exposure_shift debe definir internet, interna y aislada")
        return v


def load_tree(path: Path) -> SsvcTree:
    return SsvcTree.model_validate(load_yaml(path))


def decide(coverage: Coverage, criticality: Criticality, exposure: Exposure | None, initial_access: bool,
           tree: SsvcTree) -> Action:
    action = tree.base_table[coverage][criticality]
    if not initial_access:
        return action
    if exposure is None:
        raise ValueError("Las técnicas de Acceso Inicial requieren la exposición del activo")
    i = ACTION_ORDER.index(action) + tree.initial_access_exposure_shift[exposure]
    return ACTION_ORDER[min(max(i, 0), len(ACTION_ORDER) - 1)]


# --- Analysts -------------------------------------------------------------------


class ContextDecision(BaseModel):
    asset_id: str
    criticality: Criticality
    exposure: Exposure | None
    source: str


class Analyst(Protocol):
    mode: str

    def review_coverage(self, result: CoverageResult, name: str) -> tuple[Coverage, str]: ...

    def context(self, technique_id: str, name: str, initial_access: bool) -> ContextDecision: ...

    def global_review(self, chain: list[PrioritizedTechnique], attack: AttackData) -> GlobalReview: ...


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _chain_items(chain: list[PrioritizedTechnique], attack: AttackData) -> list[ChainItem]:
    return [ChainItem(technique_id=i.technique_id, technique_name=i.technique_name,
                      tactics=[attack.tactic_names[t] for t in i.tactics], coverage_validated=i.coverage_validated)
            for i in chain]


class AutoAnalyst:
    """Reproducible simulation: accepts step 2 and reads context from `analyst_context` (experiments only)."""

    mode = "auto"

    def __init__(self, org: OrgProfile):
        self.org = org

    def review_coverage(self, result: CoverageResult, name: str) -> tuple[Coverage, str]:
        return result.coverage, ""

    def context(self, technique_id: str, name: str, initial_access: bool) -> ContextDecision:
        asset = self.org.asset_for(technique_id)
        source = "analyst_context" if self.org.context_entry(technique_id) else "default_asset"
        return ContextDecision(asset_id=asset.id, criticality=asset.criticality,
                               exposure=asset.exposure if initial_access else None, source=source)

    def global_review(self, chain: list[PrioritizedTechnique], attack: AttackData) -> GlobalReview:
        return GlobalReview(question=GLOBAL_QUESTION, answer=None, mode="auto",
                            note="Sin responder: modo automático (la pregunta es criterio del analista).",
                            techniques_shown=_chain_items(chain, attack), timestamp=_now())


AskFn = Callable[..., str]


def _rich_ask(prompt: str, default: str | None = None, choices: list[str] | None = None) -> str:
    from rich.prompt import Prompt

    return Prompt.ask(prompt, default=default, choices=choices)


class InteractiveAnalyst:
    """Human analyst through the CLI. The script shows data and records answers; it never suggests them."""

    mode = "interactive"

    def __init__(self, org: OrgProfile, ask: AskFn = _rich_ask, console=None):
        self.org = org
        self.ask = ask
        self.console = console

    def _print(self, *args) -> None:
        if self.console is not None:
            self.console.print(*args)

    def review_coverage(self, result: CoverageResult, name: str) -> tuple[Coverage, str]:
        self._print(f"\n[bold]{result.technique_id}[/bold] {name} — cobertura según el YAML: "
                    f"[cyan]{result.coverage}[/cyan] (score: {result.score if result.score is not None else 'sin entrada'})")
        validated = self.ask("Cobertura validada (Enter = mantener)", default=result.coverage,
                             choices=list(COVERAGE_LEVELS))
        reason = ""
        if validated != result.coverage:
            reason = self.ask("Motivo de la corrección")
        return validated, reason

    def context(self, technique_id: str, name: str, initial_access: bool) -> ContextDecision:
        asset: Asset = self.org.asset_for(technique_id)
        regulated = "sí" if asset.processes_regulated_data else "no"
        self._print(f"Activo afectado según analyst_context: {asset.name} (procesa datos regulados: {regulated})")
        criticality = self.ask("Criticidad del activo", default=asset.criticality, choices=list(CRITICALITIES))
        exposure = None
        if initial_access:
            exposure = self.ask("Exposición del activo (solo Acceso Inicial)", default=asset.exposure,
                                choices=list(EXPOSURES))
        return ContextDecision(asset_id=asset.id, criticality=criticality, exposure=exposure, source="interactive")

    def global_review(self, chain: list[PrioritizedTechnique], attack: AttackData) -> GlobalReview:
        items = _chain_items(chain, attack)
        if self.console is not None:
            from rich.table import Table

            table = Table(title="Técnicas en orden de la cadena (matriz ATT&CK)")
            for col in ("Táctica(s)", "Técnica", "Cobertura validada"):
                table.add_column(col)
            for it in items:
                table.add_row(", ".join(it.tactics), f"{it.technique_id} {it.technique_name}", it.coverage_validated)
            self.console.print(table)
        raw = self.ask(GLOBAL_QUESTION + " (si/no)", choices=["si", "no"])
        answer = raw.strip().lower() in ("si", "sí")
        tactics: list[str] = []
        if answer:
            raw_tactics = self.ask("¿En qué táctica(s)? (separadas por coma)")
            by_key = {k.lower(): v for k, v in attack.tactic_names.items()}
            by_key.update({v.lower(): v for v in attack.tactic_names.values()})
            tactics = [by_key.get(t.strip().lower(), t.strip()) for t in raw_tactics.split(",") if t.strip()]
        note = self.ask("Nota (opcional)", default="")
        return GlobalReview(question=GLOBAL_QUESTION, answer=answer, tactics=tactics, note=note or "",
                            mode="interactive", techniques_shown=items, timestamp=_now())


# --- Step 3 orchestration -----------------------------------------------------------


def prioritize(coverage: list[CoverageResult], attack: AttackData, analyst: Analyst,
               tree: SsvcTree) -> list[PrioritizedTechnique]:
    out = []
    for res in coverage:
        rec = attack.get(res.technique_id)
        if rec is None:
            raise KeyError(f"Técnica {res.technique_id} no existe en ATT&CK {attack.version}")
        validated, reason = analyst.review_coverage(res, rec.name)
        initial_access = attack.is_initial_access(res.technique_id)
        ctx = analyst.context(res.technique_id, rec.name, initial_access)
        out.append(PrioritizedTechnique(
            technique_id=res.technique_id, technique_name=rec.name, tactics=list(rec.tactics),
            coverage_original=res.coverage, coverage_validated=validated, coverage_change_reason=reason,
            asset_id=ctx.asset_id, criticality=ctx.criticality, exposure=ctx.exposure if initial_access else None,
            action=decide(validated, ctx.criticality, ctx.exposure, initial_access, tree),
            context_source=ctx.source,
        ))
    return out


def chain_order(items: list[PrioritizedTechnique], attack: AttackData) -> list[PrioritizedTechnique]:
    """Attack-sequence order: earliest tactic in the matrix, then technique ID (determinism only)."""
    return sorted(items, key=lambda i: (attack.first_tactic_index(i.technique_id), i.technique_id))


def order_for_output(items: list[PrioritizedTechnique], attack: AttackData) -> list[PrioritizedTechnique]:
    """Group by action (Act, Attend, Track*, Track); chain order inside each group. No ranking within a group."""
    chained = chain_order(items, attack)
    return sorted(chained, key=lambda i: OUTPUT_ACTION_ORDER.index(i.action))
