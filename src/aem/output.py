"""Model output: one CSV per analyzed threat + the complementary global review file.

Columns are fixed (CLAUDE.md §5). `action` is the only evaluative column and it
comes from the analyst's step 3, never from the LLM. Rows are grouped by action
and, inside each group, ordered by attack sequence (matrix tactic order); the
script does not rank techniques that share an action (D-50).
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from aem.attack_data import AttackData
from aem.models import GlobalReview, PrioritizedTechnique, ReferenceInfo
from aem.step3_prioritize import order_for_output

CSV_COLUMNS = ("technique_id", "technique_name", "tactics", "coverage_validated", "criticality", "exposure",
               "action", "summary", "source_link", "mitigations", "data_sources", "groups", "prevalence")
LIST_SEP = "; "  # D-51
EMPTY_LIST = "sin dato disponible"


def _join(values: list[str]) -> str:
    return LIST_SEP.join(values) if values else EMPTY_LIST


def build_rows(prioritized: list[PrioritizedTechnique], refs: list[ReferenceInfo], attack: AttackData) -> list[dict]:
    by_id = {r.technique_id: r for r in refs}
    rows = []
    for item in order_for_output(prioritized, attack):
        ref = by_id.get(item.technique_id)
        if ref is None:
            raise KeyError(f"Falta la información de referencia (paso 4) de {item.technique_id}")
        rows.append({
            "technique_id": item.technique_id,
            "technique_name": item.technique_name,
            "tactics": LIST_SEP.join(attack.tactic_names[t] for t in item.tactics),
            "coverage_validated": item.coverage_validated,
            "criticality": item.criticality,
            "exposure": item.exposure or "",
            "action": item.action,
            "summary": ref.summary,
            "source_link": ref.source_link,
            "mitigations": _join(ref.mitigations),
            "data_sources": _join(ref.data_sources),
            "groups": _join(ref.groups),
            "prevalence": ref.prevalence,
        })
    return rows


def write_csv(path: Path, rows: list[dict]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as fh:  # BOM so Excel detects UTF-8
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def write_json(path: Path, data) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_global_review(path: Path, review: GlobalReview) -> None:
    write_json(path, review.model_dump(mode="json"))
