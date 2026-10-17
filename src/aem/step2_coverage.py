"""Step 2 — deterministic coverage analysis (no AI).

Maps each validated technique to `cubierta | parcial | sin cobertura` from the
organization's DeTT&CT-style detection scores. Thresholds and the sub-technique
policy come from `data/model_config.yaml` (see docs/DECISIONS.md D-20, D-21).
"""

from __future__ import annotations

from aem.attack_data import parent_of
from aem.config import CoverageConfig
from aem.models import Coverage, CoverageResult, OrgProfile


def classify_score(score: int | None, cfg: CoverageConfig) -> Coverage:
    if score is None or score < cfg.partial_min:
        return "sin cobertura"
    if score < cfg.covered_min:
        return "parcial"
    return "cubierta"


def assess_one(technique_id: str, org: OrgProfile, cfg: CoverageConfig) -> CoverageResult:
    det = org.detection_for(technique_id)
    if det is not None:
        return CoverageResult(technique_id=technique_id, coverage=classify_score(det.score, cfg), score=det.score,
                              data_sources=list(det.data_sources), basis="own_entry")
    parent = parent_of(technique_id)
    if cfg.subtechnique_policy == "inherit_parent" and parent != technique_id:
        pdet = org.detection_for(parent)
        if pdet is not None:
            return CoverageResult(technique_id=technique_id, coverage=classify_score(pdet.score, cfg),
                                  score=pdet.score, data_sources=list(pdet.data_sources),
                                  basis="inherited_parent", inherited_from=parent)
    return CoverageResult(technique_id=technique_id, coverage="sin cobertura", score=None, data_sources=[],
                          basis="no_entry")


def assess_coverage(technique_ids: list[str], org: OrgProfile, cfg: CoverageConfig) -> list[CoverageResult]:
    seen: dict[str, None] = dict.fromkeys(technique_ids)
    return [assess_one(tid, org, cfg) for tid in seen]
