"""Access to ATT&CK Enterprise STIX data (v19.2).

Indexing of techniques, tactics and the matrix order is done directly over the
bundle JSON (cheap and deterministic). Batch reference lookups (mitigations,
groups) go through `mitreattack-python`. Detection data components are resolved
through the v18+ chain: detection strategy -> analytics -> data components,
because techniques no longer carry `x_mitre_data_sources`.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

ATTACK_BASE_URL = "https://attack.mitre.org/techniques/"
TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
INITIAL_ACCESS = "initial-access"


class IdStatus(str, Enum):
    VALID = "valid"
    NOT_FOUND = "not_found"
    REVOKED = "revoked"
    DEPRECATED = "deprecated"
    MALFORMED = "malformed"


@dataclass(frozen=True)
class IdValidation:
    technique_id: str
    status: IdStatus
    replacement: str | None = None

    @property
    def is_valid(self) -> bool:
        return self.status is IdStatus.VALID


@dataclass(frozen=True)
class TechniqueRecord:
    technique_id: str
    name: str
    stix_id: str
    tactics: tuple[str, ...]
    is_subtechnique: bool
    revoked: bool
    deprecated: bool
    description: str

    @property
    def parent_id(self) -> str:
        return self.technique_id.split(".")[0]

    @property
    def url(self) -> str:
        return technique_url(self.technique_id)


@dataclass
class RawReference:
    technique_id: str
    description: str
    url: str
    mitigations: list[tuple[str, str]] = field(default_factory=list)
    data_components: list[str] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)


def technique_url(technique_id: str) -> str:
    """Build the attack.mitre.org URL by code (never by the LLM)."""
    return ATTACK_BASE_URL + technique_id.replace(".", "/") + "/"


def parent_of(technique_id: str) -> str:
    return technique_id.split(".")[0]


def _attack_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _is_active(obj: dict) -> bool:
    return not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False)


class AttackData:
    def __init__(self, bundle_path: Path, objects: list[dict]):
        self.bundle_path = bundle_path
        self._objects = objects
        self._by_stix_id = {o["id"]: o for o in objects}
        self._mad = None  # lazy mitreattack-python handle

        collections = [o for o in objects if o["type"] == "x-mitre-collection"]
        self.version: str = collections[0].get("x_mitre_version", "") if collections else ""

        matrices = [o for o in objects if o["type"] == "x-mitre-matrix" and _is_active(o)]
        if len(matrices) != 1:
            raise ValueError(f"Se esperaba una matriz Enterprise en el bundle; se encontraron {len(matrices)}.")
        tactic_objs = [self._by_stix_id[ref] for ref in matrices[0]["tactic_refs"]]
        self.tactic_order: list[str] = [t["x_mitre_shortname"] for t in tactic_objs]
        self.tactic_names: dict[str, str] = {t["x_mitre_shortname"]: t["name"] for t in tactic_objs}
        self._tactic_index = {short: i for i, short in enumerate(self.tactic_order)}

        self._techniques: dict[str, TechniqueRecord] = {}
        for o in objects:
            if o["type"] != "attack-pattern":
                continue
            tid = _attack_id(o)
            if not tid:
                continue
            rec = self._record(tid, o)
            current = self._techniques.get(tid)
            # If an ID appears twice, the active object wins over a revoked/deprecated one.
            if current is None or (not (rec.revoked or rec.deprecated) and (current.revoked or current.deprecated)):
                self._techniques[tid] = rec

        self._revoked_by = {
            o["source_ref"]: o["target_ref"]
            for o in objects
            if o["type"] == "relationship" and o.get("relationship_type") == "revoked-by"
        }

    def _record(self, tid: str, o: dict) -> TechniqueRecord:
        phases = {p["phase_name"] for p in o.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"}
        tactics = tuple(sorted((p for p in phases if p in self._tactic_index), key=self._tactic_index.__getitem__))
        return TechniqueRecord(
            technique_id=tid,
            name=o.get("name", ""),
            stix_id=o["id"],
            tactics=tactics,
            is_subtechnique=bool(o.get("x_mitre_is_subtechnique", False)),
            revoked=bool(o.get("revoked", False)),
            deprecated=bool(o.get("x_mitre_deprecated", False)),
            description=o.get("description", ""),
        )

    @classmethod
    def load(cls, path: Path) -> "AttackData":
        path = Path(path)
        if not path.is_file():
            raise FileNotFoundError(
                f"No se encontró el archivo de ATT&CK en {path}. Ejecute `aem fetch-data` para descargarlo."
            )
        with path.open(encoding="utf-8") as fh:
            bundle = json.load(fh)
        return cls(path, bundle["objects"])

    # --- lookups -------------------------------------------------------------

    def get(self, technique_id: str) -> TechniqueRecord | None:
        return self._techniques.get(technique_id)

    def active_ids(self) -> list[str]:
        return sorted(t for t, r in self._techniques.items() if not (r.revoked or r.deprecated))

    def validate_id(self, technique_id: str) -> IdValidation:
        if not TECHNIQUE_ID_RE.match(technique_id or ""):
            return IdValidation(technique_id, IdStatus.MALFORMED)
        rec = self._techniques.get(technique_id)
        if rec is None:
            return IdValidation(technique_id, IdStatus.NOT_FOUND)
        if rec.revoked:
            target = self._by_stix_id.get(self._revoked_by.get(rec.stix_id, ""))
            return IdValidation(technique_id, IdStatus.REVOKED, _attack_id(target) if target else None)
        if rec.deprecated:
            return IdValidation(technique_id, IdStatus.DEPRECATED)
        return IdValidation(technique_id, IdStatus.VALID)

    def is_initial_access(self, technique_id: str) -> bool:
        rec = self._require(technique_id)
        return INITIAL_ACCESS in rec.tactics

    def first_tactic_index(self, technique_id: str) -> int:
        rec = self._require(technique_id)
        return self._tactic_index[rec.tactics[0]] if rec.tactics else len(self.tactic_order)

    def tactic_display(self, technique_id: str) -> list[str]:
        return [self.tactic_names[t] for t in self._require(technique_id).tactics]

    def _require(self, technique_id: str) -> TechniqueRecord:
        rec = self._techniques.get(technique_id)
        if rec is None:
            raise KeyError(f"Técnica {technique_id} no existe en ATT&CK {self.version}.")
        return rec

    # --- batch reference ------------------------------------------------------

    def _mitreattack(self):
        if self._mad is None:
            from mitreattack.stix20 import MitreAttackData

            self._mad = MitreAttackData(stix_filepath=str(self.bundle_path))
        return self._mad

    def reference_bundle(self, technique_ids: list[str]) -> dict[str, RawReference]:
        """Fetch reference fields for all techniques in one batch."""
        recs = [self._require(tid) for tid in technique_ids]
        mad = self._mitreattack()
        all_mitigations = mad.get_all_mitigations_mitigating_all_techniques()
        all_groups = mad.get_all_groups_using_all_techniques()
        detects = self._data_components_by_technique()

        out: dict[str, RawReference] = {}
        for rec in recs:
            mitigations = sorted(
                {
                    (_attack_id(m["object"]), m["object"]["name"])
                    for m in all_mitigations.get(rec.stix_id, [])
                    if _is_active(m["object"])
                }
            )
            groups = sorted(
                {g["object"]["name"] for g in all_groups.get(rec.stix_id, []) if _is_active(g["object"])}
            )
            out[rec.technique_id] = RawReference(
                technique_id=rec.technique_id,
                description=rec.description,
                url=rec.url,
                mitigations=mitigations,
                data_components=sorted(detects.get(rec.stix_id, set())),
                groups=groups,
            )
        return out

    def _data_components_by_technique(self) -> dict[str, set[str]]:
        result: dict[str, set[str]] = {}
        for rel in self._objects:
            if rel["type"] != "relationship" or rel.get("relationship_type") != "detects":
                continue
            strategy = self._by_stix_id.get(rel["source_ref"])
            if not strategy or strategy["type"] != "x-mitre-detection-strategy" or not _is_active(strategy):
                continue
            names = result.setdefault(rel["target_ref"], set())
            for analytic_ref in strategy.get("x_mitre_analytic_refs", []):
                analytic = self._by_stix_id.get(analytic_ref)
                if not analytic or not _is_active(analytic):
                    continue
                for src in analytic.get("x_mitre_log_source_references", []):
                    dc = self._by_stix_id.get(src.get("x_mitre_data_component_ref", ""))
                    if dc and _is_active(dc):
                        names.add(dc["name"])
        return result
