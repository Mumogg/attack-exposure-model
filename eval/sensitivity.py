"""`aem sensitivity`: steps 2 and 3 and indicator 3 recomputed with other coverage parameters, without the API.

A complement to the main results, not a replacement (D-77): the confirmed configuration (D-20, D-21) does not
change, and neither `model_config.yaml`, `coverage_design` nor `results/` are touched. One parameter varies at a
time; everything else stays as in `data/model_config.yaml`.

Inputs are the outputs already on disk: `results/results.json` (which runs were valid) and each run's
`run_record.json` (techniques of `extracted_raw` and `extracted_validated`). Steps 2 and 3 are deterministic,
so the row with the current parameters reproduces indicator 3 of `results.json` exactly.
"""

from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path

from aem.config import CoverageConfig, ModelConfig
from aem.models import OrgProfile
from aem.output import write_json
from aem.scenarios import VERSIONS, Scenario, load_reference
from aem.step2_coverage import assess_coverage
from aem.step3_prioritize import AutoAnalyst, SsvcTree, prioritize
from eval.metrics import gap_techniques, model_persistence
from eval.run_experiments import NO_DATA, md_table, model_indicator3_row

HEADER = ("Análisis de sensibilidad. No sustituye los resultados principales; la configuración confirmada "
          "(D-20, D-21) no cambió")
ACTIONS = ("Act", "Attend", "Track*", "Track")
NO_RUN_RECORDS = "sin salidas por corrida en esta máquina"


class SensitivityError(Exception):
    pass


def variants(base: CoverageConfig) -> list[tuple[str, str, CoverageConfig]]:
    """(parameter, value, config): the current configuration first, then one change at a time."""
    out = [("actual", f"covered_min={base.covered_min}, partial_min={base.partial_min}, {base.subtechnique_policy}",
            base)]
    for value in (3, 4, 5):
        if value != base.covered_min:
            out.append(("covered_min", str(value), base.model_copy(update={"covered_min": value})))
    for value in (1, 2):
        if value != base.partial_min:
            out.append(("partial_min", str(value), base.model_copy(update={"partial_min": value})))
    for value in ("no_inherit", "inherit_parent"):
        if value != base.subtechnique_policy:
            out.append(("subtechnique_policy", value, base.model_copy(update={"subtechnique_policy": value})))
    return out


def load_runs(run_dir: Path, scenarios: dict[str, Scenario]) -> dict:
    """Per scenario: run records of the scored runs by version and failed runs by version; None if a scored
    run has no `run_record.json` here (e.g. a copyrighted scenario on a clone without `private/`)."""
    path = Path(run_dir) / "results" / "results.json"
    if not path.exists():
        raise SensitivityError(f"No existe {path.relative_to(Path(run_dir).parent.parent)}: la sensibilidad se "
                               "calcula sobre una corrida ya evaluada (results/, nunca results_FAKE/).")
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("fake", True):
        raise SensitivityError(f"{path.name} está marcado como FAKE: no se calcula la sensibilidad.")
    out = {}
    for sc in scenarios.values():
        runs = [r for r in data["runs"] if r["scenario"] == sc.name]
        if not runs:
            continue
        base = Path(run_dir) / ("private" if sc.copyrighted else "") / sc.name
        records: dict[str, list] = {v: [] for v in VERSIONS}
        failed = {v: 0 for v in VERSIONS}
        missing = False
        for r in runs:
            if r["status"] not in ("ok", "empty"):
                failed[r["version"]] += 1
                continue
            rec = base / r["version"] / f"r{r['replicate']}" / "run_record.json"
            if not rec.exists():
                missing = True
                break
            records[r["version"]].append(json.loads(rec.read_text(encoding="utf-8")))
        out[sc.name] = None if missing else {"records": records, "failed": failed}
    return {"results": data, "scenarios": out}


def _actions(records: list[dict], org: OrgProfile, cfg: CoverageConfig, attack, tree: SsvcTree) -> dict:
    """Step 3 of each run with this configuration, as in `run_pipeline` (`--analyst-mode auto`)."""
    out = {}
    for i, rec in enumerate(records):
        ids = [t["technique_id"] for t in rec["extraction"]["extracted_validated"]]
        for p in prioritize(assess_coverage(ids, org, cfg), attack, AutoAnalyst(org), tree):
            out[(i, p.technique_id)] = p.action
    return out


def compute_sensitivity(loaded: dict, scenarios: dict[str, Scenario], org: OrgProfile, model_cfg: ModelConfig,
                        attack, tree: SsvcTree) -> list[dict]:
    rows = []
    for name, runs in loaded["scenarios"].items():
        ref = [r.technique_id for r in load_reference(scenarios[name].reference) if r.valid]
        current_actions = None
        for param, value, cfg in variants(model_cfg.coverage):
            gaps = gap_techniques(ref, org, cfg)
            row = {"parameter": param, "value": value, "current": "sí" if param == "actual" else "no",
                   "scenario": name, "reference_techniques": len(ref), "gaps": len(gaps)}
            if runs is None:
                ind3 = {k: NO_DATA for k in model_indicator3_row(name, gaps, {v: [] for v in VERSIONS},
                                                                 {v: 0 for v in VERSIONS})}
                ind3.update(scenario=name, failed_runs=NO_RUN_RECORDS)
                acts, changed = {a: NO_DATA for a in ACTIONS}, NO_DATA
            else:
                persistence = {v: [model_persistence([t["technique_id"] for t in rec["extraction"]["extracted_raw"]],
                                                     gaps) for rec in runs["records"][v]] for v in VERSIONS}
                ind3 = model_indicator3_row(name, gaps, persistence, runs["failed"])
                by_version = {v: _actions(runs["records"][v], org, cfg, attack, tree) for v in VERSIONS}
                flat = {(v, *k): a for v, d in by_version.items() for k, a in d.items()}
                if current_actions is None:
                    current_actions = flat
                counts = Counter(flat.values())
                acts = {a: counts.get(a, 0) for a in ACTIONS}
                changed = sum(flat[k] != current_actions.get(k) for k in flat)
            row.update({k: v for k, v in ind3.items() if k not in ("scenario", "approach", "denominator_techniques",
                                                                   "ioc_matches")})
            row.update({f"step3_{a}": n for a, n in acts.items()})
            row["step3_action_changes_vs_current"] = changed
            rows.append(row)
    return rows


_MD_COLS = [("Parámetro", "parameter"), ("Valor", "value"), ("Escenario", "scenario"), ("Brechas", "gaps"),
            *[(f"{v} media _fail0", f"{v}_mean_fail0") for v in VERSIONS],
            *[(f"{v} DE _fail0", f"{v}_sd_fail0") for v in VERSIONS],
            ("mut/orig _fail0", "persistence_mut_over_orig_fail0"), ("anon/orig _fail0", "persistence_anon_over_orig_fail0"),
            *[(f"paso 3: {a}", f"step3_{a}") for a in ACTIONS],
            ("paso 3: acciones distintas de la configuración actual", "step3_action_changes_vs_current")]


def write_sensitivity(run_dir: Path, rows: list[dict], loaded: dict, model_cfg: ModelConfig) -> dict[str, Path]:
    out = Path(run_dir) / "results" / "sensitivity"
    out.mkdir(parents=True, exist_ok=True)
    paths = {"csv": out / "sensitivity.csv", "json": out / "sensitivity.json", "markdown": out / "sensitivity.md"}
    with paths["csv"].open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]) if rows else [])
        w.writeheader()
        w.writerows(rows)
    data = loaded["results"]
    base = model_cfg.coverage
    write_json(paths["json"], {
        "note": HEADER, "run_id": data.get("run_id"), "model": data.get("model"),
        "current_configuration": base.model_dump(), "source": "results/results.json + run_record.json por corrida",
        "rows": rows})
    missing = [n for n, r in loaded["scenarios"].items() if r is None]
    md = [f"# {HEADER}\n",
          f"Corrida `{data.get('run_id')}` · modelo `{data.get('model')}` · sin llamadas a la API (se releen las "
          "salidas por corrida guardadas).\n",
          f"- Configuración actual (`data/model_config.yaml`): `covered_min` = {base.covered_min}, `partial_min` = "
          f"{base.partial_min}, `subtechnique_policy` = `{base.subtechnique_policy}`. Cada fila cambia **un solo** "
          "parámetro; el resto queda como en la configuración actual.",
          "- «Brechas»: técnicas de referencia que el paso 2 deja en «parcial» o «sin cobertura» (denominador del "
          "indicador 3 del modelo).",
          "- Persistencia del modelo en %: media `_fail0` y su DE muestral; las columnas `_valid` están en el CSV y "
          "el JSON. Razones `mut/orig` y `anon/orig` sobre `_fail0`.",
          "- Paso 3: acciones de todas las corridas válidas (técnicas de `extracted_validated`, analista "
          "automático), y cuántas cambian respecto de la configuración actual. El paso 3 no tiene indicador.",
          "- La fila «actual» coincide exactamente con el indicador 3 de `results/results.json`.",
          "- El enfoque tradicional no depende de estos parámetros (D-62) y no se repite aquí.\n"]
    if missing:
        md.append(f"Escenarios con «{NO_RUN_RECORDS}» (solo brechas): {', '.join(missing)}.\n")
    md.append(md_table([{label: r[col] for label, col in _MD_COLS} for r in rows]))
    paths["markdown"].write_text("\n".join(md), encoding="utf-8")
    return paths


def check_against_results(rows: list[dict], results: dict) -> list[str]:
    """Differences between the «actual» rows and indicator 3 of `results.json` (must be none)."""
    main = {r["scenario"]: r for r in results["tables"]["indicator3"] if r["approach"] == "modelo"}
    diffs = []
    for row in rows:
        if row["parameter"] != "actual" or row["failed_runs"] == NO_RUN_RECORDS:
            continue
        ref = main.get(row["scenario"], {})
        if row["gaps"] != ref.get("denominator_techniques"):
            diffs.append(f"{row['scenario']}: brechas {row['gaps']} ≠ {ref.get('denominator_techniques')}")
        for col, value in row.items():
            if col in ref and col not in ("scenario",) and ref[col] != value:
                diffs.append(f"{row['scenario']}: {col} {value} ≠ {ref[col]}")
    return diffs
