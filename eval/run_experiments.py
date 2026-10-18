"""Full experiment (CLAUDE.md §8): scenarios × {orig, mut} × N replicates → five indicators.

Every run goes through the same pipeline as `aem run` in `--analyst-mode auto`.
API failures (quota, model, missing key, demo cache miss) stop the experiment
with a clear error; thanks to the cache, re-running resumes where it stopped.
An unusable LLM answer (not JSON / outside the schema) is recorded as a failed run.
"""

from __future__ import annotations

import csv
import json
import random
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from aem.llm import TEMPERATURE, InvalidResponse
from aem.output import write_json
from aem.pipeline import EmptyExtraction, PipelineContext, run_pipeline, write_outputs, write_record
from aem.scenarios import VERSIONS, Scenario, load_reference
from eval.baseline_ioc import baseline_recognizes
from eval.metrics import (
    aggregate, boundary_violations_extraction, coverage_correctness, extraction_scores, gap_techniques,
    model_persistence, summary_auto_check, traditional_persistence,
)

NO_DATA = "sin dato disponible"


# --- running ----------------------------------------------------------------------------------


def _one_run(ctx: PipelineContext, sc: Scenario, version: str, replicate: int, text: str, out: Path) -> dict:
    rec = {"scenario": sc.name, "version": version, "replicate": replicate, "status": "ok", "error": None,
           "raw": [], "extra_fields": [], "summaries": []}
    try:
        result = run_pipeline(text, ctx, analyst_mode="auto", replicate=replicate)
    except EmptyExtraction as exc:
        write_record(out / "run_record.json", exc.extraction, {"error": str(exc)})
        rec.update(status="empty", error=str(exc),
                   raw=[t.model_dump() for t in exc.extraction.extracted_raw],
                   extra_fields=exc.extraction.extra_fields)
        return rec
    except InvalidResponse as exc:
        write_json(out / "run_error.json", {"error": str(exc)})
        rec.update(status="error", error=str(exc))
        return rec
    write_outputs(result, out, stem=Path(sc.report_for(version)).stem)
    rec.update(raw=[t.model_dump() for t in result.extraction.extracted_raw],
               extra_fields=result.extraction.extra_fields,
               summaries=[s.model_dump(mode="json") for s in result.summaries])
    return rec


def _scored(runs: list[dict]) -> list[dict]:
    return [r for r in runs if r["status"] in ("ok", "empty")]


# --- formatting -------------------------------------------------------------------------------


def _pct(x: float | None) -> float | str:
    return NO_DATA if x is None else round(100 * x, 2)


def _agg_cols(prefix: str, values: list[float | None]) -> dict:
    a = aggregate(values)
    return {f"{prefix}_mean": _pct(a["mean"]), f"{prefix}_sd": _pct(a["sd"]) if a["n"] >= 2 else NO_DATA}


def write_table(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    cols = list(rows[0]) if rows else []
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)


def md_table(rows: list[dict]) -> str:
    if not rows:
        return "_sin datos_\n"
    cols = list(rows[0])
    out = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for r in rows:
        out.append("| " + " | ".join(str(r[c]).replace("|", "\\|") for c in cols) + " |")
    return "\n".join(out) + "\n"


# --- indicators -------------------------------------------------------------------------------


def _unique_summaries(runs: list[dict]) -> list[dict]:
    seen: dict[str, dict] = {}
    for r in runs:
        for s in r["summaries"]:
            seen.setdefault(s["technique_id"], s)
    return [seen[k] for k in sorted(seen)]


def _parse_summary(raw: str | None) -> tuple[str | None, list[str]]:
    if not raw:
        return None, []
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return raw, []
    if not isinstance(data, dict):
        return None, []
    text = data.get("summary") if isinstance(data.get("summary"), str) else None
    return text, [k for k in data if k != "summary"]


def compute(runs: list[dict], scenarios: dict[str, Scenario], ctx: PipelineContext, replicates: int) -> dict:
    org, cfg = ctx.org, ctx.model_cfg
    tables: dict[str, list[dict]] = {k: [] for k in ("indicator1", "indicator1_detail", "indicator2", "indicator3",
                                                     "indicator4", "indicator5")}
    texts: dict[tuple[str, str], str] = {}
    for sc in scenarios.values():
        for v in VERSIONS:
            if sc.report_for(v).exists():
                texts[(sc.name, v)] = sc.report_for(v).read_text(encoding="utf-8")

    for sc in scenarios.values():
        ref = [r.technique_id for r in load_reference(sc.reference) if r.valid]
        gaps = gap_techniques(ref, org, cfg.coverage)

        # indicator 2 (does not depend on the LLM: reference list only)
        cc = coverage_correctness(ref, org, cfg.coverage)
        tables["indicator2"].append({
            "scenario": sc.name, "reference_techniques": cc["total"], "matches": cc["matches"],
            "accuracy": _pct(cc["accuracy"]),
            "mismatches": "; ".join(f"{m['technique_id']} (paso 2: {m['step2']}, diseño: {m['intended']})"
                                    for m in cc["mismatches"]) or "ninguna",
        })

        persistence: dict[str, dict] = {}
        for v in VERSIONS:
            vr = [r for r in runs if r["scenario"] == sc.name and r["version"] == v]
            scored = _scored(vr)
            failed = len(vr) - len(scored)
            raw_sets = [[t["technique_id"] for t in r["raw"]] for r in scored]
            scores = [extraction_scores(ids, ref) for ids in raw_sets]
            for level in ("exact", "parent"):
                row = {"scenario": sc.name, "version": v, "level": level, "runs": len(scored), "failed_runs": failed}
                row.update(_agg_cols("precision", [s[level]["precision"] for s in scores]))
                row.update(_agg_cols("recall", [s[level]["recall"] for s in scores]))
                tables["indicator1"].append(row)
                for kind, key in (("omitida", "omitted"), ("errónea", "erroneous")):
                    counts = Counter(t for s in scores for t in s[level][key])
                    for tid, n in sorted(counts.items()):
                        tables["indicator1_detail"].append({"scenario": sc.name, "version": v, "level": level,
                                                            "kind": kind, "technique_id": tid,
                                                            "runs": f"{n}/{len(scored)}"})
            persistence[v] = aggregate([model_persistence(ids, gaps) for ids in raw_sets])

            # indicator 5 (step 1 outputs)
            per_run = []
            for r in scored:
                items = [(t["technique_id"], t["technique_name"], t["evidence_quote"]) for t in r["raw"]]
                names = {tid: rec.name for tid, *_ in items if (rec := ctx.attack.get(tid))}
                per_run.append(boundary_violations_extraction(items, texts.get((sc.name, v), ""), r["extra_fields"],
                                                              ctx.patterns, names))
            agg = aggregate([float(x["total"]) for x in per_run])
            tables["indicator5"].append({
                "scenario": sc.name, "version": v, "output": "paso 1 (extracción)", "runs": len(per_run),
                "violations_total": sum(x["total"] for x in per_run) if per_run else NO_DATA,
                "violations_mean": NO_DATA if agg["mean"] is None else round(agg["mean"], 2),
                "violations_sd": NO_DATA if agg["sd"] is None else round(agg["sd"], 2),
                "extra_fields": sum(x["extra_fields"] for x in per_run) if per_run else NO_DATA,
                "evaluative_text": sum(x["evaluative_text"] for x in per_run) if per_run else NO_DATA,
            })

        # indicator 3
        def mean(v: str):
            return persistence[v]["mean"]

        ratio = mean("mut") / mean("orig") if mean("orig") and mean("mut") is not None else None
        tables["indicator3"].append({
            "scenario": sc.name, "approach": "modelo", "denominator_techniques": len(gaps),
            "orig_mean": _pct(mean("orig")),
            "orig_sd": _pct(persistence["orig"]["sd"]) if persistence["orig"]["n"] >= 2 else NO_DATA,
            "mut_mean": _pct(mean("mut")),
            "mut_sd": _pct(persistence["mut"]["sd"]) if persistence["mut"]["n"] >= 2 else NO_DATA,
            "persistence_mut_over_orig": NO_DATA if ratio is None else round(ratio, 4), "ioc_matches": "",
        })
        if (sc.name, "orig") in texts and (sc.name, "mut") in texts:
            rec_o, m_o = baseline_recognizes(texts[(sc.name, "orig")], org.known_iocs, cfg.ioc, cfg.baseline)
            rec_m, m_m = baseline_recognizes(texts[(sc.name, "mut")], org.known_iocs, cfg.ioc, cfg.baseline)
            tp = traditional_persistence(rec_o, rec_m)
            row = {"scenario": sc.name, "approach": "tradicional", "denominator_techniques": len(ref),
                   "orig_mean": _pct(tp["orig"]), "orig_sd": "determinístico", "mut_mean": _pct(tp["mut"]),
                   "mut_sd": "determinístico",
                   "persistence_mut_over_orig": NO_DATA if tp["ratio"] is None else round(tp["ratio"], 4),
                   "ioc_matches": f"orig {len(m_o)}, mut {len(m_m)}"}
        else:
            row = {"scenario": sc.name, "approach": "tradicional", "denominator_techniques": len(ref), "orig_mean": NO_DATA,
                   "orig_sd": NO_DATA, "mut_mean": NO_DATA, "mut_sd": NO_DATA, "persistence_mut_over_orig": NO_DATA,
                   "ioc_matches": NO_DATA}
        tables["indicator3"].append(row)

    # indicator 4 + summary part of indicator 5 (one summary per technique, D-44)
    summaries = _unique_summaries(runs)
    sheet, auto_ok, summary_viol, summary_extra = [], 0, 0, 0
    for s in summaries:
        text, extra = _parse_summary(s["raw_summary"])
        summary_extra += len(extra)
        summary_viol += len(s["violations"])
        rec = ctx.attack.get(s["technique_id"])
        if text:
            chk = summary_auto_check(text, s["source_description"], cfg.summary.max_sentences)
            auto_ok += chk["ok"]
            auto = "ok" if chk["ok"] else "; ".join(chk["issues"])
        else:
            auto = "sin resumen (fallo del LLM)"
        sheet.append({"technique_id": s["technique_id"], "technique_name": rec.name if rec else "",
                      "source_description": s["source_description"], "summary": text or "", "status": s["status"],
                      "auto_check": auto, "ok (si/no)": "", "observación": ""})
    with_text = sum(1 for r in sheet if r["summary"])
    tables["indicator4"].append({
        "techniques_summarized": len(sheet), "llm_failures": len(sheet) - with_text,
        "auto_check_ok": auto_ok, "auto_check_ok_pct": _pct(auto_ok / with_text if with_text else None),
        "manual_review": "pendiente (hoja de revisión)",
    })
    tables["indicator5"].append({
        "scenario": "todos", "version": "-", "output": "paso 4 (resúmenes, uno por técnica)", "runs": len(summaries),
        "violations_total": summary_viol + summary_extra, "violations_mean": NO_DATA, "violations_sd": NO_DATA,
        "extra_fields": summary_extra, "evaluative_text": summary_viol,
    })

    # manual sample for indicator 5
    pool = []
    for r in _scored(runs):
        for t in r["raw"]:
            pool.append({"type": "cita (paso 1)", "scenario": r["scenario"], "version": r["version"],
                         "replicate": r["replicate"], "technique_id": t["technique_id"], "text": t["evidence_quote"]})
    for row in sheet:
        if row["summary"]:
            pool.append({"type": "resumen (paso 4)", "scenario": "-", "version": "-", "replicate": "-",
                         "technique_id": row["technique_id"], "text": row["summary"]})
    unique = list({(p["type"], p["technique_id"], p["text"]): p for p in pool}.values())
    k = min(cfg.experiment.manual_sample_size, len(unique))
    sample = random.Random(cfg.experiment.sample_seed).sample(unique, k) if k else []
    sample_sheet = [dict(p, **{"contiene_valoracion (si/no)": "", "observación": ""}) for p in sample]
    return {"tables": tables, "summary_sheet": sheet, "sample_sheet": sample_sheet}


# --- report -------------------------------------------------------------------------------------

_TITLES = {
    "indicator1": "Indicador 1 — Precisión y exhaustividad del paso 1 (%, sobre extracted_raw)",
    "indicator2": "Indicador 2 — Corrección del cruce de cobertura (paso 2, sobre la referencia)",
    "indicator3": "Indicador 3 — Persistencia en el reconocimiento de la exposición (%). Denominador: técnicas "
                  "de referencia con brecha (modelo) o todas las técnicas de referencia (tradicional)",
    "indicator4": "Indicador 4 — Fidelidad de los resúmenes (chequeo automático; la revisión manual está en la hoja)",
    "indicator5": "Indicador 5 — Cumplimiento de los límites (violaciones)",
    "indicator1_detail": "Anexo — Indicador 1: técnicas omitidas y erróneas (en cuántas corridas)",
}


def write_results(run_dir: Path, sheets_dir: Path, computed: dict, meta: dict) -> dict[str, Path]:
    results = run_dir / "results"
    paths = {}
    for name, rows in computed["tables"].items():
        paths[name] = results / f"{name}.csv"
        write_table(paths[name], rows)
    run_id = run_dir.name
    paths["indicator4_sheet"] = sheets_dir / f"{run_id}_indicator4_summaries.csv"
    write_table(paths["indicator4_sheet"], computed["summary_sheet"])
    paths["indicator5_sheet"] = sheets_dir / f"{run_id}_indicator5_sample.csv"
    write_table(paths["indicator5_sheet"], computed["sample_sheet"])

    md = [f"# Resultados de la evaluación — corrida `{run_id}`\n",
          f"- Modelo: `{meta['model']}` · temperatura {meta['temperature']} · ATT&CK {meta['attack_version']} · "
          f"{meta['replicates']} corridas por escenario × versión · modo demo: {'sí' if meta['demo'] else 'no'}",
          f"- Media y desviación estándar muestral (n−1). «{NO_DATA}»: no hay corridas o el valor no está definido.",
          "- No hay indicador para el paso 3 ni para la revisión global (criterio del analista).\n"]
    if meta["skipped"]:
        md.append("Escenarios/versiones sin texto (no evaluados): " + ", ".join(meta["skipped"]) + "\n")
    for name in _TITLES:
        md += [f"## {_TITLES[name]}\n", md_table(computed["tables"][name])]
    md.append(f"Hojas de revisión manual: `{paths['indicator4_sheet'].name}`, `{paths['indicator5_sheet'].name}` "
              f"(carpeta `eval/review_sheets/`).\n")
    paths["markdown"] = results / "results.md"
    paths["markdown"].write_text("\n".join(md), encoding="utf-8")
    paths["json"] = results / "results.json"
    write_json(paths["json"], dict(meta, tables=computed["tables"]))
    return paths


def run_experiment(ctx: PipelineContext, scenarios: dict[str, Scenario], run_dir: Path, sheets_dir: Path,
                   replicates: int, console=None) -> dict:
    run_dir, sheets_dir = Path(run_dir), Path(sheets_dir)
    started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    runs, skipped = [], []
    for sc in scenarios.values():
        for version in VERSIONS:
            path = sc.report_for(version)
            if not path.exists():
                skipped.append(f"{sc.name}: {version}")
                continue
            text = path.read_text(encoding="utf-8")
            for r in range(replicates):
                if console is not None:
                    console.print(f"{sc.name} · {version} · corrida {r + 1}/{replicates}")
                runs.append(_one_run(ctx, sc, version, r, text, run_dir / sc.name / version / f"r{r}"))
    computed = compute(runs, scenarios, ctx, replicates)
    meta = {"run_id": run_dir.name, "started": started,
            "finished": datetime.now(timezone.utc).isoformat(timespec="seconds"), "model": ctx.client.model,
            "temperature": TEMPERATURE, "attack_version": ctx.attack.version, "replicates": replicates,
            "demo": ctx.client.demo, "skipped": skipped,
            "runs": [{k: r[k] for k in ("scenario", "version", "replicate", "status", "error")} for r in runs]}
    paths = write_results(run_dir, sheets_dir, computed, meta)
    return {"runs": meta["runs"], "skipped": skipped, "computed": computed, "paths": paths}
