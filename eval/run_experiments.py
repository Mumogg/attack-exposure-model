"""Full experiment (CLAUDE.md §8): scenarios × {orig, mut, anon} × N replicates → five indicators.

Every run goes through the same pipeline as `aem run` in `--analyst-mode auto`.
API failures (quota, model, missing key, demo cache miss) stop the experiment
with a clear error; thanks to the cache, re-running resumes where it stopped.
An unusable LLM answer (not JSON / outside the schema) is recorded as a failed run.
Unless every answer came from the real Gemini API, tables go to `results_FAKE/` with a
`FAKE_` prefix and never to `results/` (D-71).
"""

from __future__ import annotations

import csv
import hashlib
import json
import random
from collections import Counter
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path

from aem.llm import TEMPERATURE, CacheMiss, InvalidResponse
from aem.output import write_json
from aem.pipeline import (
    EmptyExtraction, PipelineContext, output_prefix, run_pipeline, write_outputs, write_record,
)
from aem.step1_extract import PROMPT_NAME
from aem.step4_reference import SUMMARY_PROMPT
from aem.scenarios import VERSIONS, Scenario, load_reference
from eval.baseline_ioc import baseline_recognizes
from eval.metrics import (
    aggregate, aggregate_with_failures, boundary_violations_extraction, coverage_correctness, extraction_scores, gap_techniques,
    model_persistence, summary_auto_check, traditional_persistence,
)

NO_DATA = "sin dato disponible"


# --- running ----------------------------------------------------------------------------------


def _one_run(ctx: PipelineContext, sc: Scenario, version: str, replicate: int, text: str, out: Path) -> dict:
    rec = {"scenario": sc.name, "version": version, "replicate": replicate, "status": "ok", "error": None,
           "raw": [], "extra_fields": [], "summaries": []}
    first_call = len(ctx.client.call_log)

    def pre() -> str:
        return output_prefix(not ctx.client.provenance(first_call)["real"])

    try:
        result = run_pipeline(text, ctx, analyst_mode="auto", replicate=replicate, private=sc.copyrighted)
    except EmptyExtraction as exc:
        write_record(out / f"{pre()}run_record.json", exc.extraction, {"error": str(exc)})
        rec.update(status="empty", error=str(exc),
                   raw=[t.model_dump() for t in exc.extraction.extracted_raw],
                   extra_fields=exc.extraction.extra_fields)
        return rec
    except InvalidResponse as exc:
        write_json(out / f"{pre()}run_error.json", {"error": str(exc)})
        rec.update(status="error", error=str(exc))
        return rec
    write_outputs(result, out, stem=Path(sc.report_for(version)).stem)
    rec.update(raw=[t.model_dump() for t in result.extraction.extracted_raw],
               extra_fields=result.extraction.extra_fields,
               summaries=[s.model_dump(mode="json") for s in result.summaries])
    return rec


def _scored(runs: list[dict]) -> list[dict]:
    return [r for r in runs if r["status"] in ("ok", "empty")]


def _failure_reasons(runs: list[dict], width: int = 160) -> str:
    reasons = []
    for r in runs:
        if r["status"] == "error":
            msg = " ".join(str(r["error"]).split())
            reasons.append(f"r{r['replicate']}: " + (msg if len(msg) <= width else msg[:width] + "…"))
    return "; ".join(reasons) or "ninguna"


# --- formatting -------------------------------------------------------------------------------


def _pct(x: float | None) -> float | str:
    return NO_DATA if x is None else round(100 * x, 2)


def _agg_cols(prefix: str, values: list[float | None], failed: int, fmt=None) -> dict:
    """`<prefix>_mean/sd_valid` (failed runs left out) and `<prefix>_mean/sd_fail0` (failed runs as 0), D-67."""
    fmt = fmt or _pct
    cols = {}
    for view, a in aggregate_with_failures(values, failed).items():
        cols[f"{prefix}_mean_{view}"] = fmt(a["mean"])
        cols[f"{prefix}_sd_{view}"] = fmt(a["sd"]) if a["n"] >= 2 else NO_DATA
    return cols


def _num(x: float | None) -> float | str:
    return NO_DATA if x is None else round(x, 2)


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
    tables: dict[str, list[dict]] = {k: [] for k in ("runs", "indicator1", "indicator1_detail", "indicator2", "indicator3",
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

        persistence: dict[str, list] = {}
        failed_by_version: dict[str, int] = {}
        for v in VERSIONS:
            vr = [r for r in runs if r["scenario"] == sc.name and r["version"] == v]
            scored = _scored(vr)
            failed = len(vr) - len(scored)
            failed_by_version[v] = failed
            counts_cols = {"runs_total": len(vr), "runs_valid": len(scored), "failed_runs": failed}
            if vr:
                tables["runs"].append({"scenario": sc.name, "version": v, **counts_cols,
                                       "empty_runs": sum(r["status"] == "empty" for r in vr),
                                       "failure_reasons": _failure_reasons(vr)})
            raw_sets = [[t["technique_id"] for t in r["raw"]] for r in scored]
            scores = [extraction_scores(ids, ref) for ids in raw_sets]
            for level in ("exact", "parent"):
                row = {"scenario": sc.name, "version": v, "level": level, **counts_cols}
                row.update(_agg_cols("precision", [s[level]["precision"] for s in scores], failed))
                row.update(_agg_cols("recall", [s[level]["recall"] for s in scores], failed))
                tables["indicator1"].append(row)
                for kind, key in (("omitida", "omitted"), ("errónea", "erroneous")):
                    counts = Counter(t for s in scores for t in s[level][key])
                    for tid, n in sorted(counts.items()):
                        tables["indicator1_detail"].append({"scenario": sc.name, "version": v, "level": level,
                                                            "kind": kind, "technique_id": tid,
                                                            "runs": f"{n}/{len(scored)}"})
            persistence[v] = [model_persistence(ids, gaps) for ids in raw_sets]

            # indicator 5 (step 1 outputs)
            per_run = []
            for r in scored:
                items = [(t["technique_id"], t["technique_name"], t["evidence_quote"]) for t in r["raw"]]
                names = {tid: rec.name for tid, *_ in items if (rec := ctx.attack.get(tid))}
                per_run.append(boundary_violations_extraction(items, texts.get((sc.name, v), ""), r["extra_fields"],
                                                              ctx.patterns, names))
            tables["indicator5"].append({
                "scenario": sc.name, "version": v, "output": "paso 1 (extracción)", **counts_cols,
                "violations_total": sum(x["total"] for x in per_run) if per_run else NO_DATA,
                **_agg_cols("violations", [float(x["total"]) for x in per_run], failed, fmt=_num),
                "extra_fields": sum(x["extra_fields"] for x in per_run) if per_run else NO_DATA,
                "evaluative_text": sum(x["evaluative_text"] for x in per_run) if per_run else NO_DATA,
            })

        # indicator 3
        row = {"scenario": sc.name, "approach": "modelo", "denominator_techniques": len(gaps),
               "failed_runs": ", ".join(f"{v} {failed_by_version[v]}" for v in VERSIONS)}
        means = {}
        for v in VERSIONS:
            both = aggregate_with_failures(persistence[v], failed_by_version[v])
            for view, a in both.items():
                means[(v, view)] = a["mean"]
                row[f"{v}_mean_{view}"] = _pct(a["mean"])
                row[f"{v}_sd_{view}"] = _pct(a["sd"]) if a["n"] >= 2 else NO_DATA
        for v in VERSIONS[1:]:
            for view in ("fail0", "valid"):
                o, m = means[("orig", view)], means[(v, view)]
                row[f"persistence_{v}_over_orig_{view}"] = round(m / o, 4) if o and m is not None else NO_DATA
        row["ioc_matches"] = ""
        tables["indicator3"].append(row)
        trad = {"scenario": sc.name, "approach": "tradicional", "denominator_techniques": len(ref),
                "failed_runs": "no aplica (sin LLM)"}
        if all((sc.name, v) in texts for v in VERSIONS):
            recognized, matches = {}, {}
            for v in VERSIONS:
                recognized[v], matches[v] = baseline_recognizes(texts[(sc.name, v)], org.known_iocs, cfg.ioc,
                                                                cfg.baseline)
            values = {}
            for v in VERSIONS[1:]:  # anon is reported exactly like mut (D-72)
                tp = traditional_persistence(recognized["orig"], recognized[v])
                values["orig"], values[v] = tp["orig"], tp["mut"]
                ratio = NO_DATA if tp["ratio"] is None else round(tp["ratio"], 4)
                trad[f"persistence_{v}_over_orig_fail0"] = trad[f"persistence_{v}_over_orig_valid"] = ratio
            for col in row:
                if col.startswith(tuple(f"{v}_" for v in VERSIONS)):
                    v = col.split("_", 1)[0]
                    trad[col] = "determinístico" if "_sd_" in col else _pct(values[v])
            trad["ioc_matches"] = ", ".join(f"{v} {len(matches[v])}" for v in VERSIONS)
        else:
            trad.update({col: NO_DATA for col in row if col not in trad})
        tables["indicator3"].append({col: trad.get(col, NO_DATA) for col in row})

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
        "scenario": "todos", "version": "-", "output": "paso 4 (resúmenes, uno por técnica)",
        "runs_total": len(summaries), "runs_valid": len(summaries), "failed_runs": "ver indicador 4 (llm_failures)",
        "violations_total": summary_viol + summary_extra,
        **{f"violations_{k}_{v}": NO_DATA for v in ("valid", "fail0") for k in ("mean", "sd")},
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
    private = {sc.name for sc in scenarios.values() if sc.copyrighted}
    return {"tables": tables, "summary_sheet": sheet,
            "sample_sheet": [r for r in sample_sheet if r["scenario"] not in private],
            "private_sample_sheet": [r for r in sample_sheet if r["scenario"] in private]}


# --- report -------------------------------------------------------------------------------------

_TITLES = {
    "runs": "Corridas por escenario y versión (válidas, fallidas y motivo de cada falla)",
    "indicator1": "Indicador 1 — Precisión y exhaustividad del paso 1 (%, sobre extracted_raw; media principal: "
                  "`_fail0`)",
    "indicator2": "Indicador 2 — Corrección del cruce de cobertura (paso 2, sobre la referencia)",
    "indicator3": "Indicador 3 — Persistencia en el reconocimiento de la exposición (%). Denominador: técnicas "
                  "de referencia con brecha (modelo) o todas las técnicas de referencia (tradicional); media principal del "
                  "modelo: `_fail0`",
    "indicator4": "Indicador 4 — Fidelidad de los resúmenes (chequeo automático; la revisión manual está en la hoja)",
    "indicator5": "Indicador 5 — Cumplimiento de los límites (violaciones; `_fail0` y `_valid` con el mismo peso. "
                  "Aviso: contar una corrida fallida como 0 violaciones favorece al modelo)",
    "indicator1_detail": "Anexo — Indicador 1: técnicas omitidas y erróneas (en cuántas corridas)",
}


def prompt_templates_sha256() -> str:
    files = resources.files("aem.prompts")
    return "; ".join(f"{name}={hashlib.sha256(files.joinpath(name).read_bytes()).hexdigest()}"
                     for name in (PROMPT_NAME, SUMMARY_PROMPT))


def provenance_columns(meta: dict) -> dict:
    """Prepended to every row of every table, so a table copied on its own still says where it came from."""
    source = "gemini-api" if not meta["fake"] else "FAKE (" + ", ".join(meta["llm_sources"] or ["sin llamadas"]) + ")"
    return {"llm_source": source, "model": meta["model"], "model_version": "; ".join(meta["model_versions"]) or NO_DATA,
            "run_date": meta["started"][:10], "prompt_templates_sha256": meta["prompt_templates_sha256"]}


def write_results(run_dir: Path, sheets_dir: Path, computed: dict, meta: dict) -> dict[str, Path]:
    pre = output_prefix(meta["fake"])
    results = run_dir / ("results_FAKE" if meta["fake"] else "results")
    prov = provenance_columns(meta)
    tables = {name: [{**prov, **r} for r in rows] for name, rows in computed["tables"].items()}
    paths = {}
    for name, rows in tables.items():
        paths[name] = results / f"{pre}{name}.csv"
        write_table(paths[name], rows)
    run_id = run_dir.name
    paths["indicator4_sheet"] = sheets_dir / f"{pre}{run_id}_indicator4_summaries.csv"
    write_table(paths["indicator4_sheet"], computed["summary_sheet"])
    paths["indicator5_sheet"] = sheets_dir / f"{pre}{run_id}_indicator5_sample.csv"
    write_table(paths["indicator5_sheet"], computed["sample_sheet"])
    if computed["private_sample_sheet"]:  # quotes from copyrighted text: git-ignored folder
        paths["indicator5_private_sheet"] = sheets_dir / "private" / f"{pre}{run_id}_indicator5_sample_private.csv"
        write_table(paths["indicator5_private_sheet"], computed["private_sample_sheet"])

    md = []
    if meta["fake"]:
        md += [f"# FAKE — resultados con un LLM simulado, no válidos para la tesis (corrida `{run_id}`)\n",
               f"> Origen de las respuestas: {prov['llm_source']}. Estas tablas no provienen de la API real de "
               "Gemini y no deben citarse.\n"]
    md += [f"# Resultados de la evaluación — corrida `{run_id}`\n",
          f"- Modelo: `{meta['model']}` · temperatura {meta['temperature']} · ATT&CK {meta['attack_version']} · "
          f"{meta['replicates']} corridas por escenario × versión · modo demo: {'sí' if meta['demo'] else 'no'}",
          f"- Media y desviación estándar muestral (n−1). «{NO_DATA}»: no hay corridas o el valor no está definido.",
          "- Cada media se informa dos veces (D-67): `_fail0` cuenta cada corrida fallida (`failed_runs`) como 0 y "
          "`_valid` usa solo las corridas válidas. Indicadores 1 y 3 (modelo): media principal: `_fail0`; `_valid` "
          "es secundaria. Indicador 5: ambas con el mismo peso; contar una falla como 0 violaciones favorece al "
          "modelo.",
          f"- Origen: {prov['llm_source']} · versión del modelo: {prov['model_version']} · fecha: {prov['run_date']} · "
          f"hash SHA-256 de las plantillas de prompt: {prov['prompt_templates_sha256']}",
          "- No hay indicador para el paso 3 ni para la revisión global (criterio del analista).\n"]
    if meta["skipped"]:
        md.append("Escenarios/versiones sin texto (no evaluados): " + ", ".join(meta["skipped"]) + "\n")
    stamp = (f"_{prov['llm_source']} · modelo `{prov['model']}` ({prov['model_version']}) · {prov['run_date']} · "
             f"prompts {prov['prompt_templates_sha256']}_\n")
    for name in _TITLES:
        md += [f"## {'FAKE — ' if meta['fake'] else ''}{_TITLES[name]}\n", stamp, md_table(computed["tables"][name])]
    md.append(f"Hojas de revisión manual: `{paths['indicator4_sheet'].name}`, `{paths['indicator5_sheet'].name}` "
              f"(carpeta `eval/review_sheets/`).\n")
    paths["markdown"] = results / f"{pre}results.md"
    paths["markdown"].write_text("\n".join(md), encoding="utf-8")
    paths["json"] = results / f"{pre}results.json"
    write_json(paths["json"], dict(meta, tables=tables))
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
            base = run_dir / "private" if sc.copyrighted else run_dir
            done = []
            for r in range(replicates):
                if console is not None:
                    console.print(f"{sc.name} · {version} · corrida {r + 1}/{replicates}")
                try:
                    done.append(_one_run(ctx, sc, version, r, text, base / sc.name / version / f"r{r}"))
                except CacheMiss:
                    if not (ctx.client.demo and sc.copyrighted):
                        raise
                    # the private cache is never published: without it, the copyrighted scenario cannot be replayed
                    skipped.append(f"{sc.name}: {version} (sin caché privada: texto con derechos de autor)")
                    done = []
                    break
            runs += done
    computed = compute(runs, scenarios, ctx, replicates)
    provenance = ctx.client.provenance()
    meta = {"fake": not provenance["real"], "llm_sources": provenance["sources"],
            "model_versions": provenance["model_versions"], "prompt_templates_sha256": prompt_templates_sha256(),
            "run_id": run_dir.name, "started": started,
            "finished": datetime.now(timezone.utc).isoformat(timespec="seconds"), "model": ctx.client.model,
            "temperature": TEMPERATURE, "attack_version": ctx.attack.version, "replicates": replicates,
            "demo": ctx.client.demo, "skipped": skipped,
            "runs": [{k: r[k] for k in ("scenario", "version", "replicate", "status", "error")} for r in runs]}
    paths = write_results(run_dir, sheets_dir, computed, meta)
    return {"runs": meta["runs"], "skipped": skipped, "computed": computed, "paths": paths}
