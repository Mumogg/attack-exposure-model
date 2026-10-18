"""`aem report --html`: one self-contained HTML page with the results of a real run (inline CSS and JS, no CDN).

Reads only what is already on disk: `results/results.json`, the per-run `*_exposure.csv`, the evidence quotes of
the per-run `run_record.json` (public scenarios only, unless `--private`), the reference mappings, the review
sheets (figures only when complete) and the sensitivity output. No API call and no figure is recomputed.

English first, with a button for Spanish. In the public page a copyrighted scenario (Akira) shows only ATT&CK
IDs and names, tactics, coverage, actions and aggregates; its evidence quotes go only to the private page
(`runs/<id>/private/report_full.html`, git-ignored). Before the public page is written, its text is checked
against the local copy of the DFIR report (8-word windows and IoC values); any hit stops the command.
"""

from __future__ import annotations

import csv
import json
import re
from collections import Counter, defaultdict
from html import escape, unescape
from pathlib import Path

from aem.scenarios import VERSIONS, Scenario, load_reference
from eval import review
from eval.report import ReportError, load_results
from eval.run_experiments import NO_DATA, PARTIAL_LINE

ACTIONS = ("Act", "Attend", "Track*", "Track")
COVERAGE_LEVELS = ("sin cobertura", "parcial", "cubierta")
COVERAGE_EN = {"sin cobertura": "no coverage", "parcial": "partial", "cubierta": "covered"}
# ATT&CK v19.2 Enterprise matrix order (x-mitre-matrix tactic_refs)
TACTIC_ORDER = ("Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
                "Privilege Escalation", "Stealth", "Defense Impairment", "Credential Access", "Discovery",
                "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact")
ATTACK_SITE = "https://attack.mitre.org/"
VERSION_LABEL = {"orig": ("orig (original)", "orig (original)"), "mut": ("mut (IoCs changed)", "mut (IoC cambiados)"),
                 "anon": ("anon (IoCs and names changed)", "anon (IoC y nombres cambiados)")}
WINDOW_WORDS = 8


class LeakError(ReportError):
    """The public page would contain text or IoC values of the DFIR report."""


def t(en: str, es: str) -> str:
    """Both languages in the page; CSS shows one (English when JavaScript is off)."""
    return f'<span lang="en">{en}</span><span lang="es">{es}</span>'


def _v(value) -> str:
    if value is None or value == NO_DATA or value == "":
        return t("no data available", "sin dato disponible")
    return escape(str(value))


def _num(value) -> float | None:
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None


# --- data -------------------------------------------------------------------------------------


def _read_csv(path: Path) -> list[dict]:
    with path.open(encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def _attack_link(row: dict) -> str:
    link = row.get("source_link") or ""
    if link.startswith(ATTACK_SITE + "techniques/"):
        return link
    return ATTACK_SITE + "techniques/" + row["technique_id"].replace(".", "/") + "/"


def collect(run_dir: Path, sheets_dir: Path | None, scenarios: dict[str, Scenario], private: bool) -> dict:
    run_dir = Path(run_dir)
    data = load_results(run_dir)
    techniques: dict[tuple, dict] = {}
    actions: dict[tuple, Counter] = defaultdict(Counter)
    coverage: dict[tuple, Counter] = defaultdict(Counter)
    valid_runs: dict[tuple, int] = Counter((r["scenario"], r["version"]) for r in data.get("runs", [])
                                           if r["status"] in ("ok", "empty"))
    reference: dict[str, dict[str, str]] = {}
    missing_outputs = []
    for sc in scenarios.values():
        if not any(r["scenario"] == sc.name for r in data.get("runs", [])):
            continue
        try:
            reference[sc.name] = {r.technique_id: r.tactic for r in load_reference(sc.reference) if r.valid}
        except FileNotFoundError:
            reference[sc.name] = {}
        base = run_dir / ("private" if sc.copyrighted else "") / sc.name
        with_quotes = private or not sc.copyrighted
        found_any = False
        for v in VERSIONS:
            for rdir in sorted(base.glob(f"{v}/r*")):
                files = [p for p in rdir.glob("*_exposure.csv") if not p.name.startswith("FAKE_")]
                if not files:
                    continue
                found_any = True
                quotes = {}
                record = rdir / "run_record.json"
                if with_quotes and record.exists():
                    rec = json.loads(record.read_text(encoding="utf-8"))
                    quotes = {q["technique_id"]: q["evidence_quote"] for q in rec["extraction"]["extracted_raw"]}
                for row in _read_csv(files[0]):
                    tid = row["technique_id"]
                    actions[(sc.name, v)][row["action"]] += 1
                    coverage[(sc.name, v)][row["coverage_validated"]] += 1
                    item = techniques.setdefault((sc.name, v, tid), {
                        "scenario": sc.name, "version": v, "technique_id": tid, "name": row["technique_name"],
                        "tactics": [x.strip() for x in row["tactics"].split(";") if x.strip()],
                        "actions": Counter(), "coverage": Counter(), "runs": 0, "quote": None, "quote_run": None,
                        "link": _attack_link(row), "in_reference": tid in reference[sc.name],
                        "copyrighted": sc.copyrighted})
                    item["actions"][row["action"]] += 1
                    item["coverage"][row["coverage_validated"]] += 1
                    item["runs"] += 1
                    if with_quotes and item["quote"] is None and quotes.get(tid):
                        item["quote"], item["quote_run"] = quotes[tid], rdir.name
        if not found_any:
            missing_outputs.append(sc.name)
    manual = review.manual_results(Path(sheets_dir), data.get("run_id", run_dir.name)) if sheets_dir else None
    sens_path = run_dir / "results" / "sensitivity" / "sensitivity.json"
    sensitivity = json.loads(sens_path.read_text(encoding="utf-8")) if sens_path.exists() else None
    return {"results": data, "techniques": techniques, "actions": actions, "coverage": coverage,
            "valid_runs": valid_runs, "reference": reference, "manual": manual, "sensitivity": sensitivity,
            "missing_outputs": missing_outputs, "private": private,
            "copyrighted": {sc.name for sc in scenarios.values() if sc.copyrighted}}


# --- SVG charts -------------------------------------------------------------------------------

_PATTERNS = """<defs>
<pattern id="p-orig" width="6" height="6" patternUnits="userSpaceOnUse"><rect width="6" height="6" fill="var(--s1)"/></pattern>
<pattern id="p-mut" width="6" height="6" patternUnits="userSpaceOnUse" patternTransform="rotate(45)"><rect width="6" height="6" fill="var(--s2)"/><line x1="0" y1="0" x2="0" y2="6" stroke="var(--ink)" stroke-width="2"/></pattern>
<pattern id="p-anon" width="6" height="6" patternUnits="userSpaceOnUse"><rect width="6" height="6" fill="var(--s3)"/><circle cx="3" cy="3" r="1.3" fill="var(--paper)"/></pattern>
</defs>"""


def svg_bars(groups: list[str], series: dict[str, list[tuple]], label: str, unit: str = "%",
             ymax: float = 100.0) -> str:
    """Grouped bars (one per version) with ± SD error bars and the value written on top: patterns and labels,
    never colour alone. `series[version]` holds (mean, sd) per group; a missing mean is written as «n/a»."""
    if not groups:
        return ""
    bar, gap, left, top, height = 26, 22, 44, 16, 200
    width = left + len(groups) * (3 * bar + gap) + 10
    out = [f'<svg class="chart" viewBox="0 0 {width} {top + height + 46}" role="img" aria-label="{escape(label)}">',
           f"<title>{escape(label)}</title>", _PATTERNS]
    for tick in range(0, 101, 25):
        y = top + height - height * tick / 100
        out.append(f'<line x1="{left}" x2="{width - 6}" y1="{y:.1f}" y2="{y:.1f}" class="grid"/>'
                   f'<text x="{left - 6}" y="{y + 4:.1f}" class="tick" text-anchor="end">'
                   f'{ymax * tick / 100:g}</text>')
    for g_i, group in enumerate(groups):
        x0 = left + 8 + g_i * (3 * bar + gap)
        for v_i, v in enumerate(VERSIONS):
            mean, sd = series[v][g_i]
            x = x0 + v_i * bar
            m = _num(mean)
            if m is None:
                out.append(f'<text x="{x + bar / 2}" y="{top + height - 4}" class="val" text-anchor="middle">n/a</text>')
                continue
            h = height * min(m, ymax) / ymax
            out.append(f'<rect x="{x + 2}" y="{top + height - h:.1f}" width="{bar - 4}" height="{h:.1f}" '
                       f'fill="url(#p-{v})" class="bar"><title>{escape(group)} · {v}: {m:g}{unit}'
                       f'{"" if _num(sd) is None else f" ± {sd:g}"}</title></rect>')
            s = _num(sd)
            if s is not None:
                y1, y2 = (top + height - height * min(max(m - s, 0), ymax) / ymax,
                          top + height - height * min(m + s, ymax) / ymax)
                cx = x + bar / 2
                out.append(f'<path d="M{cx} {y1:.1f}V{y2:.1f}M{cx - 5} {y1:.1f}h10M{cx - 5} {y2:.1f}h10" class="err"/>')
            out.append(f'<text x="{x + bar / 2}" y="{top + height - h - 4 - (0 if s is None else height * s / ymax):.1f}" '
                       f'class="val" text-anchor="middle">{m:g}</text>')
        out.append(f'<text x="{x0 + 1.5 * bar}" y="{top + height + 18}" class="grp" text-anchor="middle">'
                   f'{escape(group)}</text>')
    out.append("</svg>")
    return "".join(out)


def legend() -> str:
    items = "".join(f'<li><svg width="18" height="14" aria-hidden="true">{_PATTERNS}<rect width="18" height="14" '
                    f'fill="url(#p-{v})" stroke="currentColor"/></svg>{t(*VERSION_LABEL[v])}</li>' for v in VERSIONS)
    return f'<ul class="legend">{items}</ul>'


def stacked(counts: Counter, order: tuple, names: dict | None = None) -> str:
    """One horizontal bar split by category, each part labelled with its name and count."""
    total = sum(counts.values())
    if not total:
        return f'<p class="muted">{t("no data available", "sin dato disponible")}</p>'
    parts = []
    for i, key in enumerate(order):
        n = counts.get(key, 0)
        if not n:
            continue
        label = names[key] if names else (key, key)
        parts.append(f'<span class="seg seg{i}" style="flex:{n}" title="{escape(key)}: {n}">'
                     f'{t(escape(label[0]), escape(label[1]))} {n}</span>')
    return f'<div class="stack" role="img" aria-label="{escape(", ".join(f"{k}: {counts.get(k, 0)}" for k in order))}">' \
           + "".join(parts) + "</div>"


# --- tables -----------------------------------------------------------------------------------


def table(headers: list[str], rows: list[list[str]], cls: str = "") -> str:
    head = "".join(f'<th scope="col">{h}</th>' for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return f'<div class="scroll"><table class="{cls}"><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def _scenarios(rows: list[dict]) -> list[str]:
    return list(dict.fromkeys(r["scenario"] for r in rows))


def _mean_sd(row: dict, prefix: str, view: str = "fail0") -> str:
    m, s = row.get(f"{prefix}_mean_{view}", NO_DATA), row.get(f"{prefix}_sd_{view}", NO_DATA)
    return _v(m) + ("" if s == NO_DATA else f" ± {escape(str(s))}")


# --- sections ---------------------------------------------------------------------------------


def _header(d: dict) -> str:
    res = d["results"]
    first = next((r for rows in res["tables"].values() for r in rows), {})
    run_date = first.get("run_date", str(res.get("started", ""))[:10])
    banner = ""
    if res.get("partial"):
        omitted = ", ".join(f'{o["scenario"]} ({o["reason"]})' for o in res.get("escenarios_omitidos") or [])
        banner = (f'<p class="banner" role="alert"><strong>{t("PARTIAL RESULT", PARTIAL_LINE.split(":")[0])}</strong>'
                  f' — {t("omitted scenarios", "escenarios omitidos")}: {escape(omitted) or "-"}</p>')
    private = ('<p class="banner">' + t("PRIVATE version: includes evidence quotes of the copyrighted report. "
                                         "Do not publish.", "Versión PRIVADA: incluye citas del reporte con "
                                         "derechos de autor. No publicar.") + '</p>') if d["private"] else ""
    facts = [(t("Run", "Corrida"), escape(res.get("run_id", ""))),
             (t("Model", "Modelo"), escape(f'{res.get("model", "")} ({"; ".join(res.get("model_versions") or []) or NO_DATA})')),
             (t("Run date", "Fecha de la corrida"), escape(run_date)),
             ("ATT&amp;CK", escape(str(res.get("attack_version", "")))),
             (t("Runs per scenario × version", "Corridas por escenario × versión"), escape(str(res.get("replicates", "")))),
             (t("Answers", "Respuestas"), escape(first.get("llm_source", NO_DATA))),
             (t("Prompt templates (SHA-256)", "Plantillas de prompt (SHA-256)"),
              f'<code>{escape(res.get("prompt_templates_sha256", ""))}</code>')]
    dl = "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in facts)
    return ('<header id="summary"><h1>' + t("AI-assisted exposure model based on MITRE ATT&amp;CK — results",
                              "Modelo de exposición asistido por IA basado en MITRE ATT&amp;CK — resultados") + '</h1>'
            f'{banner}{private}<dl class="facts">{dl}</dl>'
            '<p class="muted">' + t("Means are sample means over the runs; error bars are ± sample SD (n−1). "
                                   "<code>_fail0</code> counts a failed run as 0 (primary mean for indicators 1 and 3); "
                                   "<code>_valid</code> uses only valid runs (D-67).",
                                   "Medias muestrales sobre las corridas; las barras de error son ± DE muestral (n−1). "
                                   "<code>_fail0</code> cuenta una corrida fallida como 0 (media principal de los "
                                   "indicadores 1 y 3); <code>_valid</code> usa solo las corridas válidas (D-67).") + '</p>'
            "</header>")


def _indicator1(tables: dict) -> str:
    rows = tables.get("indicator1", [])
    groups = _scenarios(rows)
    find = {(r["scenario"], r["version"], r["level"]): r for r in rows}
    out = [f'<h3>{t("Indicator 1 — Step 1 precision and recall (%)", "Indicador 1 — Precisión y exhaustividad del paso 1 (%)")}</h3>']
    for metric, en, es in (("precision", "Precision", "Precisión"), ("recall", "Recall", "Exhaustividad")):
        series = {v: [(find.get((g, v, "exact"), {}).get(f"{metric}_mean_fail0"),
                       find.get((g, v, "exact"), {}).get(f"{metric}_sd_fail0")) for g in groups] for v in VERSIONS}
        out.append('<figure><figcaption>' + t(f"{en}, exact level (sub-technique), mean _fail0 ± SD",
                                             f"{es}, nivel exacto (sub-técnica), media _fail0 ± DE") + '</figcaption>'
                   f'{svg_bars(groups, series, f"Indicator 1 {en}")}</figure>')
    out.append(legend())
    body = [[escape(r["scenario"]), escape(r["version"]),
             t("exact", "exacto") if r["level"] == "exact" else t("parent", "padre"),
             _mean_sd(r, "precision"), _mean_sd(r, "precision", "valid"), _mean_sd(r, "recall"),
             _mean_sd(r, "recall", "valid"), f'{_v(r.get("runs_valid"))}/{_v(r.get("runs_total"))}'] for r in rows]
    out.append(table([t("Scenario", "Escenario"), t("Version", "Versión"), t("Level", "Nivel"),
                      t("Precision _fail0", "Precisión _fail0"), t("Precision _valid", "Precisión _valid"),
                      t("Recall _fail0", "Exhaustividad _fail0"), t("Recall _valid", "Exhaustividad _valid"),
                      t("Valid/total runs", "Corridas válidas/totales")], body))
    return "".join(out)


def _indicator2(tables: dict) -> str:
    rows = tables.get("indicator2", [])
    body = [[escape(r["scenario"]), _v(r.get("reference_techniques")), _v(r.get("matches")), _v(r.get("accuracy")),
             _v(r.get("mismatches"))] for r in rows]
    return (f'<h3>{t("Indicator 2 — Correctness of the coverage lookup (step 2)", "Indicador 2 — Corrección del cruce de cobertura (paso 2)")}</h3>'
            f'<p class="muted">{t("Deterministic (no LLM): no SD.", "Determinístico (sin LLM): sin DE.")}</p>'
            + table([t("Scenario", "Escenario"), t("Reference techniques", "Técnicas de referencia"),
                     t("Matches", "Coincidencias"), t("Accuracy (%)", "Exactitud (%)"),
                     t("Mismatches", "Discrepancias")], body))


def _indicator3(tables: dict) -> str:
    rows = [r for r in tables.get("indicator3", []) if r.get("approach") == "modelo"]
    groups = _scenarios(rows)
    series = {v: [(r.get(f"{v}_mean_fail0"), r.get(f"{v}_sd_fail0")) for r in rows] for v in VERSIONS}
    body = [[escape(r["scenario"]), _v(r.get("denominator_techniques")),
             *[_mean_sd(r, v) for v in VERSIONS], *[_mean_sd(r, v, "valid") for v in VERSIONS]] for r in rows]
    return (f'<h3>{t("Indicator 3 — Persistence of the model (%)", "Indicador 3 — Persistencia del modelo (%)")}</h3>'
            '<p class="muted">' + t("Share of the scenario’s reference techniques with a coverage gap that the model "
                                   "extracts (exact ID).", "Proporción de las técnicas de referencia con brecha de "
                                   "cobertura que el modelo extrae (ID exacto).") + '</p>'
            f'<figure>{svg_bars(groups, series, "Indicator 3 model persistence")}</figure>{legend()}'
            + table([t("Scenario", "Escenario"), t("Gaps (denominator)", "Brechas (denominador)"),
                     *[f"{v} _fail0" for v in VERSIONS], *[f"{v} _valid" for v in VERSIONS]], body))


def _indicator4(tables: dict, manual: dict | None) -> str:
    r = (tables.get("indicator4") or [{}])[0]
    auto = (f'{_v(r.get("auto_check_ok"))} / {_v(r.get("techniques_summarized"))} '
            f'({_v(r.get("auto_check_ok_pct"))} %)')
    if manual is None or manual["indicator4"]["status"] != "completa":
        man = t("no data available", "sin dato disponible")
        if manual is not None:
            man += f' <span class="muted">({escape(manual["indicator4"]["status_text"])})</span>'
    else:
        m = manual["indicator4"]
        man = f'{m["ok"]} / {m["total"]} ({m["ok_pct"]} %)'
    return (f'<h3>{t("Indicator 4 — Fidelity of the step 4 summaries", "Indicador 4 — Fidelidad de los resúmenes del paso 4")}</h3>'
            + table([t("Measure", "Medida"), t("Value", "Valor")],
                    [[t("Automatic check ok", "Chequeo automático ok"), auto],
                     [t("LLM failures", "Fallos del LLM"), _v(r.get("llm_failures"))],
                     [t("Manual review: faithful summaries", "Revisión manual: resúmenes fieles"), man]]))


def _indicator5(tables: dict, manual: dict | None) -> str:
    rows = tables.get("indicator5", [])
    step1 = [r for r in rows if r.get("version") in VERSIONS]
    groups = _scenarios(step1)
    find = {(r["scenario"], r["version"]): r for r in step1}
    charts = []
    for view in ("fail0", "valid"):
        series = {v: [(find.get((g, v), {}).get(f"violations_mean_{view}"),
                       find.get((g, v), {}).get(f"violations_sd_{view}")) for g in groups] for v in VERSIONS}
        top = max([_num(m) or 0 for s in series.values() for m, _ in s] + [1])
        charts.append(f'<figure><figcaption>{t(f"Violations per run, mean _{view} ± SD", f"Violaciones por corrida, media _{view} ± DE")}'
                      f'</figcaption>{svg_bars(groups, series, f"Indicator 5 violations {view}", unit="", ymax=float(top * 1.25))}</figure>')
    body = [[escape(r["scenario"]), escape(r["version"]), escape(str(r.get("output", ""))),
             _mean_sd(r, "violations"), _mean_sd(r, "violations", "valid"), _v(r.get("violations_total")),
             _v(r.get("extra_fields")), _v(r.get("evaluative_text"))] for r in rows]
    if manual is None:
        man = [[t("all", "todos"), t("no data available", "sin dato disponible")]]
    else:
        m = manual["indicator5"]
        complete = m["status"] == "completa"
        man = [[escape(sc if sc != "-" else "step 4 / paso 4"),
                (f'{c["with_valuation"]} / {c["total"]}' if complete else t("no data available", "sin dato disponible"))]
               for sc, c in m["by_scenario"].items()]
        man.append([t("total", "total"), (f'{m["with_valuation"]} / {m["total"]} ({m["with_valuation_pct"]} %)'
                                         if complete else t("no data available", "sin dato disponible")
                                         + f' <span class="muted">({escape(m["status_text"])})</span>')])
    return (f'<h3>{t("Indicator 5 — Compliance with the boundaries", "Indicador 5 — Cumplimiento de los límites")}</h3>'
            '<p class="muted">' + t("Both means carry the same weight (D-67): counting a failed run as 0 violations "
                                   "favours the model.", "Ambas medias tienen el mismo peso (D-67): contar una corrida "
                                   "fallida como 0 violaciones favorece al modelo.") + '</p>'
            + "".join(charts) + legend()
            + f'<h4>{t("Automatic count", "Conteo automático")}</h4>'
            + table([t("Scenario", "Escenario"), t("Version", "Versión"), t("Output", "Salida"), "_fail0", "_valid",
                     t("Total", "Total"), t("Extra fields", "Campos extra"), t("Evaluative text", "Texto valorativo")], body)
            + f'<h4>{t("Manual review of the sample (separate figure)", "Revisión manual de la muestra (cifra separada)")}</h4>'
            + table([t("Scenario", "Escenario"), t("Texts with valuation / reviewed", "Textos con valoración / revisados")], man))


def _model_vs_traditional(tables: dict) -> str:
    rows = tables.get("indicator3", [])
    body = []
    for r in rows:
        approach = t("model", "modelo") if r.get("approach") == "modelo" else t("traditional (IoC)", "tradicional (IoC)")
        body.append([escape(r["scenario"]), approach, _v(r.get("denominator_techniques")),
                     *[_v(r.get(f"{v}_mean_fail0")) for v in VERSIONS],
                     _v(r.get("persistence_mut_over_orig_fail0")), _v(r.get("persistence_anon_over_orig_fail0")),
                     _v(r.get("ioc_matches"))])
    return (f'<section id="comparison"><h2>{t("3. Model vs traditional approach (indicator 3)", "3. Modelo frente al enfoque tradicional (indicador 3)")}</h2>'
            + table([t("Scenario", "Escenario"), t("Approach", "Enfoque"), t("Denominator", "Denominador"),
                     "orig _fail0", "mut _fail0", "anon _fail0", "mut/orig", "anon/orig",
                     t("IoC matches", "Coincidencias de IoC")], body)
            + '<p class="note"><strong>C1.</strong> ' + t("The traditional approach gives 0 % in mut and anon by "
                "construction: no IoC of the original survives there (the code checks it). It is a reference point, "
                "not an independent measurement.", "El enfoque tradicional da 0 % en mut y anon por construcción: "
                "ningún IoC del original sobrevive (lo verifica el código). Es un punto de referencia, no una "
                "medición independiente.") + '</p>'
            + '<p class="note"><strong>D-62.</strong> ' + t("The organisation “knows” 50 % of the unique IoCs of each "
                "orig report (fixed seed); one match recognises the threat and, with it, all its reference "
                "techniques. It is a deliberately favourable bound for the traditional approach in orig (100 %).",
                "La organización «conoce» el 50 % de los IoC únicos de cada reporte orig (semilla fija); una "
                "coincidencia reconoce la amenaza y, con ella, todas sus técnicas de referencia. Es una cota "
                "deliberadamente favorable al enfoque tradicional en orig (100 %).") + '</p></section>')


def _distributions(d: dict) -> str:
    out = [f'<section id="distribution"><h2>{t("4. Actions, coverage and tactics", "4. Acciones, cobertura y tácticas")}</h2>',
           '<p class="muted">' + t("Counts over all valid runs (one row per extracted technique and run).",
                                  "Conteos sobre todas las corridas válidas (una fila por técnica extraída y corrida).") + '</p>']
    rows = []
    for (sc, v), counts in d["actions"].items():
        rows.append([escape(sc), escape(v), stacked(counts, ACTIONS),
                     stacked(d["coverage"][(sc, v)], COVERAGE_LEVELS,
                             {k: (COVERAGE_EN[k], k) for k in COVERAGE_LEVELS})])
    out.append(table([t("Scenario", "Escenario"), t("Version", "Versión"), t("Step 3 actions", "Acciones del paso 3"),
                      t("Coverage (step 2)", "Cobertura (paso 2)")], rows, "dist"))
    if d["missing_outputs"]:
        out.append(f'<p class="muted">{t("No per-run outputs on this machine for", "Sin salidas por corrida en esta máquina para")}: '
                   f'{escape(", ".join(d["missing_outputs"]))}.</p>')
    # tactic map: distinct techniques extracted in any version and run, per tactic
    by_tactic: dict[tuple, dict] = defaultdict(dict)
    for item in d["techniques"].values():
        for tac in item["tactics"]:
            by_tactic[(tac, item["scenario"])][item["technique_id"]] = item["actions"].most_common(1)[0][0]
    scen = list(dict.fromkeys(i["scenario"] for i in d["techniques"].values()))
    tactics = [x for x in TACTIC_ORDER if any((x, s) in by_tactic for s in scen)]
    tactics += sorted({tac for tac, _ in by_tactic} - set(tactics))
    map_rows = []
    for tac in tactics:
        cells = [escape(tac)]
        for s in scen:
            found = by_tactic.get((tac, s), {})
            if not found:
                cells.append('<span class="muted">0</span>')
                continue
            c = Counter(found.values())
            detail = " · ".join(f"{a} {c[a]}" for a in ACTIONS if c.get(a))
            cells.append(f'<span class="heat" style="--n:{min(len(found), 12)}"><strong>{len(found)}</strong></span> '
                         f'<small>{escape(detail)}</small>')
        map_rows.append(cells)
    out.append(f'<h3>{t("Map by ATT&amp;CK tactic", "Mapa por táctica de ATT&amp;CK")}</h3>'
               '<p class="muted">' + t("Distinct techniques extracted (any version and run) per tactic, with their step 3 action.",
                                      "Técnicas distintas extraídas (cualquier versión y corrida) por táctica, con su acción del paso 3.") + '</p>')
    out.append(table([t("Tactic", "Táctica"), *[escape(s) for s in scen]], map_rows, "map"))
    out.append("</section>")
    return "".join(out)


def _technique_table(d: dict) -> str:
    items = sorted(d["techniques"].values(), key=lambda i: (i["scenario"], VERSIONS.index(i["version"]), i["technique_id"]))
    rows = []
    for i in items:
        actions = ", ".join(f"{a}" + (f" ({n})" if len(i["actions"]) > 1 else "") for a, n in i["actions"].most_common())
        cov = ", ".join(COVERAGE_EN.get(k, k) for k in i["coverage"])
        cov_es = ", ".join(i["coverage"])
        total = d["valid_runs"].get((i["scenario"], i["version"]), 0)
        if i["copyrighted"] and not d["private"]:
            quote = f'<span class="muted">{t("not shown (copyrighted report)", "no se muestra (reporte con derechos de autor)")}</span>'
        elif i["quote"]:
            quote = f'<q>{escape(i["quote"])}</q> <small class="muted">({escape(i["quote_run"])})</small>'
        else:
            quote = t("no data available", "sin dato disponible")
        ref = t("yes", "sí") if i["in_reference"] else t("no", "no")
        rows.append(
            f'<tr data-scenario="{escape(i["scenario"])}" data-version="{escape(i["version"])}" '
            f'data-tactics="{escape("|".join(i["tactics"]))}" data-actions="{escape("|".join(i["actions"]))}">'
            f'<td>{escape(i["scenario"])}</td><td>{escape(i["version"])}</td>'
            f'<td><a href="{escape(i["link"])}" rel="noopener" target="_blank">{escape(i["technique_id"])}</a></td>'
            f'<td>{escape(i["name"])}</td><td>{escape("; ".join(i["tactics"]))}</td><td>{escape(actions)}</td>'
            f'<td>{t(escape(cov), escape(cov_es))}</td><td>{ref}</td><td>{i["runs"]}/{total}</td><td>{quote}</td></tr>')

    def select(name: str, en: str, es: str, values: list[str]) -> str:
        opts = "".join(f'<option value="{escape(v)}">{escape(v)}</option>' for v in values)
        return (f'<label>{t(en, es)} <select data-filter="{name}"><option value="">{"*"}</option>{opts}</select></label>')

    scen = list(dict.fromkeys(i["scenario"] for i in items))
    tactics = [x for x in TACTIC_ORDER if any(x in i["tactics"] for i in items)]
    tactics += sorted({x for i in items for x in i["tactics"]} - set(tactics))
    head = "".join(f'<th scope="col">{h}</th>' for h in (
        t("Scenario", "Escenario"), t("Version", "Versión"), "ID", t("Name (ATT&amp;CK)", "Nombre (ATT&amp;CK)"),
        t("Tactics", "Tácticas"), t("Action", "Acción"), t("Coverage", "Cobertura"),
        t("In reference", "En la referencia"), t("Runs", "Corridas"), t("Evidence quote (step 1)", "Cita de evidencia (paso 1)")))
    note = "" if d["private"] else (
        '<p class="muted">' + t("Evidence quotes only for the public reports (CISA). The copyrighted report shows only "
                               "IDs, ATT&amp;CK names, tactics, coverage, actions and aggregates.",
                               "Citas solo de los reportes públicos (CISA). El reporte con derechos de autor muestra "
                               "solo IDs, nombres de ATT&amp;CK, tácticas, cobertura, acciones y agregados.") + '</p>')
    return (f'<section id="techniques"><h2>{t("5. Techniques extracted", "5. Técnicas extraídas")}</h2>{note}'
            f'<div class="filters">{select("scenario", "Scenario", "Escenario", scen)}'
            f'{select("version", "Version", "Versión", list(VERSIONS))}{select("tactics", "Tactic", "Táctica", tactics)}'
            f'{select("actions", "Action", "Acción", list(ACTIONS))}'
            f'<output id="count" aria-live="polite"></output></div>'
            f'<div class="scroll"><table id="tech"><thead><tr>{head}</tr></thead><tbody>{"".join(rows)}</tbody></table></div>'
            "</section>")


def _sensitivity(d: dict) -> str:
    s = d["sensitivity"]
    title = f'<h3>{t("Sensitivity analysis (D-77)", "Análisis de sensibilidad (D-77)")}</h3>'
    if not s:
        return title + f'<p>{t("no data available", "sin dato disponible")} (<code>aem sensitivity</code>)</p>'
    body = [[escape(r["parameter"]), escape(str(r["value"])), escape(r["scenario"]), _v(r["gaps"]),
             *[_v(r.get(f"{v}_mean_fail0")) for v in VERSIONS], _v(r.get("persistence_mut_over_orig_fail0")),
             _v(r.get("persistence_anon_over_orig_fail0"))] for r in s["rows"]]
    return (title + '<p class="note">' + t("Sensitivity analysis. It does not replace the main results; the confirmed "
                                         "configuration (D-20, D-21) did not change.", escape(s["note"])) + '</p>'
            + table([t("Parameter", "Parámetro"), t("Value", "Valor"), t("Scenario", "Escenario"), t("Gaps", "Brechas"),
                     "orig _fail0", "mut _fail0", "anon _fail0", "mut/orig", "anon/orig"], body))


def _limits(tables: dict) -> str:
    recalls = [_num(r.get("recall_mean_fail0")) for r in tables.get("indicator1", []) if r.get("level") == "exact"]
    recalls = [r for r in recalls if r is not None]
    span = f"{min(recalls):g}–{max(recalls):g} %" if recalls else NO_DATA
    items = [
        ("C1", "The traditional approach gives 0 % in mut and anon by construction; it is a reference point, not an "
               "independent measurement.",
               "El enfoque tradicional da 0 % en mut y anon por construcción; es un punto de referencia, no una "
               "medición independiente."),
        ("C2", "mut keeps the names of the actor and the malware, so part of the persistence in mut may come from "
               "recognising the threat by name; anon replaces those names to control for it (D-72).",
               "mut conserva los nombres del actor y del malware, así que parte de la persistencia en mut puede venir "
               "de reconocer la amenaza por su nombre; anon reemplaza esos nombres para controlarlo (D-72)."),
        ("C3", "The language model may have seen these public reports during training; neither mut nor anon removes "
               "that effect.", "El modelo de lenguaje pudo ver estos reportes públicos durante su entrenamiento; ni mut "
               "ni anon eliminan ese efecto."),
        (t("Reference", "Referencia"), "The CISA reference is the advisories’ ATT&amp;CK tables: the authors’ mapping, "
               "not a complete ground truth. A technique supported by the text but absent from the table counts as an "
               "error (D-60, D-61).", "La referencia de CISA son las tablas de ATT&amp;CK de los boletines: el mapeo de "
               "sus autores, no una verdad de terreno completa. Una técnica respaldada por el texto pero ausente de la "
               "tabla cuenta como error (D-60, D-61)."),
        (t("Scope", "Alcance"), "One model, one date and these prompt templates; three scenarios and one fictional "
               "organisation. The figures do not generalise.", "Un modelo, una fecha y estas plantillas de prompt; tres "
               "escenarios y una organización ficticia. Las cifras no se generalizan."),
        (t("Step 1 recall", "Exhaustividad del paso 1"), f"Moderate: exact-level means _fail0 between {span}.",
               f"Moderada: medias _fail0 a nivel exacto entre {span}."),
    ]
    lis = "".join(f"<li><strong>{k}.</strong> {t(en, es)}</li>" for k, en, es in items)
    return f'<h3>{t("Limitations", "Limitaciones")}</h3><ul>{lis}</ul>'


AI_DECLARATION = (
    "The code in this repository was written with the assistance of Claude Code (Anthropic), under the direction of "
    "Sebastián Murillo Mora. The design of the model, the technical decisions (see <code>docs/DECISIONS.md</code>), "
    "the evaluation and the interpretation of the results are the author’s.",
    "El código de este repositorio fue escrito con asistencia de Claude Code (Anthropic), bajo la dirección de "
    "Sebastián Murillo Mora. El diseño del modelo, las decisiones técnicas (ver <code>docs/DECISIONS.md</code>), la "
    "evaluación y la interpretación de los resultados son del autor.")


CSS = """
:root{--paper:#ffffff;--ink:#1a1a1a;--muted:#4d4d4d;--line:#c8c8c8;--accent:#0b4f8a;--warn-bg:#fff4d6;--warn:#6b4500;
--s1:#e8e8e8;--s2:#9a9a9a;--s3:#3d3d3d;--a0:#7a1f1f;--a1:#8a5a00;--a2:#1f5f7a;--a3:#4d4d4d}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--paper:#141414;--ink:#ececec;--muted:#b5b5b5;
--line:#4a4a4a;--accent:#8cc4ff;--warn-bg:#3a2c00;--warn:#ffd98a;--s1:#d8d8d8;--s2:#8a8a8a;--s3:#4a4a4a}}
*{box-sizing:border-box}html{font-size:16px}
body{margin:0;background:var(--paper);color:var(--ink);font:1rem/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main,header{max-width:72rem;margin:0 auto;padding:0 16px}
h1{font-size:1.6rem;line-height:1.25;margin:1.2rem 0 .6rem}h2{font-size:1.3rem;margin-top:2.2rem;border-bottom:2px solid var(--line)}
h3{font-size:1.1rem;margin-top:1.6rem}a{color:var(--accent)}code{font-size:.85em;word-break:break-all}
.muted{color:var(--muted)}.note{border-left:4px solid var(--accent);padding:.3rem .8rem;margin:.6rem 0}
.banner{background:var(--warn-bg);color:var(--warn);border:2px solid currentColor;padding:.6rem .8rem;font-weight:600}
.facts{display:grid;grid-template-columns:max-content 1fr;gap:.2rem 1rem;margin:.8rem 0}.facts dt{font-weight:600}.facts dd{margin:0}
.scroll{overflow-x:auto;-webkit-overflow-scrolling:touch;margin:.6rem 0}
table{border-collapse:collapse;width:100%;font-size:.9rem}th,td{border:1px solid var(--line);padding:.3rem .45rem;text-align:left;vertical-align:top}
thead th{background:color-mix(in srgb,var(--line) 35%,var(--paper))}
figure{margin:.8rem 0}figcaption{font-size:.9rem;color:var(--muted)}
.chart{width:100%;max-width:44rem;height:auto;display:block}.chart .grid{stroke:var(--line)}.chart .tick,.chart .val,.chart .grp{fill:var(--ink);font-size:11px}
.chart .bar{stroke:var(--ink);stroke-width:1}.chart .err{stroke:var(--ink);stroke-width:1.5;fill:none}
.legend{list-style:none;padding:0;display:flex;flex-wrap:wrap;gap:.4rem 1rem;font-size:.9rem}.legend li{display:flex;align-items:center;gap:.35rem}
.stack{display:flex;min-width:16rem;border:1px solid var(--ink);font-size:.78rem}
.seg{padding:.15rem .3rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:#fff;border-right:1px solid var(--paper)}
.seg0{background:var(--a0)}.seg1{background:var(--a1)}.seg2{background:var(--a2)}.seg3{background:var(--a3)}
.heat{display:inline-block;min-width:2rem;text-align:center;padding:0 .3rem;border:1px solid var(--ink);
background:color-mix(in srgb,var(--accent) calc(var(--n)*6%),var(--paper))}
.filters{display:flex;flex-wrap:wrap;gap:.6rem 1rem;align-items:end;margin:.6rem 0}
select,button{font:inherit;padding:.25rem .4rem;color:var(--ink);background:var(--paper);border:1px solid var(--ink);border-radius:4px}
button{cursor:pointer}button:focus-visible,select:focus-visible,a:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
.top{display:flex;justify-content:flex-end;max-width:72rem;margin:0 auto;padding:.6rem 16px 0}
html[data-lang=en] [lang=es],html[data-lang=es] [lang=en]{display:none}
q{quotes:"“" "”"}footer{max-width:72rem;margin:2rem auto;padding:0 16px;font-size:.85rem;color:var(--muted)}
@media (max-width:600px){h1{font-size:1.3rem}.facts{grid-template-columns:1fr}.facts dd{margin-bottom:.4rem}}
"""

JS = """
(function(){var h=document.documentElement,b=document.getElementById('lang');
function set(l){h.setAttribute('data-lang',l);h.lang=l;b.textContent=l==='en'?'Español':'English';
b.setAttribute('aria-label',l==='en'?'Ver en español':'View in English');try{localStorage.setItem('aem-lang',l)}catch(e){}}
var saved=null;try{saved=localStorage.getItem('aem-lang')}catch(e){}set(saved==='es'?'es':'en');
b.addEventListener('click',function(){set(h.getAttribute('data-lang')==='en'?'es':'en')});
var sels=[].slice.call(document.querySelectorAll('select[data-filter]')),rows=[].slice.call(document.querySelectorAll('#tech tbody tr')),out=document.getElementById('count');
function apply(){var n=0;rows.forEach(function(r){var ok=sels.every(function(s){if(!s.value)return true;var k=s.getAttribute('data-filter'),v=r.getAttribute('data-'+k)||'';
return (k==='tactics'||k==='actions')?v.split('|').indexOf(s.value)>=0:v===s.value});r.hidden=!ok;if(ok)n++});
if(out)out.textContent=n+' / '+rows.length;}
sels.forEach(function(s){s.addEventListener('change',apply)});apply();})();
"""


def render(d: dict) -> str:
    res = d["results"]
    tables = res["tables"]
    run_id = escape(res.get("run_id", ""))
    body = [
        _header(d), "<main>",
        f'<section id="indicators"><h2>{t("2. The five indicators by scenario and version", "2. Los cinco indicadores por escenario y versión")}</h2>',
        _indicator1(tables), _indicator2(tables), _indicator3(tables), _indicator4(tables, d["manual"]),
        _indicator5(tables, d["manual"]), "</section>",
        _model_vs_traditional(tables), _distributions(d), _technique_table(d),
        f'<section id="limits"><h2>{t("6. Sensitivity, limitations and declaration of AI use", "6. Sensibilidad, limitaciones y declaración de uso de IA")}</h2>',
        _sensitivity(d), _limits(tables),
        f'<h3>{t("Declaration of AI use in development", "Declaración de uso de IA en el desarrollo")}</h3>',
        f"<p>{t(*AI_DECLARATION)}</p></section>", "</main>",
        '<footer>' + t("Generated with <code>aem report --html</code> from the files of the run; no figure was recomputed.",
                     "Generado con <code>aem report --html</code> a partir de los archivos de la corrida; no se recalculó ninguna cifra.") + '</footer>',
    ]
    return ("<!doctype html>\n"
            f'<html lang="en" data-lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            f"<title>Exposure model results {run_id}</title><style>{CSS}</style></head><body>"
            '<div class="top"><button id="lang" type="button">Español</button></div>'
            + "".join(body) + f"<script>{JS}</script></body></html>\n")


# --- checks and output ------------------------------------------------------------------------


def visible_text(html: str) -> str:
    html = re.sub(r"<(script|style)\b.*?</\1>", " ", html, flags=re.S)
    return unescape(re.sub(r"<[^>]+>", " ", html))


def leak_findings(html: str, dfir_text: str | None, iocs: list[str]) -> list[str]:
    """8-word windows of the DFIR report and its IoC values found in the page (same sources as check-repo)."""
    from aem.repo_check import copied_windows

    findings = []
    if dfir_text:
        findings += [f"frase del reporte de DFIR ({len(w.split())} palabras)" for w in
                     copied_windows(visible_text(html), dfir_text, WINDOW_WORDS)]
    low = html.casefold()
    findings += ["valor de IoC del reporte de DFIR" for v in iocs if v.casefold() in low]
    return findings


def build_html(run_dir: Path, out_path: Path, sheets_dir: Path | None, scenarios: dict[str, Scenario],
               private: bool = False, dfir_text: str | None = None, iocs: list[str] = ()) -> Path:
    page = render(collect(run_dir, sheets_dir, scenarios, private))
    if not private:
        found = leak_findings(page, dfir_text, list(iocs))
        if found:  # never print the matched text
            raise LeakError(f"La página pública contendría {len(found)} fragmento(s) del reporte de DFIR "
                            f"({', '.join(sorted(set(found)))}); no se escribió.")
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(page, encoding="utf-8")
    return out_path
