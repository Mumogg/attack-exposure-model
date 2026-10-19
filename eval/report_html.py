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
import math
import re
from collections import Counter, defaultdict
from html import escape, unescape
from pathlib import Path

from aem.scenarios import VERSIONS, Scenario, load_reference
from eval import provenance, review
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
    prov_path = run_dir / "results" / "provenance.json"
    prov = json.loads(prov_path.read_text(encoding="utf-8")) if prov_path.exists() else None
    sens_path = run_dir / "results" / "sensitivity" / "sensitivity.json"
    sensitivity = json.loads(sens_path.read_text(encoding="utf-8")) if sens_path.exists() else None
    return {"results": data, "techniques": techniques, "actions": actions, "coverage": coverage,
            "valid_runs": valid_runs, "reference": reference, "manual": manual, "sensitivity": sensitivity,
            "missing_outputs": missing_outputs, "private": private, "provenance": prov,
            "copyrighted": {sc.name for sc in scenarios.values() if sc.copyrighted}}


# --- localisation of values written in Spanish by the pipeline ------------------------------------

# fixed values that `aem eval` writes in Spanish into the tables (the figures themselves are untouched)
DATA_EN = {"ninguna": "none", "ninguno": "none", "todos": "all", "paso 1 (extracción)": "step 1 (extraction)",
           "paso 4 (resúmenes, uno por técnica)": "step 4 (summaries, one per technique)",
           "ver indicador 4 (llm_failures)": "see indicator 4 (llm_failures)",
           "no aplica (sin LLM)": "not applicable (no LLM)", "determinístico": "deterministic", "actual": "current",
           "sin texto local": "no local text", "sin caché privada": "no private cache", "sin texto": "no text",
           "modelo": "model", "tradicional": "traditional"}


def data(text: str) -> str:
    """Language-neutral data (scenario, ATT&CK names, quotes): shown as is in both views, never translated."""
    return f'<span translate="no">{escape(str(text))}</span>'


def _d(value) -> str:
    """A table value: «sin dato disponible», booleans and the fixed Spanish values in both languages."""
    if isinstance(value, bool):
        return t("yes", "sí") if value else t("no", "no")
    if isinstance(value, str) and value in DATA_EN:
        return t(escape(DATA_EN[value]), escape(value))
    return _v(value)


def _mismatches(text) -> str:
    if not isinstance(text, str) or text in DATA_EN or text == NO_DATA:
        return _d(text)
    en = text.replace("paso 2:", "step 2:").replace("diseño:", "design:")
    for es_name, en_name in COVERAGE_EN.items():
        en = en.replace(es_name, en_name)
    return t(escape(en), escape(text))


def _review_status(m: dict) -> str:
    """«revisión incompleta: N de M filas» and the other review states, in both languages."""
    text = str(m.get("status_text", ""))
    if text.startswith("revisión completa"):
        return t("review complete", "revisión completa")
    found = re.match(r"revisión incompleta: (\d+) de (\d+) filas", text)
    if found:
        return t(f"review incomplete: {found[1]} of {found[2]} rows", escape(text))
    found = re.search(r"(\d+) de (\d+) filas válidas", text)
    if text.startswith("revisión con errores") and found:
        return t(f"review with errors: {found[1]} of {found[2]} valid rows (see <code>aem review-check</code>)",
                 escape(text).replace("`aem review-check`", "<code>aem review-check</code>"))
    if text.startswith(NO_DATA):
        return t("no data available (no review sheet)", escape(text))
    return t(escape(text), escape(text))


# --- SVG charts -------------------------------------------------------------------------------

_PATTERNS = """<defs>
<pattern id="p-orig" width="6" height="6" patternUnits="userSpaceOnUse"><rect width="6" height="6" fill="var(--s1)"/></pattern>
<pattern id="p-mut" width="6" height="6" patternUnits="userSpaceOnUse" patternTransform="rotate(45)"><rect width="6" height="6" fill="var(--s2)"/><line x1="0" y1="0" x2="0" y2="6" stroke="var(--ink)" stroke-width="2"/></pattern>
<pattern id="p-anon" width="6" height="6" patternUnits="userSpaceOnUse"><rect width="6" height="6" fill="var(--s3)"/><circle cx="3" cy="3" r="1.3" fill="var(--paper)"/></pattern>
</defs>"""
BAR, GAP, LEFT, TOP, HEIGHT = 30, 24, 40, 30, 200
VALUE_FONT = 9  # px; with BAR = 30, a label of up to 5 characters (e.g. «100.0») fits within its own bar


def _label(m: float, unit: str) -> str:
    return f"{m:g}" if unit == "" else f"{m:.1f}"


def svg_bars(groups: list[str], series: dict[str, list[tuple]], label_en: str, label_es: str, unit: str = "%",
             ticks: tuple = (0, 25, 50, 75, 100)) -> str:
    """Grouped bars (one per version) with ± SD error bars, patterns (never colour alone) and a small value label
    above each bar, the middle one raised one line so that neighbours never touch. Each bar is focusable and
    has an aria-label with its exact value; the exact numbers are also in the table under the chart.
    `series[version]` holds (mean, sd) per group; a missing mean is drawn as «–»."""
    if not groups:
        return ""
    ymax = float(ticks[-1])
    width = LEFT + len(groups) * (3 * BAR + GAP) + 10
    base = TOP + HEIGHT
    out = [f'<svg class="chart" viewBox="0 0 {width} {base + 30}" role="group" aria-label="{escape(label_en)}" '
           f'data-aria-en="{escape(label_en)}" data-aria-es="{escape(label_es)}">', _PATTERNS]
    for tick in ticks:
        y = base - HEIGHT * tick / ymax
        out.append(f'<line x1="{LEFT}" x2="{width - 6}" y1="{y:.1f}" y2="{y:.1f}" class="grid"/>'
                   f'<text x="{LEFT - 6}" y="{y + 4:.1f}" class="tick" text-anchor="end">{tick:g}</text>')
    for g_i, group in enumerate(groups):
        x0 = LEFT + 8 + g_i * (3 * BAR + GAP)
        for v_i, v in enumerate(VERSIONS):
            mean, sd = series[v][g_i]
            x, cx = x0 + v_i * BAR, x0 + v_i * BAR + BAR / 2
            m, s = _num(mean), _num(sd)
            name = f"{group} · {v}: " + ("–" if m is None else f"{m:g}{(' ' + unit) if unit else ''}"
                                         + ("" if s is None else f" ± {s:g}"))
            out.append(f'<g class="bar-g" tabindex="0" role="img" aria-label="{escape(name)}"><title>{escape(name)}</title>')
            if m is None:
                out.append(f'<text x="{cx}" y="{base - 4}" class="val" text-anchor="middle">–</text></g>')
                continue
            h = HEIGHT * min(m, ymax) / ymax
            out.append(f'<rect x="{x + 3}" y="{base - h:.1f}" width="{BAR - 6}" height="{h:.1f}" fill="url(#p-{v})" '
                       'class="bar"/>')
            top = base - h
            if s is not None and s > 0:
                y1, y2 = base - HEIGHT * min(max(m - s, 0), ymax) / ymax, base - HEIGHT * min(m + s, ymax) / ymax
                out.append(f'<path d="M{cx} {y1:.1f}V{y2:.1f}M{cx - 5} {y1:.1f}h10M{cx - 5} {y2:.1f}h10" class="err"/>')
                top = min(top, y2)
            y = max(top - 4 - (VALUE_FONT + 2) * (v_i == 1), VALUE_FONT + 1)
            out.append(f'<text x="{cx}" y="{y:.1f}" class="val" text-anchor="middle">{_label(m, unit)}</text></g>')
        out.append(f'<text x="{x0 + 1.5 * BAR}" y="{base + 18}" class="grp" text-anchor="middle">{escape(group)}</text>')
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
        parts.append(f'<span class="seg seg{i}" style="flex:{n}" title="{escape(label[0])}: {n}">'
                     f'{t(escape(label[0]), escape(label[1]))} {n}</span>')
    aria = ", ".join(f"{(names[k][0] if names else k)}: {counts.get(k, 0)}" for k in order)
    return f'<div class="stack" role="img" aria-label="{escape(aria)}">' + "".join(parts) + "</div>"


# --- tables -----------------------------------------------------------------------------------


def table(headers: list[str], rows: list[list[str]], cls: str = "") -> str:
    head = "".join(f'<th scope="col">{h}</th>' for h in headers)
    body = "\n".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return (f'<div class="scroll"><table class="{cls}"><thead><tr>{head}</tr></thead>\n<tbody>\n{body}\n'
            "</tbody></table></div>\n")


def _scenarios(rows: list[dict]) -> list[str]:
    return list(dict.fromkeys(r["scenario"] for r in rows))


def _mean_sd(row: dict, prefix: str, view: str = "fail0") -> str:
    m, s = row.get(f"{prefix}_mean_{view}", NO_DATA), row.get(f"{prefix}_sd_{view}", NO_DATA)
    return _v(m) + ("" if s == NO_DATA else f" ± {escape(str(s))}")


def section(sid: str, title_en: str, title_es: str, body: str, open_: bool = False) -> str:
    """A numbered section that folds (<details>); the table of contents links to its id."""
    return (f'<section id="{sid}" aria-labelledby="{sid}-h"><details{" open" if open_ else ""}>'
            f'<summary><h2 id="{sid}-h">{t(title_en, title_es)}</h2></summary>\n{body}\n</details></section>\n')


SECTIONS = (("run", "1. Run data and provenance", "1. Datos de la corrida y procedencia"),
            ("indicators", "2. The five indicators by scenario and version",
             "2. Los cinco indicadores por escenario y versión"),
            ("comparison", "3. Model vs traditional approach (indicator 3)",
             "3. Modelo frente al enfoque tradicional (indicador 3)"),
            ("distribution", "4. Actions, coverage and tactics", "4. Acciones, cobertura y tácticas"),
            ("techniques", "5. Techniques extracted", "5. Técnicas extraídas"),
            ("limits", "6. Sensitivity, limitations and declaration of AI use",
             "6. Sensibilidad, limitaciones y declaración de uso de IA"))


def toc() -> str:
    # one link per line in the source, so the text of two links never runs together
    items = "\n".join(f'<li><a href="#{sid}">{t(en, es)}</a></li>' for sid, en, es in SECTIONS)
    return f'<nav class="toc" aria-label="Contents / Contenido"><ol>\n{items}\n</ol></nav>\n'


# --- sections ---------------------------------------------------------------------------------


def _provenance(d: dict) -> str:
    title = f'<h3 class="prov">{t("Provenance", "Procedencia")}</h3>'
    if not d.get("provenance"):
        return (title + "<p>" + t("no data available", "sin dato disponible")
                + ' (<code translate="no">results/provenance.json</code>)</p>')
    from aem.config import REPO_ROOT

    s = provenance.summary(d["provenance"], REPO_ROOT)
    not_rec = t("not recorded", "no registrado")
    if s["reconstructed"]:
        kind = t("reconstructed (<code>aem provenance</code>)", "reconstruida (<code>aem provenance</code>)")
        commits = escape(", ".join(s["reconstructed_commits"]))
        code = (t("not recorded; reconstructed from git", "no registrado; reconstruido de git")
                + (f": <code>{commits}</code>" if commits else ""))
    else:
        kind = t("recorded by <code>aem eval</code>", "registrada por <code>aem eval</code>")
        code = f'<code>{escape((s["commit"] or "")[:12])}</code>' if s["commit"] else not_rec
        if s["dirty"]:
            code += " " + t("with uncommitted changes in", "con cambios sin commit en") + ": " + ", ".join(f"<code>{escape(f)}</code>" for f in s["dirty"])
    matches = {True: t("yes", "sí"), False: t("no", "no"), None: not_rec}[s["attack_matches"]]
    attack = (f'{escape(str(s["attack_version"]))} · SHA-256 <code>{escape(s["attack_sha"])}…</code> '
              f'({t("matches the expected checksum", "coincide con el esperado")}: {matches})')
    deps = escape(", ".join(f"{k} {v}" for k, v in s["dependencies"].items())) if s["dependencies"] else not_rec
    if not s["frozen_total"]:
        frozen = not_rec
    else:
        frozen = t(f'{s["frozen_total"]} files with SHA-256', f'{s["frozen_total"]} archivos con SHA-256')
        if not s["frozen_changes"]:
            frozen += "; " + t("none changed after the run", "ninguno cambió después de la corrida")
        else:
            frozen += "; " + t("changed after the run", "cambiaron después de la corrida") + ": " + ", ".join(
                f'<code>{escape(path)}</code> (' + t(provenance.FROZEN_STATUS_EN[st], provenance.FROZEN_STATUS_ES[st])
                + ")" for path, st in s["frozen_changes"])
    rows = [(t("Record", "Registro"), kind), (t("Code", "Código"), code), ("ATT&amp;CK", attack),
            ("Python", escape(s["python"]) if s["python"] else not_rec), (t("Dependencies", "Dependencias"), deps),
            (t("Frozen files", "Archivos congelados"), frozen)]
    dl = "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in rows)
    return (title + f'<dl class="facts">{dl}</dl><p class="muted">'
            + t("Read from <code>results/provenance.json</code>.", "Leída de <code>results/provenance.json</code>.")
            + "</p>")


def _header(d: dict) -> str:
    res = d["results"]
    banner = ""
    if res.get("partial"):
        omitted = ", ".join(f'{data(o["scenario"])} ({_d(o["reason"])})' for o in res.get("escenarios_omitidos") or [])
        banner = (f'<p class="banner" role="alert"><strong>{t("PARTIAL RESULT", PARTIAL_LINE.split(":")[0])}</strong>'
                  f' — {t("omitted scenarios", "escenarios omitidos")}: {omitted or "-"}</p>')
    private = ('<p class="banner">' + t("PRIVATE version: includes evidence quotes of the copyrighted report. "
                                         "Do not publish.", "Versión PRIVADA: incluye citas del reporte con "
                                         "derechos de autor. No publicar.") + '</p>') if d["private"] else ""
    return ('<header id="top"><h1>' + t("AI-assisted exposure model based on MITRE ATT&amp;CK — results",
                                       "Modelo de exposición asistido por IA basado en MITRE ATT&amp;CK — resultados")
            + f"</h1>{banner}{private}</header>\n")


def _run_section(d: dict) -> str:
    res = d["results"]
    first = next((r for rows in res["tables"].values() for r in rows), {})
    run_date = first.get("run_date", str(res.get("started", ""))[:10])
    versions = res.get("model_versions") or []
    model = res.get("model", "")
    # the configured name once when the API reported the same one
    model_text = model if versions in ([], [model]) else f'{model} ({"; ".join(versions)})'
    facts = [(t("Run", "Corrida"), data(res.get("run_id", ""))),
             (t("Model", "Modelo"), data(model_text)),
             (t("Run date", "Fecha de la corrida"), escape(run_date)),
             ("ATT&amp;CK", escape(str(res.get("attack_version", "")))),
             (t("Runs per scenario × version", "Corridas por escenario × versión"), escape(str(res.get("replicates", "")))),
             (t("Answers", "Respuestas"), data(first.get("llm_source", ""))),
             (t("Prompt templates (SHA-256)", "Plantillas de prompt (SHA-256)"),
              f'<code translate="no">{escape(res.get("prompt_templates_sha256", ""))}</code>')]
    dl = "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in facts)
    note = ('<p class="muted">' + t("Means are sample means over the runs; error bars are ± sample SD (n−1). "
                                    "<code>_fail0</code> counts a failed run as 0 (primary mean for indicators 1 and 3); "
                                    "<code>_valid</code> uses only valid runs (D-67).",
                                    "Medias muestrales sobre las corridas; las barras de error son ± DE muestral (n−1). "
                                    "<code>_fail0</code> cuenta una corrida fallida como 0 (media principal de los "
                                    "indicadores 1 y 3); <code>_valid</code> usa solo las corridas válidas (D-67).")
            + "</p>")
    return f'<dl class="facts">{dl}</dl>{note}\n{_provenance(d)}'


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
                   + svg_bars(groups, series, f"Indicator 1: {en} (%)", f"Indicador 1: {es} (%)") + "</figure>")
    out.append(legend())
    body = [[data(r["scenario"]), escape(r["version"]),
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
    body = [[data(r["scenario"]), _v(r.get("reference_techniques")), _v(r.get("matches")), _v(r.get("accuracy")),
             _mismatches(r.get("mismatches"))] for r in rows]
    return (f'<h3>{t("Indicator 2 — Correctness of the coverage lookup (step 2)", "Indicador 2 — Corrección del cruce de cobertura (paso 2)")}</h3>'
            f'<p class="muted">{t("Deterministic (no LLM): no SD.", "Determinístico (sin LLM): sin DE.")}</p>'
            + table([t("Scenario", "Escenario"), t("Reference techniques", "Técnicas de referencia"),
                     t("Matches", "Coincidencias"), t("Accuracy (%)", "Exactitud (%)"),
                     t("Mismatches", "Discrepancias")], body))


def _indicator3(tables: dict) -> str:
    rows = [r for r in tables.get("indicator3", []) if r.get("approach") == "modelo"]
    groups = _scenarios(rows)
    series = {v: [(r.get(f"{v}_mean_fail0"), r.get(f"{v}_sd_fail0")) for r in rows] for v in VERSIONS}
    body = [[data(r["scenario"]), _v(r.get("denominator_techniques")),
             *[_mean_sd(r, v) for v in VERSIONS], *[_mean_sd(r, v, "valid") for v in VERSIONS]] for r in rows]
    return (f'<h3>{t("Indicator 3 — Persistence of the model (%)", "Indicador 3 — Persistencia del modelo (%)")}</h3>'
            '<p class="muted">' + t("Share of the scenario’s reference techniques with a coverage gap that the model "
                                   "extracts (exact ID).", "Proporción de las técnicas de referencia con brecha de "
                                   "cobertura que el modelo extrae (ID exacto).") + '</p>'
            + "<figure>" + svg_bars(groups, series, "Indicator 3: model persistence (%)",
                                    "Indicador 3: persistencia del modelo (%)") + f"</figure>{legend()}"
            + table([t("Scenario", "Escenario"), t("Gaps (denominator)", "Brechas (denominador)"),
                     *[f"{v} _fail0" for v in VERSIONS], *[f"{v} _valid" for v in VERSIONS]], body))


def _indicator4(tables: dict, manual: dict | None) -> str:
    r = (tables.get("indicator4") or [{}])[0]
    auto = (f'{_v(r.get("auto_check_ok"))} / {_v(r.get("techniques_summarized"))} '
            f'({_v(r.get("auto_check_ok_pct"))} %)')
    if manual is None or manual["indicator4"]["status"] != "completa":
        man = t("no data available", "sin dato disponible")
        if manual is not None:
            man += f' <span class="muted">({_review_status(manual["indicator4"])})</span>'
    else:
        m = manual["indicator4"]
        man = f'{m["ok"]} / {m["total"]} ({m["ok_pct"]} %)'
    return (f'<h3>{t("Indicator 4 — Fidelity of the step 4 summaries", "Indicador 4 — Fidelidad de los resúmenes del paso 4")}</h3>'
            + table([t("Measure", "Medida"), t("Value", "Valor")],
                    [[t("Automatic check ok", "Chequeo automático ok"), auto],
                     [t("LLM failures", "Fallos del LLM"), _v(r.get("llm_failures"))],
                     [t("Manual review: faithful summaries", "Revisión manual: resúmenes fieles"), man]]))


def violation_ticks(values: list[float | None]) -> tuple[int, ...]:
    """Integer axis: 0–1 when every value is 0, otherwise up to the next integer above the largest mean + SD."""
    top = max([v for v in values if v is not None] + [0])
    if top == 0:
        return (0, 1)
    ymax = math.ceil(top)
    step = max(1, math.ceil(ymax / 4))
    return tuple(range(0, ymax + step, step)) if ymax % step == 0 else tuple(range(0, ymax + 2 * step, step))[:6]


def _indicator5(tables: dict, manual: dict | None) -> str:
    rows = tables.get("indicator5", [])
    step1 = [r for r in rows if r.get("version") in VERSIONS]
    groups = _scenarios(step1)
    find = {(r["scenario"], r["version"]): r for r in step1}
    charts = []
    all_values = []
    for view in ("fail0", "valid"):
        for r in step1:
            m, s = _num(r.get(f"violations_mean_{view}")), _num(r.get(f"violations_sd_{view}"))
            all_values.append(None if m is None else m + (s or 0))
    ticks = violation_ticks(all_values)
    runs = sum(_num(r.get("runs_total")) or 0 for r in step1)
    note = ""
    if all_values and all(v == 0 for v in all_values):
        note = ('<p class="note">' + t(f"0 violations in all {runs:g} runs.", f"0 violaciones en todas las {runs:g} corridas.")
                + "</p>")
    for view in ("fail0", "valid"):
        series = {v: [(find.get((g, v), {}).get(f"violations_mean_{view}"),
                       find.get((g, v), {}).get(f"violations_sd_{view}")) for g in groups] for v in VERSIONS}
        charts.append('<figure><figcaption>' + t(f"Violations per run, mean _{view} ± SD",
                                                 f"Violaciones por corrida, media _{view} ± DE") + "</figcaption>"
                      + svg_bars(groups, series, f"Indicator 5: violations per run, {view}",
                                 f"Indicador 5: violaciones por corrida, {view}", unit="", ticks=ticks) + "</figure>")
    body = [[_d(r["scenario"]) if r["scenario"] in DATA_EN else data(r["scenario"]), escape(r["version"]),
             _d(str(r.get("output", ""))), _mean_sd(r, "violations"), _mean_sd(r, "violations", "valid"),
             _v(r.get("violations_total")), _v(r.get("extra_fields")), _v(r.get("evaluative_text"))] for r in rows]
    if manual is None:
        man = [[t("all", "todos"), t("no data available", "sin dato disponible")]]
    else:
        m = manual["indicator5"]
        complete = m["status"] == "completa"
        man = [[t("step 4 summaries", "resúmenes del paso 4") if sc == "-" else data(sc),
                (f'{c["with_valuation"]} / {c["total"]}' if complete else t("no data available", "sin dato disponible"))]
               for sc, c in m["by_scenario"].items()]
        man.append([t("total", "total"), (f'{m["with_valuation"]} / {m["total"]} ({m["with_valuation_pct"]} %)'
                                         if complete else t("no data available", "sin dato disponible")
                                         + f' <span class="muted">({_review_status(m)})</span>')])
    return (f'<h3>{t("Indicator 5 — Compliance with the boundaries", "Indicador 5 — Cumplimiento de los límites")}</h3>'
            '<p class="muted">' + t("Both means carry the same weight (D-67): counting a failed run as 0 violations "
                                   "favours the model.", "Ambas medias tienen el mismo peso (D-67): contar una corrida "
                                   "fallida como 0 violaciones favorece al modelo.") + '</p>'
            + note + "".join(charts) + legend()
            + f'<h4>{t("Automatic count", "Conteo automático")}</h4>'
            + table([t("Scenario", "Escenario"), t("Version", "Versión"), t("Output", "Salida"), "_fail0", "_valid",
                     t("Total", "Total"), t("Extra fields", "Campos extra"), t("Evaluative text", "Texto valorativo")], body)
            + f'<h4>{t("Manual review of the sample (separate figure)", "Revisión manual de la muestra (cifra separada)")}</h4>'
            + table([t("Scenario", "Escenario"), t("Texts with valuation / reviewed", "Textos con valoración / revisados")], man))


def _model_vs_traditional(tables: dict) -> str:
    rows = tables.get("indicator3", [])
    body = []
    for r in rows:
        body.append([data(r["scenario"]), _d(r.get("approach")), _v(r.get("denominator_techniques")),
                     *[_d(r.get(f"{v}_mean_fail0")) for v in VERSIONS],
                     _d(r.get("persistence_mut_over_orig_fail0")), _d(r.get("persistence_anon_over_orig_fail0")),
                     _d(r.get("ioc_matches")) if r.get("ioc_matches") else ""])
    return (table([t("Scenario", "Escenario"), t("Approach", "Enfoque"), t("Denominator", "Denominador"),
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
                "deliberadamente favorable al enfoque tradicional en orig (100 %).") + '</p>')


def _distributions(d: dict) -> str:
    out = ['<p class="muted">' + t("Counts over all valid runs (one row per extracted technique and run).",
                                  "Conteos sobre todas las corridas válidas (una fila por técnica extraída y corrida).") + '</p>']
    rows = []
    for (sc, v), counts in d["actions"].items():
        rows.append([data(sc), escape(v), stacked(counts, ACTIONS),
                     stacked(d["coverage"][(sc, v)], COVERAGE_LEVELS,
                             {k: (COVERAGE_EN[k], k) for k in COVERAGE_LEVELS})])
    out.append(table([t("Scenario", "Escenario"), t("Version", "Versión"), t("Step 3 actions", "Acciones del paso 3"),
                      t("Coverage (step 2)", "Cobertura (paso 2)")], rows, "dist"))
    if d["missing_outputs"]:
        out.append('<p class="muted">' + t("No per-run outputs on this machine for", "Sin salidas por corrida en esta máquina para")
                   + f': {data(", ".join(d["missing_outputs"]))}.</p>')
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
        cells = [data(tac)]
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
    out.append(table([t("Tactic", "Táctica"), *[data(s) for s in scen]], map_rows, "map"))
    return "".join(out)


TECHNIQUE_ROWS_SHOWN = 25


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
            quote = f'<q translate="no">{escape(i["quote"])}</q> <small class="muted">({escape(i["quote_run"])})</small>'
        else:
            quote = t("no data available", "sin dato disponible")
        ref = t("yes", "sí") if i["in_reference"] else t("no", "no")
        rows.append(
            f'<tr data-scenario="{escape(i["scenario"])}" data-version="{escape(i["version"])}" '
            f'data-tactics="{escape("|".join(i["tactics"]))}" data-actions="{escape("|".join(i["actions"]))}">'
            f'<td>{data(i["scenario"])}</td><td>{escape(i["version"])}</td>'
            f'<td><a href="{escape(i["link"])}" rel="noopener" target="_blank">{escape(i["technique_id"])}</a></td>'
            f'<td>{data(i["name"])}</td><td>{data("; ".join(i["tactics"]))}</td><td>{escape(actions)}</td>'
            f'<td>{t(escape(cov), escape(cov_es))}</td><td>{ref}</td><td>{i["runs"]}/{total}</td><td>{quote}</td></tr>')

    def select(name: str, en: str, es: str, values: list[str]) -> str:
        opts = "".join(f'<option value="{escape(v)}" translate="no">{escape(v)}</option>' for v in values)
        return (f'<label>{t(en, es)} <select data-filter="{name}"><option value="">*</option>{opts}</select></label>')

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
    more = (f'<p class="more"><button id="more" type="button" aria-controls="tech" aria-expanded="false" '
            f'data-limit="{TECHNIQUE_ROWS_SHOWN}">{t("Show more", "Mostrar más")}</button></p>'
            if len(rows) > TECHNIQUE_ROWS_SHOWN else "")
    return (f'{note}<div class="filters">{select("scenario", "Scenario", "Escenario", scen)}'
            f'{select("version", "Version", "Versión", list(VERSIONS))}{select("tactics", "Tactic", "Táctica", tactics)}'
            f'{select("actions", "Action", "Acción", list(ACTIONS))}'
            f'<output id="count" aria-live="polite">{t(f"{len(rows)} rows", f"{len(rows)} filas")}</output></div>\n'
            f'<div class="scroll"><table id="tech"><thead><tr>{head}</tr></thead>\n<tbody>\n' + "\n".join(rows)
            + f"\n</tbody></table></div>{more}")


def _sensitivity(d: dict) -> str:
    s = d["sensitivity"]
    title = f'<h3>{t("Sensitivity analysis (D-77)", "Análisis de sensibilidad (D-77)")}</h3>'
    if not s:
        return title + f'<p>{t("no data available", "sin dato disponible")} (<code>aem sensitivity</code>)</p>'
    body = [[_d(r["parameter"]) if r["parameter"] in DATA_EN else data(r["parameter"]), data(str(r["value"])),
             data(r["scenario"]), _v(r["gaps"]),
             *[_v(r.get(f"{v}_mean_fail0")) for v in VERSIONS], _v(r.get("persistence_mut_over_orig_fail0")),
             _v(r.get("persistence_anon_over_orig_fail0"))] for r in s["rows"]]
    return (title + '<p class="note">' + t("Sensitivity analysis. It does not replace the main results; the confirmed "
                                         "configuration (D-20, D-21) did not change.", escape(s["note"])) + '</p>'
            + table([t("Parameter", "Parámetro"), t("Value", "Valor"), t("Scenario", "Escenario"), t("Gaps", "Brechas"),
                     "orig _fail0", "mut _fail0", "anon _fail0", "mut/orig", "anon/orig"], body))


def _limits(tables: dict) -> str:
    recalls = [_num(r.get("recall_mean_fail0")) for r in tables.get("indicator1", []) if r.get("level") == "exact"]
    recalls = [r for r in recalls if r is not None]
    span_en = f"between {min(recalls):g} and {max(recalls):g} %" if recalls else "no data available"
    span_es = f"entre {min(recalls):g} y {max(recalls):g} %" if recalls else NO_DATA
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
        (t("Step 1 recall", "Exhaustividad del paso 1"), f"Moderate: exact-level means _fail0 {span_en}.",
               f"Moderada: medias _fail0 a nivel exacto {span_es}."),
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
*{box-sizing:border-box}html{font-size:16px;scroll-behavior:smooth}
body{margin:0;background:var(--paper);color:var(--ink);font:1rem/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main,header{max-width:72rem;margin:0 auto;padding:0 16px}
h1{font-size:1.6rem;line-height:1.25;margin:1.2rem 0 .6rem}h2{font-size:1.3rem;margin:0;display:inline}
section{margin-top:1.2rem;border-bottom:2px solid var(--line);padding-bottom:.6rem;scroll-margin-top:.5rem}
summary{cursor:pointer;padding:.3rem 0}summary:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
h3{font-size:1.1rem;margin-top:1.4rem}a{color:var(--accent)}code{font-size:.85em;word-break:break-all}
.toc ol{list-style:none;display:flex;flex-wrap:wrap;gap:.5rem 1.6rem;padding:0;margin:.6rem 0 0}.toc a{display:inline-block;padding:.15rem 0}
.muted{color:var(--muted)}.note{border-left:4px solid var(--accent);padding:.3rem .8rem;margin:.6rem 0}
.banner{background:var(--warn-bg);color:var(--warn);border:2px solid currentColor;padding:.6rem .8rem;font-weight:600}
.facts{display:grid;grid-template-columns:max-content 1fr;gap:.2rem 1rem;margin:.8rem 0}.facts dt{font-weight:600}.facts dd{margin:0}
.scroll{overflow-x:auto;-webkit-overflow-scrolling:touch;margin:.6rem 0}
table{border-collapse:collapse;width:100%;font-size:.9rem}th,td{border:1px solid var(--line);padding:.3rem .45rem;text-align:left;vertical-align:top}
thead th{background:color-mix(in srgb,var(--line) 35%,var(--paper))}
figure{margin:.8rem 0}figcaption{font-size:.9rem;color:var(--muted)}
.chart{width:100%;max-width:44rem;height:auto;display:block}.chart .grid{stroke:var(--line)}
.chart .tick,.chart .grp{fill:var(--ink);font-size:11px}.chart .val{fill:var(--ink);font-size:9px}
.chart .bar{stroke:var(--ink);stroke-width:1}.chart .err{stroke:var(--ink);stroke-width:1.5;fill:none}
.chart .bar-g:focus{outline:none}.chart .bar-g:focus .bar,.chart .bar-g:hover .bar{stroke:var(--accent);stroke-width:3}
.chart .bar-g:focus .val,.chart .bar-g:hover .val{font-weight:700}
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
@media (max-width:600px){h1{font-size:1.3rem}.toc ol{flex-direction:column;gap:.35rem}.facts{grid-template-columns:1fr}.facts dd{margin-bottom:.4rem}}
"""

JS = """
(function(){var h=document.documentElement,b=document.getElementById('lang');
function tr(en,es){return '<span lang="en">'+en+'</span><span lang="es">'+es+'</span>';}
function set(l){h.setAttribute('data-lang',l);h.lang=l;
b.setAttribute('aria-label',l==='en'?'Ver en español':'View in English');
[].forEach.call(document.querySelectorAll('[data-aria-en]'),function(e){e.setAttribute('aria-label',e.getAttribute('data-aria-'+l))});
try{localStorage.setItem('aem-lang',l)}catch(e){}}
var saved=null;try{saved=localStorage.getItem('aem-lang')}catch(e){}set(saved==='es'?'es':'en');
b.addEventListener('click',function(){set(h.getAttribute('data-lang')==='en'?'es':'en')});
function openTarget(id){var s=id&&document.getElementById(id);if(!s)return;var d=s.querySelector('details');if(d)d.open=true;}
[].forEach.call(document.querySelectorAll('.toc a'),function(a){a.addEventListener('click',function(){openTarget(a.getAttribute('href').slice(1))})});
window.addEventListener('hashchange',function(){openTarget(location.hash.slice(1))});openTarget(location.hash.slice(1));
var sels=[].slice.call(document.querySelectorAll('select[data-filter]')),rows=[].slice.call(document.querySelectorAll('#tech tbody tr')),
out=document.getElementById('count'),more=document.getElementById('more'),limit=more?+more.getAttribute('data-limit'):Infinity,all=false;
function apply(){var n=0,shown=0;rows.forEach(function(r){var ok=sels.every(function(s){if(!s.value)return true;var k=s.getAttribute('data-filter'),v=r.getAttribute('data-'+k)||'';
return (k==='tactics'||k==='actions')?v.split('|').indexOf(s.value)>=0:v===s.value});
var vis=ok&&(all||n<limit);if(ok)n++;if(vis)shown++;r.hidden=!vis});
if(out)out.innerHTML=tr('Showing '+shown+' of '+n+' matching rows ('+rows.length+' in total)','Se muestran '+shown+' de '+n+' filas que cumplen el filtro ('+rows.length+' en total)');
if(more){more.hidden=n<=limit;more.setAttribute('aria-expanded',all?'true':'false');
more.innerHTML=all?tr('Show fewer','Mostrar menos'):tr('Show more','Mostrar más');}}
if(more)more.addEventListener('click',function(){all=!all;apply();});
sels.forEach(function(s){s.addEventListener('change',apply)});apply();})();
"""


def render(d: dict) -> str:
    res = d["results"]
    tables = res["tables"]
    run_id = escape(res.get("run_id", ""))
    indicators = "".join((_indicator1(tables), _indicator2(tables), _indicator3(tables), _indicator4(tables, d["manual"]),
                          _indicator5(tables, d["manual"])))
    limits = (_sensitivity(d) + _limits(tables)
              + f'<h3>{t("Declaration of AI use in development", "Declaración de uso de IA en el desarrollo")}</h3>'
              + f"<p>{t(*AI_DECLARATION)}</p>")
    bodies = {"run": _run_section(d), "indicators": indicators, "comparison": _model_vs_traditional(tables),
              "distribution": _distributions(d), "techniques": _technique_table(d), "limits": limits}
    body = [_header(d), "<main>", toc()]
    body += [section(sid, en, es, bodies[sid], open_=sid == "indicators") for sid, en, es in SECTIONS]
    body += ["</main>",
             '<footer>' + t("Generated with <code>aem report --html</code> from the files of the run; no figure was recomputed.",
                            "Generado con <code>aem report --html</code> a partir de los archivos de la corrida; no se recalculó ninguna cifra.")
             + '</footer>']
    return ("<!doctype html>\n"
            f'<html lang="en" data-lang="en"><head><meta charset="utf-8">\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
            f"<title>Exposure model results / Resultados del modelo de exposición — {run_id}</title>\n"
            f"<style>{CSS}</style></head>\n<body>\n"
            '<div class="top"><button id="lang" type="button">' + t("Español", "English") + "</button></div>\n"
            + "\n".join(body) + f"\n<script>{JS}</script>\n</body></html>\n")


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
