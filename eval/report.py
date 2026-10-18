"""`aem report`: summary of a real run (`runs/<id>/results/`) for the thesis, in `docs/resultados/<id>/`.

Reads only `results/results.json`, never `results_FAKE/`, and refuses a run whose answers did not all come
from the real Gemini API (D-71). Every number is copied as written in the file (no rounding); missing values
are listed, not hidden. The charts use the primary mean (`_fail0`, D-67) with its sample SD as error bar.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from aem.scenarios import format_omitted
from eval import review
from eval.run_experiments import (
    NO_DATA, PARTIAL_LINE, manual_indicator4_columns, manual_indicator5_rows, manual_negative_rows_md, md_table,
)

VERSIONS = ("orig", "mut", "anon")
# grey levels and hatches: the series never depend on colour alone
SERIES_STYLE = {
    "orig": {"color": "#f2f2f2", "hatch": "", "label": "orig (original)"},
    "mut": {"color": "#a6a6a6", "hatch": "///", "label": "mut (IoC cambiados)"},
    "anon": {"color": "#595959", "hatch": "...", "label": "anon (IoC y nombres cambiados)"},
}
LEVELS = {"exact": "exacto (sub-técnica)", "parent": "padre"}
_COLUMN_ABSENT = "columna ausente en el archivo"

LIMITS = """## Lo que estos números permiten y no permiten afirmar

- **C1 — El enfoque tradicional da 0 % por construcción:** en `mut` y `anon` ningún IoC del original sobrevive (lo verifica el código), así que el enfoque tradicional siempre da 0 %. Es un punto de referencia, **no una medición independiente**.
- **C2 — Reconocimiento por el nombre:** `mut` conserva los nombres del actor y del malware, así que parte de la persistencia del modelo en `mut` podría deberse a que el LLM reconoce la amenaza por su nombre y no por el comportamiento. La versión `anon`, que reemplaza esos nombres, sirve para controlarlo (D-72).
- **C3 — Datos de entrenamiento:** el modelo de lenguaje pudo conocer estos reportes (públicos) durante su entrenamiento; ni `mut` ni `anon` eliminan ese efecto.
- **D-67 — Corridas fallidas:** cada media se informa dos veces. `_fail0` cuenta cada corrida fallida como 0; `_valid` usa solo las corridas válidas. En los indicadores 1 y 3 la media principal es `_fail0`. Si no hay corridas fallidas, ambas coinciden; si las hay, `_fail0` mezcla la calidad de las respuestas con la tasa de fallos y `_valid` la deja fuera, así que ninguna de las dos por sí sola describe ambas cosas.
- **D-67 — Indicador 5:** las dos medias tienen el mismo peso. Contar una corrida fallida como 0 violaciones favorece al modelo.
- **D-67 — Corridas vacías:** una corrida válida sin técnicas propuestas tiene precisión indefinida y no entra en las medias de precisión.
- La razón `mut/orig` o `anon/orig` no muestra los niveles absolutos: las medias absolutas están en la tabla del indicador 3.
- La desviación estándar es muestral (n−1) sobre las corridas de cada escenario × versión; con menos de 2 valores figura «sin dato disponible».
- Los números describen estos escenarios, este modelo (versión y fecha indicadas arriba) y estas plantillas de prompt. No describen otros reportes, otros modelos ni otras versiones del mismo modelo.
- No hay indicador para el paso 3 ni para la revisión global (criterio del analista). Los indicadores 4 y 5 tienen además una revisión manual (hojas de `eval/review_sheets/`); mientras una hoja no esté completa y sin errores, no se informa ningún porcentaje.
"""


class ReportError(Exception):
    pass


def load_results(run_dir: Path) -> dict:
    run_dir = Path(run_dir)
    path = run_dir / "results" / "results.json"
    if not path.exists():
        if (run_dir / "results_FAKE").exists():
            raise ReportError(f"La corrida {run_dir.name} solo tiene resultados FAKE (results_FAKE/): no provienen "
                              "de la API real de Gemini y no se resumen para la tesis.")
        raise ReportError(f"No hay resultados de la corrida {run_dir.name} en results/results.json. "
                          "Ejecute antes `aem eval --run-id " + run_dir.name + "`.")
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("fake", True):
        raise ReportError(f"{path.name} de la corrida {run_dir.name} está marcado como FAKE: no se resume.")
    return data


def _v(row: dict, col: str) -> str:
    if col not in row:
        return _COLUMN_ABSENT
    return str(row[col]).replace("|", "\\|")


def _table(rows: list[dict], columns: list[tuple[str, str]]) -> str:
    if not rows:
        return "_sin filas en el archivo_\n"
    out = ["| " + " | ".join(label for label, _ in columns) + " |", "|" + "---|" * len(columns)]
    for r in rows:
        out.append("| " + " | ".join(_v(r, col) for _, col in columns) + " |")
    return "\n".join(out) + "\n"


def _runs_cols() -> list[tuple[str, str]]:
    return [("Corridas totales", "runs_total"), ("Corridas válidas", "runs_valid"), ("Corridas fallidas", "failed_runs")]


def _ind1_cols(metric: str, label: str) -> list[tuple[str, str]]:
    return [("Escenario", "scenario"), ("Versión", "version"), ("Nivel", "level_label"),
            (f"{label} media _fail0", f"{metric}_mean_fail0"), ("DE _fail0", f"{metric}_sd_fail0"),
            (f"{label} media _valid", f"{metric}_mean_valid"), ("DE _valid", f"{metric}_sd_valid"), *_runs_cols()]


def _ind3_cols(view: str) -> list[tuple[str, str]]:
    cols = [("Escenario", "scenario"), ("Enfoque", "approach"), ("Denominador (técnicas)", "denominator_techniques")]
    for v in VERSIONS:
        cols += [(f"{v} media _{view}", f"{v}_mean_{view}"), (f"{v} DE _{view}", f"{v}_sd_{view}")]
    cols += [(f"{v}/orig _{view}", f"persistence_{v}_over_orig_{view}") for v in VERSIONS[1:]]
    return cols + [("Corridas fallidas", "failed_runs"), ("Coincidencias de IoC", "ioc_matches")]


IND2_COLS = [("Escenario", "scenario"), ("Técnicas de referencia", "reference_techniques"),
             ("Coincidencias", "matches"), ("Exactitud (%)", "accuracy"), ("Discrepancias", "mismatches")]
IND4_COLS = [("Técnicas resumidas", "techniques_summarized"), ("Fallos del LLM", "llm_failures"),
             ("Chequeo automático ok", "auto_check_ok"), ("Chequeo automático ok (%)", "auto_check_ok_pct"),
             ("Revisión manual", "manual_review")]
IND5_COLS = [("Escenario", "scenario"), ("Versión", "version"), ("Salida", "output"),
             ("Violaciones media _fail0", "violations_mean_fail0"), ("DE _fail0", "violations_sd_fail0"),
             ("Violaciones media _valid", "violations_mean_valid"), ("DE _valid", "violations_sd_valid"),
             ("Total de violaciones", "violations_total"), ("Campos extra", "extra_fields"),
             ("Texto valorativo", "evaluative_text"), *_runs_cols()]
RUNS_COLS = [("Escenario", "scenario"), ("Versión", "version"), *_runs_cols(), ("Corridas vacías", "empty_runs")]


# --- charts -----------------------------------------------------------------------------------


def _number(x) -> float | None:
    return x if isinstance(x, (int, float)) and not isinstance(x, bool) else None


def _bar_chart(path: Path, groups: list[str], series: dict[str, list[tuple]], title: str, ylabel: str,
               xlabel: str, panels: list[str] | None = None) -> Path:
    """`series[version]` holds (mean, sd) per group, or per (panel, group) when `panels` is given.
    A missing mean is drawn as the text «sin dato» instead of a bar; a missing SD as a bar without error bar."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    panels = panels or [""]
    fig, axes = plt.subplots(1, len(panels), figsize=(max(6.5, 2.4 * len(groups)) * len(panels), 5.4), squeeze=False)
    width = 0.26
    for p_i, (ax, panel) in enumerate(zip(axes[0], panels)):
        for v_i, v in enumerate(VERSIONS):
            style = SERIES_STYLE[v]
            for g_i, _ in enumerate(groups):
                mean, sd = series[v][p_i * len(groups) + g_i]
                x = g_i + (v_i - 1) * width
                if _number(mean) is None:
                    ax.text(x, 1, "sin dato", rotation=90, ha="center", va="bottom", fontsize=8)
                    continue
                ax.bar(x, mean, width, color=style["color"], hatch=style["hatch"], edgecolor="black",
                       label=style["label"] if p_i == 0 and g_i == 0 else None,
                       yerr=_number(sd), capsize=4, error_kw={"elinewidth": 1})
                if _number(sd) is None:
                    ax.text(x, mean + 1, "sin DE", rotation=90, ha="center", va="bottom", fontsize=8)
        ax.set_xticks(range(len(groups)), groups)
        ax.set_ylim(0, 110)
        ax.set_xlabel(xlabel)
        ax.set_ylabel(ylabel)
        if panel:
            ax.set_title(panel)
    handles, labels = axes[0][0].get_legend_handles_labels()
    if handles:
        fig.legend(handles, labels, fontsize=8, loc="lower center", ncol=3, bbox_to_anchor=(0.5, 0.07))
    fig.suptitle(title)
    fig.text(0.5, 0.01, "Barra: media _fail0 (corridas fallidas = 0). Línea: ± desviación estándar muestral.\n"
                        "«sin dato» / «sin DE»: valor no disponible en el archivo.", fontsize=7, ha="center")
    fig.tight_layout(rect=(0, 0.14, 1, 1))
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path


def _scenarios(rows: list[dict]) -> list[str]:
    return list(dict.fromkeys(r["scenario"] for r in rows))


def _ind1_chart(out_dir: Path, rows: list[dict], metric: str, label: str, name: str) -> Path:
    groups = _scenarios(rows)
    find = {(r["scenario"], r["version"], r["level"]): r for r in rows}
    series = {v: [] for v in VERSIONS}
    for level in LEVELS:
        for g in groups:
            for v in VERSIONS:
                r = find.get((g, v, level), {})
                series[v].append((r.get(f"{metric}_mean_fail0"), r.get(f"{metric}_sd_fail0")))
    return _bar_chart(out_dir / name, groups, series, f"Indicador 1 — {label} del paso 1 por escenario y versión",
                      f"{label} (%)", "Escenario", panels=[f"Nivel {lv}" for lv in LEVELS.values()])


def _ind3_chart(out_dir: Path, rows: list[dict]) -> Path:
    model = [r for r in rows if r.get("approach") == "modelo"]
    groups = _scenarios(model)
    series = {v: [(r.get(f"{v}_mean_fail0"), r.get(f"{v}_sd_fail0")) for r in model] for v in VERSIONS}
    return _bar_chart(out_dir / "indicador3_persistencia.png", groups, series,
                      "Indicador 3 — Persistencia del modelo por escenario y versión", "Persistencia (%)", "Escenario")


# --- missing data -----------------------------------------------------------------------------


def _missing_cells(tables: dict) -> list[str]:
    names = {"runs": "Corridas", "indicator1": "Indicador 1", "indicator2": "Indicador 2", "indicator3": "Indicador 3",
             "indicator4": "Indicador 4", "indicator5": "Indicador 5"}
    out = []
    for key, label in names.items():
        cols: dict[str, int] = {}
        for r in tables.get(key, []):
            for c, val in r.items():
                if val == NO_DATA:
                    cols[c] = cols.get(c, 0) + 1
        if cols:
            detail = ", ".join(f"`{c}` ({n})" for c, n in cols.items())
            out.append(f"- {label}: {sum(cols.values())} celda(s) con «{NO_DATA}» — {detail}.")
    return out


def _per_run_outputs(run_dir: Path) -> list[str]:
    files = [p for p in sorted(run_dir.rglob("*_exposure.csv"))
             if not p.name.startswith("FAKE_") and not {"results", "results_FAKE"} & set(p.relative_to(run_dir).parts)]
    if not files:
        return ["- Columnas `data_sources` y `prevalence`: no se encontraron salidas por corrida (`*_exposure.csv`) "
                "en la carpeta de la corrida; no se puede decir cuántas filas quedaron sin dato."]
    rows = []
    for p in files:
        with p.open(encoding="utf-8-sig", newline="") as fh:
            rows += list(csv.DictReader(fh))
    out = []
    for col in ("data_sources", "prevalence"):
        empty = sum(1 for r in rows if (r.get(col) or NO_DATA) == NO_DATA)
        out.append(f"- Columna `{col}` de las salidas por corrida: {empty} de {len(rows)} filas con «{NO_DATA}» "
                   f"({len(files)} archivos `*_exposure.csv`).")
    return out


# --- report -------------------------------------------------------------------------------------


def manual_review_md(sheets_dir: Path | None, run_id: str) -> list[str]:
    """Manual review as the sheets are now (a review filled after `aem eval` counts without re-running it)."""
    if sheets_dir is None:
        return [f"- Revisión manual de los indicadores 4 y 5: {NO_DATA} (no se indicó la carpeta de las hojas).\n"]
    manual = review.manual_results(Path(sheets_dir), run_id)
    ind4 = manual_indicator4_columns(manual["indicator4"])
    return [
        "### Indicador 4 — Revisión manual de los resúmenes\n",
        f"Estado: {ind4['manual_review']}. Resúmenes fieles («si»): {ind4['manual_ok']} de {ind4['manual_total']} "
        f"({ind4['manual_ok_pct']}{'' if ind4['manual_ok_pct'] == NO_DATA else ' %'}).\n",
        manual_negative_rows_md(manual, "indicator4"),
        "### Indicador 5 — Revisión manual de la muestra\n",
        "Cifra separada del conteo automático de violaciones (tabla anterior); no se suman.\n",
        md_table(manual_indicator5_rows(manual["indicator5"])),
        manual_negative_rows_md(manual, "indicator5_manual"),
    ]


def build_report(run_dir: Path, out_dir: Path, sheets_dir: Path | None = None) -> dict:
    run_dir, out_dir = Path(run_dir), Path(out_dir)
    data = load_results(run_dir)
    tables = data["tables"]
    ind1 = [dict(r, level_label=LEVELS.get(r.get("level"), r.get("level"))) for r in tables.get("indicator1", [])]
    out_dir.mkdir(parents=True, exist_ok=True)
    charts = [_ind1_chart(out_dir, ind1, "precision", "Precisión", "indicador1_precision.png"),
              _ind1_chart(out_dir, ind1, "recall", "Exhaustividad", "indicador1_exhaustividad.png"),
              _ind3_chart(out_dir, tables.get("indicator3", []))]

    first = next((r for rows in tables.values() for r in rows), {})
    run_date = first.get("run_date", str(data.get("started", NO_DATA))[:10])
    omitted = data.get("escenarios_omitidos") or []
    md = [f"# Resumen de resultados — corrida `{data.get('run_id', run_dir.name)}`\n"]
    if data.get("partial"):
        md.append(f"**{PARTIAL_LINE}** — ESCENARIOS OMITIDOS: {format_omitted(omitted)}\n")
    md += [
          "Generado con `aem report` a partir de `runs/" + run_dir.name + "/results/results.json`. Los números se "
          "copian tal como están en ese archivo, sin redondear.\n",
          f"- Modelo (ID): `{data.get('model', NO_DATA)}`",
          f"- Versión del modelo informada por la API: {'; '.join(data.get('model_versions') or []) or NO_DATA}",
          f"- Fecha de la corrida: {run_date} (inicio {data.get('started', NO_DATA)}, fin {data.get('finished', NO_DATA)})",
          f"- Hash SHA-256 de las plantillas de prompt: `{data.get('prompt_templates_sha256', NO_DATA)}`",
          f"- Origen de las respuestas: {first.get('llm_source', NO_DATA)} · temperatura {data.get('temperature', NO_DATA)}"
          f" · ATT&CK {data.get('attack_version', NO_DATA)} · {data.get('replicates', NO_DATA)} corridas por "
          "escenario × versión",
          f"- Porcentajes en %. «{NO_DATA}»: el archivo no tiene el valor (sin corridas o valor no definido).\n",
          "## Corridas\n", _table(tables.get("runs", []), RUNS_COLS),
          "## Indicador 1 — Precisión y exhaustividad del paso 1 (%)\n",
          "Media principal: `_fail0`; `_valid` es secundaria (D-67). DE: desviación estándar muestral.\n",
          "### Precisión\n", _table(ind1, _ind1_cols("precision", "Precisión")),
          "### Exhaustividad\n", _table(ind1, _ind1_cols("recall", "Exhaustividad")),
          "![Indicador 1 — precisión](indicador1_precision.png)\n",
          "![Indicador 1 — exhaustividad](indicador1_exhaustividad.png)\n",
          "## Indicador 2 — Corrección del cruce de cobertura (paso 2)\n", _table(tables.get("indicator2", []), IND2_COLS),
          "## Indicador 3 — Persistencia en el reconocimiento de la exposición (%)\n",
          "Denominador: técnicas de referencia con brecha (modelo) o todas las técnicas de referencia (tradicional). "
          "Media principal del modelo: `_fail0`. Corridas totales y válidas por versión: tabla «Corridas».\n",
          "### Media principal: `_fail0`\n", _table(tables.get("indicator3", []), _ind3_cols("fail0")),
          "### Media secundaria: `_valid`\n", _table(tables.get("indicator3", []), _ind3_cols("valid")),
          "![Indicador 3 — persistencia del modelo](indicador3_persistencia.png)\n",
          "El gráfico muestra solo el enfoque del modelo; la fila del enfoque tradicional está en la tabla (C1).\n",
          "## Indicador 4 — Fidelidad de los resúmenes (chequeo automático)\n", _table(tables.get("indicator4", []), IND4_COLS),
          "## Indicador 5 — Cumplimiento de los límites (violaciones)\n",
          "`_fail0` y `_valid` con el mismo peso (D-67).\n", _table(tables.get("indicator5", []), IND5_COLS),
          "## Indicadores 4 y 5 — Revisión manual (hojas de revisión)\n",
          *manual_review_md(sheets_dir, data.get("run_id", run_dir.name)),
          "## Escenarios omitidos\n",
          f"- escenarios_omitidos: {format_omitted(omitted)}",
          f"- Resultado parcial: {'sí' if data.get('partial') else 'no'}. Las tablas del LLM no tienen corridas de "
          "los escenarios omitidos; si aparecen filas suyas en el indicador 2 o en el enfoque tradicional del "
          "indicador 3, esas no dependen del LLM (D-73).\n" if data.get("partial") else
          "- Resultado parcial: no.\n",
          "## Datos faltantes\n"]
    skipped = data.get("skipped") or []
    md.append("- Escenarios o versiones no evaluados: " + (", ".join(skipped) if skipped else "ninguno") + ".")
    md += _missing_cells(tables) or [f"- Ninguna celda de las tablas tiene «{NO_DATA}»."]
    md += _per_run_outputs(run_dir)
    md += ["", LIMITS]
    path = out_dir / "resumen.md"
    path.write_text("\n".join(md), encoding="utf-8")
    return {"markdown": path, "charts": charts}
