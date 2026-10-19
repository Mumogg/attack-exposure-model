"""`aem integrate-review`: the human review of indicators 4 and 5 into an evaluated run, without `aem eval`.

Reads the review sheets and rewrites only what depends on them: the manual columns of `indicator4`, the
`indicator5_manual` table, `results.json` (those two tables), `results.md` and `resumen.md`. No preflight, no
LLM client, no call to the API; the per-run files, `provenance.json`, the sensitivity outputs and the tables
of indicators 1, 2, 3 and 5 (automatic count) are not written. Each integration is recorded in
`eval_history.json` with the date and the SHA-256 of every sheet read (RUNBOOK §j).
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from aem.output import write_json
from eval import review
from eval.report import build_report
from eval.run_experiments import (
    _append_history, manual_indicator4_columns, manual_indicator5_rows, provenance_columns, results_markdown,
    write_table,
)

STATUS = "integración de revisión humana"
REWRITTEN_TABLES = ("indicator4", "indicator5_manual")


class IntegrationError(Exception):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def integrate_review(run_dir: Path, sheets_dir: Path, docs_dir: Path, allow_incomplete: bool = False) -> dict:
    """Returns the paths written and the history entry. Nothing is written when a sheet has errors, when the
    review is incomplete (unless `allow_incomplete`) or when the run is not a real, evaluated one."""
    run_dir, sheets_dir = Path(run_dir), Path(sheets_dir)
    started = _now()
    results = run_dir / "results"
    json_path = results / "results.json"
    if not json_path.exists():
        raise IntegrationError(f"No hay results/results.json en la corrida {run_dir.name} (sin `aem eval` "
                               "previo, o solo resultados FAKE, que no se integran).")
    data = json.loads(json_path.read_text(encoding="utf-8"))
    if data.get("fake"):
        raise IntegrationError("results.json está marcado como FAKE: la revisión solo se integra en una corrida real.")
    prov = provenance_columns(data)
    for name, rows in data["tables"].items():
        if any({k: r.get(k) for k in prov} != prov for r in rows):
            raise IntegrationError(f"las columnas de procedencia de la tabla {name} no coinciden con los metadatos "
                                   "de results.json; no se integra nada.")

    run_id = data.get("run_id", run_dir.name)
    manual = review.manual_results(sheets_dir, run_id, write_private_summary=True)
    errors = [rv.path.name for rv in manual["reviews"] if rv.exists and rv.status == "con errores"]
    if errors:
        raise IntegrationError("hojas con errores: " + ", ".join(errors) + " (ver `aem review-check`); no se "
                               "integra nada.")
    incomplete = [s["status_text"] for s in (manual["indicator4"], manual["indicator5"]) if s["status"] != "completa"]
    if incomplete and not allow_incomplete:
        raise IntegrationError("la revisión no está completa (" + "; ".join(incomplete) + "). Termine las hojas o "
                               "use --allow-incomplete para registrar el estado parcial.")

    bare = {name: [{k: v for k, v in r.items() if k not in prov} for r in rows] for name, rows in data["tables"].items()}
    bare["indicator4"] = [dict(r, **manual_indicator4_columns(manual["indicator4"])) for r in bare["indicator4"]]
    bare["indicator5_manual"] = manual_indicator5_rows(manual["indicator5"])
    paths = {}
    for name in REWRITTEN_TABLES:
        data["tables"][name] = [{**prov, **r} for r in bare[name]]
        paths[name] = results / f"{name}.csv"
        write_table(paths[name], data["tables"][name])
    sheet4 = review.sheet_path(sheets_dir, run_id, review.IND4)
    sheet5 = review.sheet_path(sheets_dir, run_id, review.IND5)
    paths["markdown"] = results / "results.md"
    paths["markdown"].write_text(results_markdown(data, bare, manual, (sheet4.name, sheet5.name)), encoding="utf-8")
    paths["json"] = json_path
    write_json(json_path, data)
    paths["report"] = build_report(run_dir, Path(docs_dir), sheets_dir)["markdown"]

    read = [rv.path for rv in manual["reviews"] if rv.exists]
    summary = review.private_summary_path(sheets_dir, run_id)
    if summary.exists():
        read.append(summary)
    entry = {"started": started, "finished": _now(), "status": STATUS, "api_calls": 0,
             "review": {"indicator4": manual["indicator4"]["status_text"],
                        "indicator5": manual["indicator5"]["status_text"]},
             "sheets": [{"file": p.name, "sha256": _sha256(p)} for p in read],
             "rewritten": [f"results/{p.name}" for k, p in paths.items() if k != "report"] + ["resumen.md"]}
    _append_history(run_dir, entry)
    return {"paths": paths, "entry": entry, "manual": manual}
