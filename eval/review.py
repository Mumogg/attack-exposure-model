"""Manual review sheets of indicators 4 and 5: generation without losing a review, validation and results.

`aem eval` writes each sheet next to a manifest (`<sheet>.manifest.json`) with a SHA-256 per row and per
cell of the generated columns. The reviewer fills only the verdict column and `observación`; validation
compares every other cell with the manifest, so an edited summary or quote is caught (row and column).

- Indicator 4 (`ok (si/no)`): «no» (unfaithful summary) needs an `observación`.
- Indicator 5 (`contiene_valoracion (si/no)`): «si» (the text evaluates or recommends) needs an `observación`.
- Verdicts are «si» or «no», case- and accent-insensitive («Sí», «SÍ», «si» are the same).

An incomplete or invalid sheet yields no percentage, only «revisión incompleta: N de M filas» or
«revisión con errores: …». The private sheet of a copyrighted scenario (Akira) stays in `private/`; only
its aggregate counts leave that folder (`<run-id>_indicator5_private_summary.json`, D-69).
"""

from __future__ import annotations

import csv
import hashlib
import json
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

from aem.output import write_json

NO_DATA = "sin dato disponible"
OBSERVATION = "observación"
ROWS_MISMATCH = "las filas no coinciden con el original"
ROWS_HINT = ("No ordene ni filtre la hoja: restáurela (`git checkout -- <hoja>`) y llénela en el orden en que se "
             "generó.")


@dataclass(frozen=True)
class SheetKind:
    name: str
    suffix: str  # file name after `<prefix><run-id>`
    verdict: str  # column the reviewer fills
    negative: str  # verdict that needs an observation
    private: bool = False


IND4 = SheetKind("indicator4", "_indicator4_summaries.csv", "ok (si/no)", "no")
IND5 = SheetKind("indicator5", "_indicator5_sample.csv", "contiene_valoracion (si/no)", "si")
IND5_PRIVATE = SheetKind("indicator5_private", "_indicator5_sample_private.csv", "contiene_valoracion (si/no)", "si",
                         private=True)
KINDS = (IND4, IND5, IND5_PRIVATE)


class ReviewSheetConflict(Exception):
    """A sheet that already has a review would be overwritten with different generated content."""


# --- files ------------------------------------------------------------------------------------


def sheet_path(sheets_dir: Path, run_id: str, kind: SheetKind, prefix: str = "") -> Path:
    folder = Path(sheets_dir) / "private" if kind.private else Path(sheets_dir)
    return folder / f"{prefix}{run_id}{kind.suffix}"


def manifest_path(sheet: Path) -> Path:
    return sheet.with_name(sheet.stem + ".manifest.json")


def private_summary_path(sheets_dir: Path, run_id: str, prefix: str = "") -> Path:
    """Aggregate counts of the private sheet (no text), public so that a clone without private/ keeps them."""
    return Path(sheets_dir) / f"{prefix}{run_id}_indicator5_private_summary.json"


def read_sheet(path: Path) -> tuple[list[str], list[dict]]:
    with Path(path).open(encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        return list(reader.fieldnames or []), list(reader)


def _write_csv(path: Path, columns: list[str], rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=columns)
        w.writeheader()
        w.writerows(rows)


# --- hashing ----------------------------------------------------------------------------------


def _cell(value) -> str:
    """Spreadsheet programs may change line endings or trailing spaces: those do not count as edits."""
    return str(value if value is not None else "").replace("\r\n", "\n").replace("\r", "\n").strip()


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _generated_columns(columns: list[str], kind: SheetKind) -> list[str]:
    return [c for c in columns if c not in (kind.verdict, OBSERVATION)]


def build_manifest(columns: list[str], rows: list[dict], kind: SheetKind) -> dict:
    generated = _generated_columns(columns, kind)
    return {
        "kind": kind.name, "columns": list(columns), "generated_columns": generated,
        "review_columns": [kind.verdict, OBSERVATION],
        "rows": [{"sha256": _sha(json.dumps([_cell(r.get(c)) for c in generated], ensure_ascii=False)),
                  "cells": {c: _sha(_cell(r.get(c)))[:16] for c in generated}} for r in rows],
    }


def _has_review(rows: list[dict], kind: SheetKind) -> bool:
    return any(_cell(r.get(kind.verdict)) or _cell(r.get(OBSERVATION)) for r in rows)


def write_sheet(path: Path, rows: list[dict], kind: SheetKind) -> str:
    """Write a generated sheet and its manifest without ever discarding a review.

    Returns «nueva», «regenerada» (no review yet) or «conservada» (it had a review and the generated content
    is the same, so the file is left as it is). Raises ReviewSheetConflict if it had a review and the
    generated content changed."""
    path = Path(path)
    columns = list(rows[0]) if rows else []
    manifest = build_manifest(columns, rows, kind)
    status = "nueva"
    if path.exists():
        old_columns, old_rows = read_sheet(path)
        if _has_review(old_rows, kind):
            if build_manifest(old_columns, old_rows, kind)["rows"] == manifest["rows"] and old_columns == columns:
                write_json(manifest_path(path), manifest)
                return "conservada"
            raise ReviewSheetConflict(
                f"La hoja {path.name} ya tiene revisión y su contenido generado cambió en esta ejecución. "
                "No se sobrescribe: muévala a otra carpeta (o renómbrela) y vuelva a ejecutar.")
        status = "regenerada"
    _write_csv(path, columns, rows)
    write_json(manifest_path(path), manifest)
    return status


def init_manifest(path: Path, kind: SheetKind) -> Path:
    """Manifest for a sheet generated before manifests existed. Only for a sheet still without any review
    (so it is the generated one) and without a manifest."""
    path = Path(path)
    mpath = manifest_path(path)
    if mpath.exists():
        raise ValueError(f"{mpath.name} ya existe: no se reemplaza.")
    columns, rows = read_sheet(path)
    if _has_review(rows, kind):
        raise ValueError(f"{path.name} ya tiene valores de revisión: el manifiesto solo se crea sobre la hoja "
                         "recién generada.")
    write_json(mpath, build_manifest(columns, rows, kind))
    return mpath


# --- validation -------------------------------------------------------------------------------


def normalize_verdict(value) -> str | None:
    """«si»/«no» ignoring case and accents; None if empty; the cleaned text otherwise (invalid)."""
    text = _cell(value)
    if not text:
        return None
    plain = "".join(ch for ch in unicodedata.normalize("NFKD", text) if not unicodedata.combining(ch)).casefold()
    return plain if plain in ("si", "no") else text


@dataclass
class SheetReview:
    kind: SheetKind
    path: Path
    exists: bool
    total: int = 0
    valid: int = 0  # rows with a valid verdict and, when needed, an observation
    empty: int = 0
    counts: dict = field(default_factory=lambda: {"si": 0, "no": 0})
    problems: list = field(default_factory=list)  # (row number, key, reason)
    rows: list = field(default_factory=list)  # parsed rows with "_verdict"

    @property
    def errors(self) -> list:
        return [p for p in self.problems if not p[2].startswith("sin valor")]

    @property
    def status(self) -> str:
        if not self.exists:
            return "sin hoja"
        if self.errors:
            return "con errores"
        return "completa" if self.valid == self.total else "incompleta"

    def status_text(self) -> str:
        if not self.exists:
            return f"{NO_DATA} (no existe {self.path.name})"
        if self.status == "con errores":
            return (f"revisión con errores: {len(self.errors)} problema(s), {self.valid} de {self.total} filas "
                    "válidas (ver `aem review-check`)")
        if self.status == "incompleta":
            return f"revisión incompleta: {self.valid} de {self.total} filas"
        return "revisión completa"


def _row_key(row: dict) -> str:
    return _cell(row.get("technique_id")) or "-"


def _moved_cells(rows: list[dict], manifest: dict) -> set[tuple[int, str]]:
    """(row number, column) of generated cells that differ from their own row in the manifest but equal that
    column in another row: the sheet (or one column of it) was sorted or filtered, not edited."""
    moved = set()
    for c in manifest["generated_columns"]:
        column = [r["cells"][c] for r in manifest["rows"]]
        others = set(column)
        for i, row in enumerate(rows, 1):
            h = _sha(_cell(row.get(c)))[:16]
            if h != column[i - 1] and h in others:
                moved.add((i, c))
    return moved


def validate_sheet(path: Path, kind: SheetKind) -> SheetReview:
    path = Path(path)
    review = SheetReview(kind=kind, path=path, exists=path.exists())
    if not review.exists:
        return review
    columns, rows = read_sheet(path)
    review.total = len(rows)
    mpath = manifest_path(path)
    manifest = json.loads(mpath.read_text(encoding="utf-8")) if mpath.exists() else None
    if manifest is None:
        review.problems.append((0, "-", f"sin manifiesto ({mpath.name}): no se puede verificar que las columnas "
                                        "generadas no cambiaron (`aem review-check --init-manifest`)"))
    elif columns != manifest["columns"]:
        review.problems.append((0, "-", "las columnas no coinciden con la hoja generada (se agregaron, quitaron, "
                                        "renombraron o reordenaron columnas)"))
        manifest = None
    elif len(rows) != len(manifest["rows"]):
        review.problems.append((0, "-", f"la hoja tiene {len(rows)} filas y la generada tenía "
                                        f"{len(manifest['rows'])} (se agregaron o quitaron filas). {ROWS_HINT}"))
        manifest = None
    moved = _moved_cells(rows, manifest) if manifest is not None else set()
    if moved:
        columns_moved = [c for c in manifest["generated_columns"] if any(m[1] == c for m in moved)]
        review.problems.append((0, "-", f"{ROWS_MISMATCH} (columnas movidas: {', '.join(columns_moved)}; "
                                        f"{len({m[0] for m in moved})} de {len(rows)} filas afectadas). {ROWS_HINT}"))
    for i, row in enumerate(rows, 1):
        key = _row_key(row)
        altered = []
        if manifest is not None:
            expected = manifest["rows"][i - 1]["cells"]
            altered = [c for c in manifest["generated_columns"] if _sha(_cell(row.get(c)))[:16] != expected[c]]
            for c in altered:
                if (i, c) not in moved:  # moved cells are already reported once for the whole sheet
                    review.problems.append((i, key, f"columna «{c}» modificada respecto de la hoja generada"))
        verdict = normalize_verdict(row.get(kind.verdict))
        row = dict(row, _verdict=verdict)
        review.rows.append(row)
        if verdict is None:
            review.empty += 1
            review.problems.append((i, key, f"sin valor en «{kind.verdict}»"))
            continue
        if verdict not in ("si", "no"):
            review.problems.append((i, key, f"valor «{verdict}» no válido en «{kind.verdict}» (use si o no)"))
            continue
        if verdict == kind.negative and not _cell(row.get(OBSERVATION)):
            review.problems.append((i, key, f"«{kind.negative}» sin observación"))
            continue
        if not altered:
            review.valid += 1
            review.counts[verdict] += 1
    return review


def _pct(num: int, den: int) -> float | str:
    return round(100 * num / den, 2) if den else NO_DATA


# --- results ----------------------------------------------------------------------------------


def _scenario_counts(review: SheetReview) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for r in review.rows:
        sc = _cell(r.get("scenario")) or "-"
        c = out.setdefault(sc, {"total": 0, "reviewed": 0, "with_valuation": 0})
        c["total"] += 1
        if r["_verdict"] in ("si", "no"):
            c["reviewed"] += 1
            c["with_valuation"] += r["_verdict"] == "si"
    return out


def private_summary(review: SheetReview) -> dict:
    """Aggregate counts of the private sheet: no text, no observation."""
    return {"sheet": review.path.name, "status": review.status, "status_text": review.status_text(),
            "total": review.total, "valid": review.valid, "with_valuation": review.counts["si"],
            "by_scenario": _scenario_counts(review)}


def manual_results(sheets_dir: Path, run_id: str, prefix: str = "", write_private_summary: bool = False) -> dict:
    """Indicator 4 and the manual part of indicator 5, from the sheets as they are now.

    The private sheet is read if present (and, with `write_private_summary`, its aggregate is saved);
    otherwise the saved aggregate is used, so a clone without private/ still has the counts."""
    ind4 = validate_sheet(sheet_path(sheets_dir, run_id, IND4, prefix), IND4)
    ind5 = validate_sheet(sheet_path(sheets_dir, run_id, IND5, prefix), IND5)
    priv = validate_sheet(sheet_path(sheets_dir, run_id, IND5_PRIVATE, prefix), IND5_PRIVATE)
    spath = private_summary_path(sheets_dir, run_id, prefix)
    if priv.exists:
        psum = private_summary(priv)
        if write_private_summary:
            write_json(spath, psum)
    else:
        psum = json.loads(spath.read_text(encoding="utf-8")) if spath.exists() else None

    complete4 = ind4.exists and ind4.status == "completa"
    indicator4 = {
        "status": ind4.status, "status_text": ind4.status_text(), "total": ind4.total, "reviewed": ind4.valid,
        "ok": ind4.counts["si"] if complete4 else NO_DATA,
        "ok_pct": _pct(ind4.counts["si"], ind4.total) if complete4 else NO_DATA,
        "not_ok": [{"technique_id": _cell(r.get("technique_id")), "technique_name": _cell(r.get("technique_name")),
                    OBSERVATION: _cell(r.get(OBSERVATION))} for r in ind4.rows if r["_verdict"] == "no"],
    }

    parts = [("público", ind5.status if ind5.exists else "sin hoja", ind5.valid, ind5.total, ind5.counts["si"])]
    if psum is not None:
        parts.append(("privado", psum["status"], psum["valid"], psum["total"], psum["with_valuation"]))
    total = sum(p[3] for p in parts)
    valid = sum(p[2] for p in parts)
    complete5 = all(p[1] == "completa" for p in parts) and ind5.exists
    if complete5:
        text5 = "revisión completa"
    elif any(p[1] == "con errores" for p in parts):
        text5 = f"revisión con errores: {valid} de {total} filas válidas (ver `aem review-check`)"
    elif not ind5.exists:
        text5 = ind5.status_text()
    else:
        text5 = f"revisión incompleta: {valid} de {total} filas"
    by_scenario = _scenario_counts(ind5) if ind5.exists else {}
    for sc, c in ((psum or {}).get("by_scenario") or {}).items():
        by_scenario[sc] = c
    with_val = sum(p[4] for p in parts)
    indicator5 = {
        "status": "completa" if complete5 else "incompleta", "status_text": text5, "total": total, "reviewed": valid,
        "with_valuation": with_val if complete5 else NO_DATA,
        "with_valuation_pct": _pct(with_val, total) if complete5 else NO_DATA,
        "by_scenario": by_scenario, "private_sheet": "presente" if priv.exists else (
            "solo resumen agregado" if psum is not None else "no disponible"),
        # only rows of the public sheet are listed; the private ones stay aggregated (D-69)
        "flagged": [{k: _cell(r.get(k)) for k in ("type", "scenario", "version", "technique_id", OBSERVATION)}
                    for r in ind5.rows if r["_verdict"] == "si"],
    }
    return {"indicator4": indicator4, "indicator5": indicator5, "reviews": [ind4, ind5, priv]}
