"""Manual review sheets of indicators 4 and 5 (validation, preservation, results). All sheets are synthetic."""

from __future__ import annotations

import csv
import json

import pytest
from typer.testing import CliRunner

from aem import cli
from eval import review
from eval.review import IND4, IND5, IND5_PRIVATE, NO_DATA, ReviewSheetConflict

VERDICT4, VERDICT5, OBS = IND4.verdict, IND5.verdict, review.OBSERVATION


def _ind4_rows(n=3):
    return [{"technique_id": f"T10{i:02d}", "technique_name": f"Técnica {i}", "source_description": f"Descripción {i}.\nSegunda línea.",
             "summary": f"Resumen {i}.", "status": "ok", "auto_check": "ok", VERDICT4: "", OBS: ""} for i in range(n)]


def _ind5_rows(scenario="gunra", n=2):
    return [{"type": "cita (paso 1)", "scenario": scenario, "version": "orig", "replicate": "0",
             "technique_id": f"T11{i:02d}", "text": f"texto sintético {i}", VERDICT5: "", OBS: ""} for i in range(n)]


def _fill(path, values: dict[int, tuple[str, str]], kind=IND4, edit: dict | None = None):
    """Write a review into a generated sheet: `values[row index] = (verdict, observation)`."""
    columns, rows = review.read_sheet(path)
    for i, (verdict, obs) in values.items():
        rows[i][kind.verdict], rows[i][OBS] = verdict, obs
    for (i, col), value in (edit or {}).items():
        rows[i][col] = value
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=columns)
        w.writeheader()
        w.writerows(rows)


@pytest.fixture
def sheet4(tmp_path):
    path = review.sheet_path(tmp_path, "r1", IND4)
    assert review.write_sheet(path, _ind4_rows(), IND4) == "nueva"
    return path


def test_complete_sheet_gives_a_percentage(sheet4, tmp_path):
    _fill(sheet4, {0: ("si", ""), 1: ("no", "omite el alcance de la técnica"), 2: ("si", "")})
    rv = review.validate_sheet(sheet4, IND4)
    assert rv.status == "completa" and rv.problems == []
    ind4 = review.manual_results(tmp_path, "r1")["indicator4"]
    assert ind4["ok"] == 2 and ind4["total"] == 3 and ind4["ok_pct"] == 66.67
    assert ind4["not_ok"] == [{"technique_id": "T1001", "technique_name": "Técnica 1",
                               OBS: "omite el alcance de la técnica"}]


def test_incomplete_sheet_shows_count_and_never_a_percentage(sheet4, tmp_path):
    _fill(sheet4, {0: ("si", "")})
    rv = review.validate_sheet(sheet4, IND4)
    assert rv.status == "incompleta"
    assert rv.status_text() == "revisión incompleta: 1 de 3 filas"
    assert [(row, reason) for row, _, reason in rv.problems] == [(2, f"sin valor en «{VERDICT4}»"),
                                                                 (3, f"sin valor en «{VERDICT4}»")]
    ind4 = review.manual_results(tmp_path, "r1")["indicator4"]
    assert ind4["ok_pct"] == NO_DATA and ind4["ok"] == NO_DATA
    assert ind4["status_text"] == "revisión incompleta: 1 de 3 filas"


def test_negative_verdict_without_observation_is_an_error(sheet4, tmp_path):
    _fill(sheet4, {0: ("si", ""), 1: ("no", "  "), 2: ("si", "")})
    rv = review.validate_sheet(sheet4, IND4)
    assert rv.status == "con errores"
    assert rv.errors == [(2, "T1001", "«no» sin observación")]
    assert review.manual_results(tmp_path, "r1")["indicator4"]["ok_pct"] == NO_DATA


def test_indicator5_needs_an_observation_when_text_has_valuation(tmp_path):
    path = review.sheet_path(tmp_path, "r1", IND5)
    review.write_sheet(path, _ind5_rows(), IND5)
    _fill(path, {0: ("si", ""), 1: ("no", "")}, kind=IND5)
    assert review.validate_sheet(path, IND5).errors == [(1, "T1100", "«si» sin observación")]


def test_altered_generated_column_is_reported_by_row_and_column(sheet4):
    _fill(sheet4, {0: ("si", ""), 1: ("si", ""), 2: ("si", "")}, edit={(2, "summary"): "Resumen corregido."})
    rv = review.validate_sheet(sheet4, IND4)
    assert rv.status == "con errores"
    assert rv.errors == [(3, "T1002", "columna «summary» modificada respecto de la hoja generada")]
    assert rv.valid == 2


def test_line_endings_and_surrounding_spaces_are_not_edits(sheet4):
    _fill(sheet4, {0: ("si", ""), 1: ("si", ""), 2: ("si", "")},
          edit={(0, "source_description"): "Descripción 0.\r\nSegunda línea.  "})
    assert review.validate_sheet(sheet4, IND4).status == "completa"


def test_added_column_or_row_is_an_error(sheet4):
    columns, rows = review.read_sheet(sheet4)
    with sheet4.open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=columns + ["extra"])
        w.writeheader()
        w.writerows([dict(r, extra="", **{VERDICT4: "si"}) for r in rows])
    rv = review.validate_sheet(sheet4, IND4)
    assert rv.status == "con errores" and rv.errors[0][0] == 0 and "columnas" in rv.errors[0][2]


def _rewrite(path, transform):
    columns, rows = review.read_sheet(path)
    review._write_csv(path, columns, transform(rows))


def test_sorted_rows_are_one_sheet_error_not_a_cell_per_column(sheet4):
    """Sorting the whole sheet in a spreadsheet keeps every row intact but moves it: rejected as a whole."""
    _fill(sheet4, {0: ("si", ""), 1: ("si", ""), 2: ("si", "")})
    _rewrite(sheet4, lambda rows: rows[::-1])
    rv = review.validate_sheet(sheet4, IND4)
    assert rv.status == "con errores" and rv.valid == 1  # the middle row did not move
    assert len(rv.errors) == 1
    row, key, reason = rv.errors[0]
    assert row == 0 and reason.startswith(review.ROWS_MISMATCH) and review.ROWS_HINT in reason
    assert "technique_id" in reason and "summary" in reason and "2 de 3 filas" in reason


def test_one_sorted_column_is_detected(sheet4):
    """Sorting only the selected column (the other columns stay): each summary lands next to another technique."""
    def swap_summaries(rows):
        rows[0]["summary"], rows[1]["summary"] = rows[1]["summary"], rows[0]["summary"]
        return rows
    _rewrite(sheet4, swap_summaries)
    rv = review.validate_sheet(sheet4, IND4)
    assert [(row, reason) for row, _, reason in rv.errors] == [
        (0, f"{review.ROWS_MISMATCH} (columnas movidas: summary; 2 de 3 filas afectadas). {review.ROWS_HINT}")]


def test_moved_rows_and_an_edited_cell_are_both_reported(sheet4):
    def edit_and_swap(rows):
        rows[0], rows[1] = rows[1], rows[0]
        rows[2]["summary"] = "Resumen corregido."
        return rows
    _rewrite(sheet4, edit_and_swap)
    errors = review.validate_sheet(sheet4, IND4).errors
    assert errors[0][0] == 0 and errors[0][2].startswith(review.ROWS_MISMATCH)
    assert errors[1:] == [(3, "T1002", "columna «summary» modificada respecto de la hoja generada")]


def test_filtered_sheet_with_fewer_rows_says_not_to_filter(sheet4):
    _rewrite(sheet4, lambda rows: rows[:2])
    reason = review.validate_sheet(sheet4, IND4).errors[0][2]
    assert "se agregaron o quitaron filas" in reason and review.ROWS_HINT in reason


@pytest.mark.parametrize("value", ["Si", "SÍ", "sí", " si ", "NO", "No"])
def test_verdicts_ignore_case_and_accents(value):
    assert review.normalize_verdict(value) in ("si", "no")


def test_mixed_case_and_accented_verdicts_complete_the_sheet(sheet4, tmp_path):
    _fill(sheet4, {0: ("Si", ""), 1: ("SÍ", ""), 2: ("No", "falta una condición")})
    rv = review.validate_sheet(sheet4, IND4)
    assert rv.status == "completa" and rv.counts == {"si": 2, "no": 1}


def test_other_values_are_rejected(sheet4):
    _fill(sheet4, {0: ("ok", ""), 1: ("si", ""), 2: ("si", "")})
    assert review.validate_sheet(sheet4, IND4).errors == [(1, "T1000", f"valor «ok» no válido en «{VERDICT4}» (use si o no)")]


def test_sheet_without_manifest_cannot_be_validated(tmp_path):
    path = tmp_path / "r1_indicator4_summaries.csv"
    review._write_csv(path, list(_ind4_rows()[0]), _ind4_rows())
    assert "sin manifiesto" in review.validate_sheet(path, IND4).errors[0][2]
    review.init_manifest(path, IND4)
    assert review.validate_sheet(path, IND4).status == "incompleta"
    with pytest.raises(ValueError, match="ya existe"):
        review.init_manifest(path, IND4)


def test_manifest_is_not_created_over_a_reviewed_sheet(tmp_path):
    path = tmp_path / "r1_indicator4_summaries.csv"
    rows = _ind4_rows()
    rows[0][VERDICT4] = "si"
    review._write_csv(path, list(rows[0]), rows)
    with pytest.raises(ValueError, match="ya tiene valores de revisión"):
        review.init_manifest(path, IND4)


# --- regeneration never loses a review ------------------------------------------------------


def test_regenerating_keeps_a_reviewed_sheet(sheet4):
    _fill(sheet4, {0: ("si", "")})
    before = sheet4.read_bytes()
    assert review.write_sheet(sheet4, _ind4_rows(), IND4) == "conservada"
    assert sheet4.read_bytes() == before


def test_regenerating_with_different_content_refuses(sheet4):
    _fill(sheet4, {0: ("si", "")})
    rows = _ind4_rows()
    rows[1]["summary"] = "Otro resumen."
    with pytest.raises(ReviewSheetConflict, match="ya tiene revisión"):
        review.write_sheet(sheet4, rows, IND4)


def test_unreviewed_sheet_is_regenerated(sheet4):
    rows = _ind4_rows()
    rows[1]["summary"] = "Otro resumen."
    assert review.write_sheet(sheet4, rows, IND4) == "regenerada"
    assert review.read_sheet(sheet4)[1][1]["summary"] == "Otro resumen."


# --- indicator 5: public and private sheets ------------------------------------------------------


def _ind5_sheets(tmp_path, public=("no", "si"), private=("si", "no")):
    pub = review.sheet_path(tmp_path, "r1", IND5)
    review.write_sheet(pub, _ind5_rows("gunra"), IND5)
    priv = review.sheet_path(tmp_path, "r1", IND5_PRIVATE)
    review.write_sheet(priv, _ind5_rows("akira"), IND5_PRIVATE)
    obs = {"si": "recomienda una acción", "no": ""}
    _fill(pub, {i: (v, obs[v]) for i, v in enumerate(public) if v}, kind=IND5)
    _fill(priv, {i: (v, "OBSERVACION-PRIVADA" if v == "si" else "") for i, v in enumerate(private) if v},
          kind=IND5_PRIVATE)
    return pub, priv


def test_private_sheet_stays_in_private_and_only_its_counts_leave(tmp_path):
    pub, priv = _ind5_sheets(tmp_path)
    assert priv.parent.name == "private" and pub.parent == tmp_path
    manual = review.manual_results(tmp_path, "r1", write_private_summary=True)
    ind5 = manual["indicator5"]
    assert ind5["status"] == "completa" and ind5["total"] == 4 and ind5["with_valuation"] == 2
    assert ind5["with_valuation_pct"] == 50.0
    assert ind5["by_scenario"]["akira"] == {"total": 2, "reviewed": 2, "with_valuation": 1}
    assert [r["scenario"] for r in ind5["flagged"]] == ["gunra"]  # private rows are never listed
    summary = review.private_summary_path(tmp_path, "r1")
    assert summary.parent == tmp_path
    text = summary.read_text(encoding="utf-8")
    assert "OBSERVACION-PRIVADA" not in text and "texto sintético" not in text and "T11" not in text
    # a clone without private/ still has the aggregate
    priv.unlink()
    again = review.manual_results(tmp_path, "r1")["indicator5"]
    assert again["with_valuation"] == 2 and again["private_sheet"] == "solo resumen agregado"


def test_indicator5_is_incomplete_while_the_private_sheet_is(tmp_path):
    _ind5_sheets(tmp_path, private=("si", ""))
    ind5 = review.manual_results(tmp_path, "r1")["indicator5"]
    assert ind5["status_text"] == "revisión incompleta: 3 de 4 filas"
    assert ind5["with_valuation_pct"] == NO_DATA


# --- CLI ------------------------------------------------------------------------------------------


def test_review_check_reports_rows_and_exit_code(tmp_path, monkeypatch, sheet4):
    monkeypatch.setattr("aem.cli.REVIEW_SHEETS_DIR", tmp_path)
    review.write_sheet(review.sheet_path(tmp_path, "r1", IND5), _ind5_rows(), IND5)
    _fill(sheet4, {0: ("si", ""), 1: ("no", "")})
    res = CliRunner().invoke(cli.app, ["review-check", "--run-id", "r1"], env={"COLUMNS": "200"})
    assert res.exit_code == 1
    assert "fila 2 (T1001): «no» sin observación" in res.output
    assert "filas sin valor en «ok (si/no)»: 3" in res.output
    assert "revisión incompleta: 0 de 2 filas" in res.output
    assert "%" not in res.output


def test_review_check_rejects_a_sorted_sheet(tmp_path, monkeypatch, sheet4):
    monkeypatch.setattr("aem.cli.REVIEW_SHEETS_DIR", tmp_path)
    _fill(sheet4, {0: ("si", ""), 1: ("si", ""), 2: ("si", "")})
    _ind5_sheets(tmp_path)
    _rewrite(sheet4, lambda rows: sorted(rows, key=lambda r: r["summary"], reverse=True))
    res = CliRunner().invoke(cli.app, ["review-check", "--run-id", "r1"], env={"COLUMNS": "300"})
    assert res.exit_code == 1
    assert f"hoja: {review.ROWS_MISMATCH}" in res.output and review.ROWS_HINT in res.output
    assert "modificada respecto" not in res.output


def test_review_check_passes_on_complete_sheets(tmp_path, monkeypatch, sheet4):
    monkeypatch.setattr("aem.cli.REVIEW_SHEETS_DIR", tmp_path)
    _fill(sheet4, {0: ("si", ""), 1: ("si", ""), 2: ("si", "")})
    _ind5_sheets(tmp_path)
    res = CliRunner().invoke(cli.app, ["review-check", "--run-id", "r1"], env={"COLUMNS": "200"})
    assert res.exit_code == 0, res.output
    assert "fieles: 3 de 3 (100.0)" in res.output
    assert json.loads(review.private_summary_path(tmp_path, "r1").read_text(encoding="utf-8"))["valid"] == 2
