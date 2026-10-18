"""`aem report`: summary of a real run for the thesis. All numbers here are synthetic test values."""

from __future__ import annotations

import csv

import pytest
from typer.testing import CliRunner

from aem import cli
from eval.report import ReportError, build_report
from eval.run_experiments import NO_DATA, write_results

ND = NO_DATA


def _ind1(scenario, version, level, p, r):
    return {"scenario": scenario, "version": version, "level": level, "runs_total": 5, "runs_valid": 4,
            "failed_runs": 1, "precision_mean_valid": p + 1, "precision_sd_valid": 2.5,
            "precision_mean_fail0": p, "precision_sd_fail0": 3.25, "recall_mean_valid": r + 1,
            "recall_sd_valid": 1.5, "recall_mean_fail0": r, "recall_sd_fail0": 4.75}


def _ind3(scenario, approach):
    row = {"scenario": scenario, "approach": approach, "denominator_techniques": 7, "failed_runs": "orig 1, mut 0, anon 2"}
    for i, v in enumerate(("orig", "mut", "anon")):
        row.update({f"{v}_mean_valid": 61.11 - i, f"{v}_sd_valid": 9.5, f"{v}_mean_fail0": 48.89 - i,
                    f"{v}_sd_fail0": 12.25})
    row.update({"persistence_mut_over_orig_valid": 0.9836, "persistence_anon_over_orig_valid": ND,
                "persistence_mut_over_orig_fail0": 0.9795, "persistence_anon_over_orig_fail0": ND, "ioc_matches": ""})
    return row


def _tables():
    runs = [{"scenario": s, "version": v, "runs_total": 5, "runs_valid": 4, "failed_runs": 1, "empty_runs": 0,
             "failure_reasons": "r2: respuesta no válida"} for s in ("alfa", "beta") for v in ("orig", "mut", "anon")]
    ind1 = [_ind1(s, v, lvl, 70.37, 41.18) for s in ("alfa", "beta") for v in ("orig", "mut", "anon")
            for lvl in ("exact", "parent")]
    ind1[0]["precision_sd_fail0"] = ND
    return {
        "runs": runs, "indicator1": ind1, "indicator1_detail": [],
        "indicator2": [{"scenario": "alfa", "reference_techniques": 9, "matches": 9, "accuracy": 100.0,
                        "mismatches": "ninguna"}],
        "indicator3": [_ind3("alfa", "modelo"), _ind3("alfa", "tradicional"), _ind3("beta", "modelo")],
        "indicator4": [{"techniques_summarized": 12, "llm_failures": 1, "auto_check_ok": 10,
                        "auto_check_ok_pct": 90.91, "manual_review": "pendiente (hoja de revisión)"}],
        "indicator5": [{"scenario": "alfa", "version": "orig", "output": "paso 1 (extracción)", "runs_total": 5,
                        "runs_valid": 4, "failed_runs": 1, "violations_total": 3, "violations_mean_valid": 0.75,
                        "violations_sd_valid": 0.5, "violations_mean_fail0": 0.6, "violations_sd_fail0": 0.55,
                        "extra_fields": 0, "evaluative_text": 3}],
    }


def _meta(fake=False):
    return {"fake": fake, "llm_sources": ["gemini-api"] if not fake else ["FakeLLM"],
            "model_versions": ["modelo-sintetico-001"], "prompt_templates_sha256": "extract.txt=abc123; summary.txt=def456",
            "run_id": "2099-01-02", "started": "2099-01-02T10:00:00+00:00", "finished": "2099-01-02T10:30:00+00:00",
            "model": "modelo-sintetico", "temperature": 0, "attack_version": "19.2", "replicates": 5, "demo": False,
            "skipped": ["gamma: anon"], "runs": []}


def _write(tmp_path, fake=False):
    run = tmp_path / "runs" / "2099-01-02"
    computed = {"tables": _tables(), "summary_sheet": [], "sample_sheet": [], "private_sample_sheet": []}
    write_results(run, tmp_path / "sheets", computed, _meta(fake))
    return run


def _exposure(run, rows, name="alfa/orig/r0/alfa_exposure.csv"):
    path = run / name
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["technique_id", "data_sources", "prevalence"])
        w.writeheader()
        w.writerows(rows)


def test_report_has_metadata_and_exact_numbers(tmp_path):
    run = _write(tmp_path)
    out = build_report(run, tmp_path / "docs" / "resultados" / "2099-01-02")
    md = out["markdown"].read_text(encoding="utf-8")
    assert out["markdown"].name == "resumen.md"
    for s in ("modelo-sintetico", "modelo-sintetico-001", "2099-01-02", "extract.txt=abc123; summary.txt=def456"):
        assert s in md
    # numbers exactly as written in the files, with no rounding or reformatting
    for n in ("70.37", "71.37", "3.25", "41.18", "4.75", "48.89", "61.11", "12.25", "0.9795", "0.9836", "90.91", "0.55"):
        assert n in md
    assert "Indicador 1" in md and "Indicador 2" in md and "Indicador 3" in md and "Indicador 4" in md
    assert "Indicador 5" in md


def test_fail0_columns_come_before_valid_and_runs_are_counted(tmp_path):
    md = build_report(_write(tmp_path), tmp_path / "out")["markdown"].read_text(encoding="utf-8")
    header = next(line for line in md.splitlines() if line.startswith("|") and "Precisión" in line)
    assert header.index("_fail0") < header.index("_valid")
    assert "Corridas totales" in header and "válidas" in header and "fallidas" in header
    ind3 = md.split("## Indicador 3", 1)[1].split("\n## ", 1)[0]
    assert ind3.index("orig media _fail0") < ind3.index("orig media _valid")


def test_charts_for_indicators_1_and_3_are_png(tmp_path):
    out = build_report(_write(tmp_path), tmp_path / "out")
    charts = out["charts"]
    assert {p.name for p in charts} == {"indicador1_precision.png", "indicador1_exhaustividad.png",
                                         "indicador3_persistencia.png"}
    for p in charts:
        assert p.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
        assert f"]({p.name})" in out["markdown"].read_text(encoding="utf-8")


def test_series_are_not_distinguished_by_hue_alone():
    from eval.report import SERIES_STYLE
    hatches = {s["hatch"] for s in SERIES_STYLE.values()}
    assert set(SERIES_STYLE) == {"orig", "mut", "anon"} and len(hatches) == 3


def test_limits_section_repeats_c1_c3_and_d67(tmp_path):
    md = build_report(_write(tmp_path), tmp_path / "out")["markdown"].read_text(encoding="utf-8")
    section = md.split("## Lo que estos números permiten y no permiten afirmar", 1)[1]
    for s in ("C1", "C2", "C3", "D-67", "_fail0", "_valid"):
        assert s in section


def test_missing_data_is_stated(tmp_path):
    run = _write(tmp_path)
    _exposure(run, [{"technique_id": "T1059.001", "data_sources": "Process Creation", "prevalence": ND},
                    {"technique_id": "T1021.001", "data_sources": ND, "prevalence": ND}])
    md = build_report(run, tmp_path / "out")["markdown"].read_text(encoding="utf-8")
    section = md.split("## Datos faltantes", 1)[1].split("\n## ", 1)[0]
    assert "gamma: anon" in section
    assert "prevalence" in section and "2 de 2" in section
    assert "data_sources" in section and "1 de 2" in section
    assert "Indicador 1" in section and "Indicador 3" in section  # cells with «sin dato disponible»


def test_no_per_run_outputs_is_stated(tmp_path):
    md = build_report(_write(tmp_path), tmp_path / "out")["markdown"].read_text(encoding="utf-8")
    assert "no se encontraron salidas por corrida" in md


def test_fake_per_run_outputs_are_not_counted(tmp_path):
    run = _write(tmp_path)
    _exposure(run, [{"technique_id": "T1", "data_sources": ND, "prevalence": ND}], name="alfa/orig/r0/FAKE_x_exposure.csv")
    md = build_report(run, tmp_path / "out")["markdown"].read_text(encoding="utf-8")
    assert "no se encontraron salidas por corrida" in md


def test_refuses_when_only_fake_results_exist(tmp_path):
    run = _write(tmp_path, fake=True)
    assert (run / "results_FAKE").exists() and not (run / "results").exists()
    with pytest.raises(ReportError, match="FAKE"):
        build_report(run, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_refuses_results_json_marked_fake(tmp_path):
    run = _write(tmp_path, fake=True)
    (run / "results_FAKE").rename(run / "results")
    (run / "results" / "FAKE_results.json").rename(run / "results" / "results.json")
    with pytest.raises(ReportError, match="FAKE"):
        build_report(run, tmp_path / "out")


def test_refuses_missing_run(tmp_path):
    with pytest.raises(ReportError, match="No hay resultados"):
        build_report(tmp_path / "runs" / "nada", tmp_path / "out")


def test_cli_report(tmp_path, monkeypatch):
    run = _write(tmp_path)
    monkeypatch.setattr(cli, "RUNS_DIR", run.parent)
    monkeypatch.setattr(cli, "RESULTS_DOCS_DIR", tmp_path / "docs" / "resultados")
    res = CliRunner().invoke(cli.app, ["report", "--run-id", "2099-01-02"])
    assert res.exit_code == 0, res.output
    assert (tmp_path / "docs" / "resultados" / "2099-01-02" / "resumen.md").exists()


def test_cli_report_refuses_fake(tmp_path, monkeypatch):
    run = _write(tmp_path, fake=True)
    monkeypatch.setattr(cli, "RUNS_DIR", run.parent)
    monkeypatch.setattr(cli, "RESULTS_DOCS_DIR", tmp_path / "docs" / "resultados")
    res = CliRunner().invoke(cli.app, ["report", "--run-id", "2099-01-02"])
    assert res.exit_code == 1 and "FAKE" in res.output


def test_partial_run_is_stated_in_the_report(tmp_path):
    """D-73: a run with an omitted scenario says so at the top and in its own section."""
    run = tmp_path / "runs" / "2099-01-02"
    computed = {"tables": _tables(), "summary_sheet": [], "sample_sheet": [], "private_sample_sheet": []}
    meta = dict(_meta(), partial=True, escenarios_omitidos=[{"scenario": "akira", "reason": "sin texto local"}])
    write_results(run, tmp_path / "sheets", computed, meta)
    md = build_report(run, tmp_path / "out")["markdown"].read_text(encoding="utf-8")
    head = md.split("## Corridas")[0]
    assert "RESULTADO PARCIAL: faltan escenarios" in head and "akira (sin texto local)" in head
    assert "## Escenarios omitidos" in md and "escenarios_omitidos: akira (sin texto local)" in md
    with (run / "results" / "indicator1.csv").open(encoding="utf-8-sig", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert rows and all(r["escenarios_omitidos"] == "akira (sin texto local)" for r in rows)


def test_complete_run_is_not_marked_partial(tmp_path):
    run = tmp_path / "runs" / "2099-01-02"
    computed = {"tables": _tables(), "summary_sheet": [], "sample_sheet": [], "private_sample_sheet": []}
    write_results(run, tmp_path / "sheets", computed, dict(_meta(), partial=False, escenarios_omitidos=[]))
    md = build_report(run, tmp_path / "out")["markdown"].read_text(encoding="utf-8")
    assert "RESULTADO PARCIAL" not in md and "escenarios_omitidos: ninguno" in md
