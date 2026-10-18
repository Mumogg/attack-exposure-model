"""`aem preflight`: everything that must be in place before spending API calls on `aem eval`.

Each check is OK, FALTA (blocks `aem eval`) or AVISO (does not block). INFO lines carry the
expected number of calls and time.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from aem.config import ModelConfig, Settings
from aem.fetch import read_checksums
from aem.llm import GeminiClient, LLMCache, LLMError, ModelUnavailable, Transport
from aem.scenarios import VERSIONS, Scenario, load_reference
from aem.step1_extract import chunk_text
from aem.step4_reference import load_prevalence

ATTACK_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b|\bTA\d{4}\b")
# Paths that must never reach git (D-69 and secrets); a dummy name stands for any run id / file.
MUST_BE_IGNORED = (".env", "runs/llm_cache_private/", "runs/<run-id>/private/", "eval/review_sheets/private/",
                   "data/reports/private/")


@dataclass(frozen=True)
class Check:
    status: str  # OK | FALTA | AVISO | INFO
    item: str
    detail: str = ""


def has_blocker(checks: list[Check]) -> bool:
    return any(c.status == "FALTA" for c in checks)


def _api_checks(settings: Settings, demo: bool, transport: Transport | None) -> list[Check]:
    if demo:
        return [Check("OK", "GEMINI_API_KEY", "modo demo: no se usa la API")]
    if not settings.gemini_api_key:
        return [Check("FALTA", "GEMINI_API_KEY", "no está en .env (vea docs/RUNBOOK.md, paso a)"),
                Check("FALTA", f"Modelo {settings.gemini_model}", "no se puede verificar sin API key")]
    client = GeminiClient(settings, LLMCache(Path("/nonexistent")), transport=transport)
    try:
        client._check_model(client._transport())  # metadata request only: no tokens are spent
    except ModelUnavailable as exc:
        return [Check("OK", "GEMINI_API_KEY", "presente en .env"),
                Check("FALTA", f"Modelo {settings.gemini_model}", str(exc))]
    except LLMError as exc:
        return [Check("OK", "GEMINI_API_KEY", "presente en .env"),
                Check("FALTA", f"Modelo {settings.gemini_model}", f"no se pudo verificar: {exc}")]
    return [Check("OK", "GEMINI_API_KEY", "presente en .env"),
            Check("OK", f"Modelo {settings.gemini_model}", "existe en la API de Gemini")]


def _attack_check(attack_path: Path, checksums_path: Path) -> Check:
    item = "Datos de ATT&CK v19.2 (checksum)"
    if not Path(attack_path).exists():
        return Check("FALTA", item, f"no existe {attack_path}; ejecute `aem fetch-data`")
    expected = read_checksums(Path(checksums_path)).get(Path(attack_path).name)
    if not expected:
        return Check("FALTA", item, f"no hay checksum registrado para {Path(attack_path).name} en {checksums_path}")
    actual = hashlib.sha256(Path(attack_path).read_bytes()).hexdigest()
    if actual != expected:
        return Check("FALTA", item, f"SHA-256 {actual[:16]}… no coincide con el registrado {expected[:16]}…; "
                                    "vuelva a ejecutar `aem fetch-data`")
    return Check("OK", item, f"SHA-256 {actual[:16]}… coincide")


def _scenario_checks(scenarios: dict[str, Scenario], demo: bool) -> list[Check]:
    checks = []
    for sc in scenarios.values():
        # demo: a copyrighted scenario cannot be replayed by someone who clones the repo (D-69), so it may be absent
        absent = "AVISO" if demo and sc.copyrighted else "FALTA"
        if sc.copyrighted:
            if sc.text.exists():
                checks.append(Check("OK", f"Texto de {sc.name}", str(sc.text)))
            else:
                checks.append(Check(absent, f"Texto de {sc.name}",
                                    f"no existe {sc.text} (docs/report_preparation.md §5)"))
        if sc.stripped.exists():
            ids = ATTACK_ID.findall(sc.stripped.read_text(encoding="utf-8"))
            if ids:
                checks.append(Check("FALTA", f"Texto stripped de {sc.name} sin IDs de ATT&CK",
                                    f"contiene {len(ids)} ID(s), p. ej. {', '.join(sorted(set(ids))[:5])}; "
                                    "vuelva a ejecutar `aem prepare-reports`"))
            else:
                checks.append(Check("OK", f"Texto stripped de {sc.name} sin IDs de ATT&CK", sc.stripped.name))
        missing = [v for v in VERSIONS if not sc.report_for(v).exists()]
        if missing:
            how = "`aem prepare-reports`" if "orig" in missing else "`aem make-variants`"
            checks.append(Check(absent, f"Versiones de {sc.name}", f"faltan {', '.join(missing)}; ejecute {how}"))
        else:
            checks.append(Check("OK", f"Versiones de {sc.name}", ", ".join(VERSIONS)))
    return checks


def _prevalence_check(path: Path) -> Check:
    item = "Prevalencia (Red Canary 2026)"
    try:
        rows = load_prevalence(Path(path))
    except ValueError as exc:
        return Check("FALTA", item, str(exc))
    if not rows:
        return Check("AVISO", item, f"{Path(path).name} está vacío: la columna prevalence saldrá "
                                    "«sin dato disponible» en todas las técnicas")
    return Check("OK", item, f"{len(rows)} técnicas")


def _gitignore_checks(repo_root: Path) -> list[Check]:
    checks = []
    for rel in MUST_BE_IGNORED:
        probe = rel.replace("<run-id>", "preflight") + ("x" if rel.endswith("/") else "")
        try:
            res = subprocess.run(["git", "-C", str(repo_root), "check-ignore", "-q", probe],
                                 capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired) as exc:
            checks.append(Check("AVISO", f"Ignorado por git: {rel}", f"no se pudo ejecutar git: {exc}"))
            continue
        if res.returncode == 0:
            checks.append(Check("OK", f"Ignorado por git: {rel}"))
        elif res.returncode == 1:
            checks.append(Check("FALTA", f"Ignorado por git: {rel}", "agregue la regla a .gitignore"))
        else:
            checks.append(Check("AVISO", f"Ignorado por git: {rel}", res.stderr.strip() or "git no respondió"))
    return checks


def estimate_calls(scenarios: dict[str, Scenario], model_cfg: ModelConfig, replicates: int, rpm: int) -> dict:
    """Extraction calls are exact for the texts present; summaries have a lower bound (one per distinct
    reference technique, D-44) plus whatever valid technique the LLM proposes outside the references."""
    extraction, unknown = 0, []
    for sc in scenarios.values():
        for v in VERSIONS:
            path = sc.report_for(v)
            if path.exists():
                extraction += len(chunk_text(path.read_text(encoding="utf-8"), model_cfg.extraction)) * replicates
            else:
                unknown.append(f"{sc.name}: {v}")
    reference = set()
    for sc in scenarios.values():
        if sc.reference.exists():
            reference |= {r.technique_id for r in load_reference(sc.reference) if r.valid}
    seconds = 60.0 / max(rpm, 1)
    return {"extraction_calls": extraction, "summary_calls_min": len(reference), "unknown_texts": unknown,
            "minutes_min": (extraction + len(reference)) * seconds / 60, "rpm": rpm, "replicates": replicates}


def run_preflight(*, settings: Settings, demo: bool, attack_path: Path, checksums_path: Path,
                  scenarios: dict[str, Scenario], prevalence_path: Path, repo_root: Path, model_cfg: ModelConfig,
                  replicates: int, transport: Transport | None = None) -> list[Check]:
    checks = _api_checks(settings, demo, transport)
    checks.append(_attack_check(attack_path, checksums_path))
    checks += _scenario_checks(scenarios, demo)
    checks.append(_prevalence_check(prevalence_path))
    checks += _gitignore_checks(repo_root)
    est = estimate_calls(scenarios, model_cfg, replicates, settings.gemini_rpm)
    detail = (f"{est['extraction_calls']} de extracción ({len(VERSIONS)} versiones × {replicates} corridas × "
              f"fragmentos) + al menos {est['summary_calls_min']} resúmenes (uno por técnica distinta) = "
              f"≥ {est['extraction_calls'] + est['summary_calls_min']} llamadas; ≥ {est['minutes_min']:.0f} min a "
              f"GEMINI_RPM={est['rpm']} (sin contar reintentos ni lo que ya esté en la caché)")
    if est["unknown_texts"]:
        detail += f". Sin texto, no contados: {', '.join(est['unknown_texts'])}"
    checks.append(Check("INFO", "Estimación de llamadas y tiempo", detail))
    return checks
