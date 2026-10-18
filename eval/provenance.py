"""Provenance of a run: `runs/<id>/results/provenance.json`.

`aem eval` writes it at the end of every evaluation (`reconstructed: false`): code commit and whether the
working tree had uncommitted changes in the frozen files, model, ATT&CK version and SHA-256, SHA-256 of every
frozen input (prompts, parameters, SSVC tree, organisation, anon names, scenarios, references), Python and
the main dependencies.

For a run evaluated before this file existed, `aem provenance --run-id <id>` rebuilds it from what is on disk
and in git (`reconstructed: true`): each field says where it comes from (`sources`), and what cannot be known
is written as «no registrado». Nothing is guessed.
"""

from __future__ import annotations

import hashlib
import json
import platform
import subprocess
from datetime import datetime, timedelta, timezone
from importlib import metadata
from pathlib import Path

from aem.output import write_json

NOT_RECORDED = "no registrado"
# inputs that define the experiment (RUNBOOK, «Congelamiento del experimento»); private files are left out
FROZEN_FILES = (
    "src/aem/prompts/extract_v1.txt", "src/aem/prompts/summary_v1.txt", "data/model_config.yaml",
    "data/ssvc_tree.yaml", "data/org/fictional_org.yaml", "data/org/known_iocs_generated.yaml",
    "data/anon_names.yaml", "data/scenarios.yaml", "data/boundary_patterns.yaml",
    "data/reference_mappings/gunra.csv", "data/reference_mappings/interlock.csv",
    "data/reference_mappings/akira.csv", "data/attack/CHECKSUMS.sha256",
)
# code of steps 1 to 4 and of the evaluation (the review sheets are outputs, not code)
FROZEN_CODE = ("src/aem", "eval", ":(exclude)eval/review_sheets")
MAIN_DEPENDENCIES = ("pydantic", "pyyaml", "python-dotenv", "typer", "rich", "mitreattack-python", "google-genai",
                     "matplotlib")
ATTACK_FILE_REL = "data/attack/enterprise-attack-19.2.json"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _git(repo: Path, *args: str) -> str | None:
    try:
        res = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        return None
    # only the final newline: `git status --porcelain` lines start with a significant space
    return res.stdout.decode("utf-8", errors="replace").rstrip("\n") if res.returncode == 0 else None


def _git_blob(repo: Path, commit: str, path: str) -> bytes | None:
    try:
        res = subprocess.run(["git", "-C", str(repo), "show", f"{commit}:{path}"], capture_output=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return res.stdout if res.returncode == 0 else None


def _expected_attack_sha(repo: Path) -> str | None:
    path = repo / "data" / "attack" / "CHECKSUMS.sha256"
    if not path.exists():
        return None
    for line in path.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].endswith(Path(ATTACK_FILE_REL).name):
            return parts[0]
    return None


def _attack(repo: Path, version: str) -> dict:
    file = repo / ATTACK_FILE_REL
    actual = _sha(file.read_bytes()) if file.exists() else NOT_RECORDED
    expected = _expected_attack_sha(repo) or NOT_RECORDED
    return {"version": version, "file": ATTACK_FILE_REL, "sha256": actual, "expected_sha256": expected,
            "matches_expected": actual == expected if NOT_RECORDED not in (actual, expected) else NOT_RECORDED}


def file_hashes(repo: Path) -> dict[str, str]:
    return {p: (_sha((repo / p).read_bytes()) if (repo / p).exists() else "no existe") for p in FROZEN_FILES}


def dependency_versions() -> dict[str, str]:
    out = {}
    for name in MAIN_DEPENDENCIES:
        try:
            out[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            out[name] = NOT_RECORDED
    return out


def _dirty_frozen(repo: Path) -> list[str] | str:
    status = _git(repo, "status", "--porcelain", "--untracked-files=no", "--", *FROZEN_FILES, *FROZEN_CODE)
    if status is None:
        return NOT_RECORDED
    return sorted(line[3:] for line in status.splitlines() if line.strip())


def live(repo: Path, meta: dict) -> dict:
    """Provenance at the end of `aem eval` (values read now, from the environment that ran it)."""
    repo = Path(repo)
    commit = _git(repo, "rev-parse", "HEAD") or NOT_RECORDED
    return {
        "run_id": meta["run_id"], "reconstructed": False, "fake": meta.get("fake", NOT_RECORDED),
        "written": datetime.now(timezone.utc).isoformat(timespec="seconds"), "written_by": "aem eval",
        "code": {"commit": commit, "uncommitted_changes_in_frozen_files": _dirty_frozen(repo)},
        "model": {"name": meta["model"], "versions_reported_by_api": meta.get("model_versions") or NOT_RECORDED,
                  "temperature": meta.get("temperature", NOT_RECORDED)},
        "attack": _attack(repo, meta.get("attack_version", NOT_RECORDED)),
        "prompt_templates_sha256": meta.get("prompt_templates_sha256", NOT_RECORDED),
        "frozen_files_sha256": file_hashes(repo),
        "python": platform.python_version(), "dependencies": dependency_versions(),
        "sources": {"all": "leído por `aem eval` al terminar la evaluación, en la misma máquina y entorno"},
    }


def write(results_dir: Path, data: dict, prefix: str = "") -> Path:
    path = Path(results_dir) / f"{prefix}provenance.json"
    write_json(path, data)
    return path


# --- reconstruction -------------------------------------------------------------------------------


def _commit_at(repo: Path, when: str) -> dict | str:
    """Last commit created before `when` (ISO time): what HEAD most likely was. The working tree is not known."""
    line = _git(repo, "log", "-1", f"--before={when}", "--format=%H %cI %s")
    if not line:
        return NOT_RECORDED
    sha, date, subject = line.split(" ", 2)
    return {"commit": sha, "committed": date, "subject": subject}


def _code_commits_between(repo: Path, start: str, end: str) -> list[dict]:
    out = _git(repo, "log", "--reverse", f"--after={start}", f"--before={end}", "--format=%H %cI %s", "--",
               *FROZEN_CODE, *FROZEN_FILES) or ""
    return [dict(zip(("commit", "committed", "subject"), line.split(" ", 2))) for line in out.splitlines() if line]


def reconstruct(run_dir: Path, repo: Path) -> dict:
    run_dir, repo = Path(run_dir), Path(repo)
    results = json.loads((run_dir / "results" / "results.json").read_text(encoding="utf-8"))
    history_path = run_dir / "eval_history.json"
    history = json.loads(history_path.read_text(encoding="utf-8")) if history_path.exists() else []
    rel = (run_dir / "results" / "results.json").relative_to(repo).as_posix()
    published = (_git(repo, "log", "--format=%H %cI %s", "--", rel) or "").splitlines()
    published = [dict(zip(("commit", "committed", "subject"), line.split(" ", 2))) for line in published]
    invocations = []
    for entry in history:
        head = _commit_at(repo, entry["started"])
        after = published[0]["committed"] if published else datetime.now(timezone.utc).isoformat()
        # the next commit that published results after this invocation
        nxt = next((p for p in reversed(published) if p["committed"] >= _local(entry["finished"], p["committed"])),
                   None)
        invocations.append({
            "started": entry["started"], "finished": entry["finished"],
            "status": entry.get("status") or NOT_RECORDED, "runs_completed": entry.get("runs_completed", NOT_RECORDED),
            "head_commit_before_start": head,
            "working_tree": NOT_RECORDED,
            "code_commits_after_start_until_results_commit": _code_commits_between(
                repo, entry["started"], nxt["committed"] if nxt else after),
            "results_committed_in": nxt["commit"] if nxt else NOT_RECORDED,
        })
    outputs = {}
    for scenario_dir in sorted(p for p in run_dir.iterdir() if p.is_dir() and p.name not in ("results", "private")):
        commits = (_git(repo, "log", "--format=%H %cI", "--", scenario_dir.relative_to(repo).as_posix()) or "").split()
        outputs[scenario_dir.name] = {"versioned_in_commit": commits[0] if commits else NOT_RECORDED,
                                      "source": "`git log` de la carpeta de la corrida"}
    private = run_dir / "private"
    for scenario_dir in sorted(p for p in private.iterdir() if p.is_dir()) if private.exists() else []:
        times = sorted(datetime.fromtimestamp(f.stat().st_mtime, timezone.utc).isoformat(timespec="seconds")
                       for f in scenario_dir.rglob("run_record.json"))
        outputs[scenario_dir.name] = {
            "versioned_in_commit": "no se versiona (texto con derechos de autor, D-69)",
            "run_record_mtime_utc": [times[0], times[-1]] if times else NOT_RECORDED,
            "source": "fecha de modificación de los archivos locales (cambia si se copian o restauran)"}
    final = invocations[-1] if invocations else None
    final_publish = published[0]["commit"] if published else None
    hashes = {}
    for p in FROZEN_FILES:
        current = (repo / p).read_bytes() if (repo / p).exists() else None
        at_head = (_git_blob(repo, final["head_commit_before_start"]["commit"], p)
                   if final and isinstance(final["head_commit_before_start"], dict) else None)
        at_publish = _git_blob(repo, final_publish, p) if final_publish else None
        hashes[p] = {
            "at_head_before_final_eval": _sha(at_head) if at_head is not None else NOT_RECORDED,
            "at_results_commit": _sha(at_publish) if at_publish is not None else NOT_RECORDED,
            "current": _sha(current) if current is not None else "no existe",
        }
    prompts_now = "; ".join(f"{Path(p).name}={hashes[p]['current']}" for p in FROZEN_FILES[:2])
    return {
        "run_id": results.get("run_id", run_dir.name), "reconstructed": True,
        "written": datetime.now(timezone.utc).isoformat(timespec="seconds"), "written_by": "aem provenance",
        "code": {
            "commit": NOT_RECORDED,
            "note": "El commit y el estado del árbol de trabajo no se registraron al evaluar. Para cada ejecución de "
                    "`aem eval` se da el último commit anterior a su inicio y los commits de código o de archivos "
                    "congelados hechos entre ese inicio y el commit que publicó los resultados: si hay alguno, la "
                    "ejecución pudo usar esos cambios sin commit todavía.",
            "invocations": invocations,
            "results_commits": published,
            "per_run_outputs": outputs,
        },
        "model": {"name": results.get("model", NOT_RECORDED),
                  "versions_reported_by_api": results.get("model_versions") or NOT_RECORDED,
                  "temperature": results.get("temperature", NOT_RECORDED)},
        "attack": dict(_attack(repo, results.get("attack_version", NOT_RECORDED)),
                       note="El SHA-256 es el del archivo local actual; no se registró al evaluar. `aem fetch-data` "
                            "solo acepta el archivo si coincide con `expected_sha256`."),
        "prompt_templates_sha256": results.get("prompt_templates_sha256", NOT_RECORDED),
        "prompt_templates_match_current_files": results.get("prompt_templates_sha256") == prompts_now,
        "frozen_files_sha256": hashes,
        "python": NOT_RECORDED, "dependencies": NOT_RECORDED,
        "sources": {
            "model, attack.version, prompt_templates_sha256": "results/results.json (escrito por `aem eval`)",
            "code.invocations": "eval_history.json (horas de cada `aem eval`) cruzado con `git log`",
            "code.results_commits": "`git log` de results/results.json",
            "code.per_run_outputs": "`git log` de cada carpeta versionada; fecha de modificación para private/",
            "attack.sha256": "archivo local actual; attack.expected_sha256: data/attack/CHECKSUMS.sha256",
            "frozen_files_sha256": "`git show <commit>:<archivo>` en el último commit antes de la ejecución final y "
                                   "en el commit de resultados, más el archivo actual",
            "python, dependencies": "no se registraron al evaluar; las del entorno actual no prueban las de la "
                                    "corrida",
        },
    }


def _local(when: str, like: str) -> str:
    """`when` (UTC ISO) in the UTC offset of `like`, so that both compare as strings."""
    t = datetime.fromisoformat(when)
    off = datetime.fromisoformat(like).utcoffset() or timedelta(0)
    return t.astimezone(timezone(off)).isoformat(timespec="seconds")


def summary_lines(data: dict) -> list[tuple[str, str]]:
    """Short block for `aem report` and the HTML page: (label, value)."""
    code = data.get("code", {})
    if data.get("reconstructed"):
        commits = []
        for inv in code.get("invocations", []):
            head = inv.get("head_commit_before_start")
            if isinstance(head, dict):
                commits.append(head["commit"][:7])
            commits += [c["commit"][:7] for c in inv.get("code_commits_after_start_until_results_commit", [])]
        code_text = (f"no registrado; reconstruido de git: {', '.join(dict.fromkeys(commits)) or NOT_RECORDED}")
    else:
        dirty = code.get("uncommitted_changes_in_frozen_files")
        code_text = f"{str(code.get('commit', NOT_RECORDED))[:12]}" + (
            f" (con cambios sin commit: {', '.join(dirty)})" if isinstance(dirty, list) and dirty else "")
    model = data.get("model", {})
    attack = data.get("attack", {})
    deps = data.get("dependencies")
    files = data.get("frozen_files_sha256", {})
    changed = [p for p, h in files.items() if isinstance(h, dict) and h.get("at_results_commit") != h.get("current")]
    return [
        ("Procedencia", "reconstruida (`aem provenance`)" if data.get("reconstructed") else "registrada por `aem eval`"),
        ("Código", code_text),
        ("Modelo", f"{model.get('name', NOT_RECORDED)} ({'; '.join(model.get('versions_reported_by_api') or []) if isinstance(model.get('versions_reported_by_api'), list) else NOT_RECORDED})"),
        ("ATT&CK", f"{attack.get('version', NOT_RECORDED)} · SHA-256 {str(attack.get('sha256', NOT_RECORDED))[:16]}… "
                   f"(coincide con el esperado: {attack.get('matches_expected', NOT_RECORDED)})"),
        ("Python", str(data.get("python", NOT_RECORDED))),
        ("Dependencias", ", ".join(f"{k} {v}" for k, v in deps.items()) if isinstance(deps, dict) else str(deps)),
        ("Archivos congelados", (f"{len(files)} con SHA-256" + (f"; cambiaron después del commit de resultados: "
                                                                 f"{', '.join(changed)}" if changed else ""))
         if files else NOT_RECORDED),
    ]
