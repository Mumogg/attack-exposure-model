"""`aem check-repo`: nothing secret or copyrighted in the tracked files or anywhere in the git history.

Looks at every commit reachable from any ref plus the index (staged files) for:
- a committed `.env`, files inside a `private/` folder (D-69) and the DFIR report files;
- API-key patterns (the matched value is never printed);
- text of the DFIR report, found through distinctive phrases taken from the local copy;
- IoC values of the DFIR report (refanged and as written), also taken from the local copy (D-76).
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path, PurePosixPath

KEY_PATTERNS = {
    "API key de Google": r"AIza[0-9A-Za-z_-]{35}",
    "GEMINI_API_KEY con valor": r"GEMINI_API_KEY[ \t]*[=:][ \t]*['\"]?[A-Za-z0-9_-]{20,}",
    "clave privada": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
}
_ATTACK_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b|\bTA\d{4}\b")
_REV_BATCH = 50


def distinctive_phrases(text: str, count: int = 30, min_line: int = 120, length: int = 70) -> list[str]:
    """Fragments of prose lines spread over the text. Lines with ATT&CK IDs (technique lists, whose names
    are also in the reference mapping) and short lines (titles, table cells) are skipped."""
    lines = [" ".join(line.split()) for line in text.splitlines()]
    prose = [line for line in lines if len(line) >= min_line and not _ATTACK_ID.search(line)]
    if not prose:
        return []
    step = max(1, len(prose) // count)
    phrases = []
    for line in prose[::step][:count]:
        middle = len(line) // 2
        phrases.append(line[max(0, middle - length // 2): middle + length // 2].strip())
    return [p for p in phrases if len(p) >= 60]


def ioc_values(iocs, min_length: int = 7) -> list[str]:
    """Distinct IoC values, normalized and as written; very short ones are skipped to avoid false hits."""
    values = {v for i in iocs for v in (i.value, i.raw)}
    return sorted(v for v in values if len(v) >= min_length)


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, timeout=600)


def _out(res: subprocess.CompletedProcess) -> list[str]:
    return res.stdout.decode("utf-8", errors="replace").splitlines()


def _path_kind(path: str) -> str | None:
    p = PurePosixPath(path)
    if p.name == ".env":
        return "archivo .env versionado"
    if any(part in ("private", "llm_cache_private") for part in p.parts[:-1]):
        return "archivo dentro de una carpeta private/"
    if path.startswith("data/reports/akira_dfir_2026"):
        return "archivo del reporte de DFIR"
    return None


def _grep(repo: Path, revs: list[str], flag: str, patterns: list[str]) -> list[tuple[str, str, str]]:
    """(commit or 'índice', path, line) of every match; `flag` is -E (regex) or -F (fixed strings).
    Only locations are kept: the matched text (a key, a quote) is never stored or printed."""
    pattern_args = [a for p in patterns for a in ("-e", p)]
    hits = []
    for i in range(0, len(revs), _REV_BATCH):
        for line in _out(_git(repo, "grep", "-I", "-n", flag, *pattern_args, *revs[i:i + _REV_BATCH])):
            rev, path, num = line.split(":", 3)[:3]
            hits.append((rev, path, num))
    for line in _out(_git(repo, "grep", "-I", "-n", "--cached", flag, *pattern_args)):
        path, num = line.split(":", 2)[:2]
        hits.append(("índice", path, num))
    return hits


def _group(kind: str, hits: list[tuple[str, str, str]]) -> list[dict]:
    where: dict[tuple[str, str], list[str]] = {}
    for rev, path, num in hits:
        where.setdefault((path, num), [])
        label = rev if rev == "índice" else rev[:8]
        if label not in where[(path, num)]:
            where[(path, num)].append(label)
    out = []
    for (path, num), revs in sorted(where.items()):
        shown = ", ".join(revs[:5]) + (f" y {len(revs) - 5} más" if len(revs) > 5 else "")
        out.append({"kind": kind, "where": f"{path}:{num} (en {shown})"})
    return out


def check_repo(repo: Path, phrases: list[str], iocs: list[str] = ()) -> dict:
    repo = Path(repo)
    if _git(repo, "rev-parse", "--git-dir").returncode != 0:
        raise ValueError(f"{repo} no es un repositorio git")
    revs = _out(_git(repo, "rev-list", "--all"))
    findings: list[dict] = []

    # paths ever committed (with the commits that touch them) and paths in the index
    paths: dict[str, list[str]] = {}
    current = None
    for line in _out(_git(repo, "log", "--all", "--format=@%H", "--name-only")):
        if line.startswith("@"):
            current = line[1:]
        elif line.strip():
            paths.setdefault(line.strip(), []).append(current)
    for path in _out(_git(repo, "ls-files")):
        paths.setdefault(path, []).append("índice")
    by_kind: dict[str, list[tuple[str, str, str]]] = {}
    for path, commits in paths.items():
        kind = _path_kind(path)
        if kind:
            by_kind.setdefault(kind, []).extend((c, path, "-") for c in commits)
    for kind, hits in by_kind.items():
        findings += [dict(f, where=f["where"].replace(":- ", " ")) for f in _group(kind, hits)]

    for kind, pattern in KEY_PATTERNS.items():
        findings += _group(kind, _grep(repo, revs, "-E", [pattern]))
    if phrases:
        findings += _group("texto del reporte de DFIR", _grep(repo, revs, "-F", phrases))
    if iocs:
        findings += _group("IoC del reporte de DFIR", _grep(repo, revs, "-iF", list(iocs)))
    return {"findings": findings, "commits": len(revs), "phrases": len(phrases), "iocs": len(iocs)}
