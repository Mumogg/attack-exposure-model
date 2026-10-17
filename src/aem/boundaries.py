"""Detection of evaluative language in AI output (indicator 5, summary filter)."""

from __future__ import annotations

import re
from pathlib import Path

from aem.config import BOUNDARY_PATTERNS_FILE, load_yaml


def load_patterns(path: Path = BOUNDARY_PATTERNS_FILE) -> list[re.Pattern]:
    return [re.compile(p, re.IGNORECASE) for p in load_yaml(path)["patterns"]]


def find_evaluative(text: str, patterns: list[re.Pattern]) -> list[str]:
    return [m.group(0) for p in patterns for m in [p.search(text or "")] if m]


def violations(generated: str, source: str, patterns: list[re.Pattern]) -> list[str]:
    """Evaluative matches in `generated` whose pattern does not occur in `source` (D-65)."""
    return [m.group(0) for p in patterns for m in [p.search(generated or "")] if m and not p.search(source or "")]
