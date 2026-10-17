"""Loading of the organization profile YAML."""

from __future__ import annotations

from pathlib import Path

from aem.config import load_yaml
from aem.models import OrgProfile


def load_org(path: Path) -> OrgProfile:
    """Load and validate the org YAML; merge the generated known-IoC file if it exists (D-62)."""
    path = Path(path)
    data = load_yaml(path)
    ioc_file = data.get("known_iocs_file")
    if ioc_file:
        gen = path.parent / ioc_file
        if gen.exists():
            data["known_iocs"] = list(data.get("known_iocs") or []) + list(load_yaml(gen).get("known_iocs") or [])
    return OrgProfile.model_validate(data)
