"""`mut` variant of a report: same behavior, different indicators (indicator 3).

Hashes → random hex of the same length and case; IPv4 → RFC 5737 documentation
ranges; domains (also URL hosts) → random `.invalid` names. Everything else is
left byte-for-byte intact. The seed is fixed and recorded with a diff.
"""

from __future__ import annotations

import difflib
import ipaddress
import random
import re
import string

from pathlib import Path

import yaml

from aem.config import IocConfig, ModelConfig
from aem.output import write_json
from eval.baseline_ioc import extract_iocs, refang, scan, select_known_iocs, url_host

DOC_NETWORKS = tuple(ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))


def _restyle(raw: str, new: str) -> str:
    """Keep the defang style of the original: same separator in the same position when possible."""
    seps = re.findall(r"\[\.\]|\.", raw)
    parts = new.split(".")
    if len(parts) - 1 == len(seps):
        return "".join(p + (seps[i] if i < len(seps) else "") for i, p in enumerate(parts))
    return new.replace(".", "[.]") if "[.]" in raw else new


class _Mapper:
    def __init__(self, seed: int, salt: str):
        self.rng = random.Random(f"{seed}:{salt}")
        pool = [str(h) for net in DOC_NETWORKS for h in net.hosts()]
        self.rng.shuffle(pool)
        self.ip_pool = pool
        self.ips: dict[str, str] = {}
        self.domains: dict[str, str] = {}
        self.hashes: dict[str, str] = {}

    def ip(self, raw: str) -> str:
        key = refang(raw)
        if key not in self.ips:
            if not self.ip_pool:
                raise ValueError("Se agotaron las direcciones de documentación RFC 5737")
            self.ips[key] = self.ip_pool.pop()
        return _restyle(raw, self.ips[key])

    def domain(self, raw: str) -> str:
        key = refang(raw).lower()
        while key not in self.domains:
            name = "".join(self.rng.choice(string.ascii_lowercase) for _ in range(10)) + ".invalid"
            if name not in self.domains.values():
                self.domains[key] = name
        return _restyle(raw, self.domains[key])

    def hash(self, raw: str) -> str:
        key = raw.lower()
        if key not in self.hashes:
            self.hashes[key] = "".join(self.rng.choice("0123456789abcdef") for _ in raw)
        new = self.hashes[key]
        return new.upper() if raw.isupper() else new

    def host(self, raw: str) -> str:
        try:
            ipaddress.ip_address(refang(raw))
            return self.ip(raw)
        except ValueError:
            return self.domain(raw)


def make_variant(text: str, cfg: IocConfig, seed: int, salt: str) -> tuple[str, list[dict]]:
    mapper = _Mapper(seed, salt)
    out: list[str] = []
    mapping: dict[str, dict] = {}
    pos = 0
    for ioc, excluded in scan(text, cfg):
        if excluded:
            continue
        if ioc.type == "url":
            hs, he = url_host(ioc.raw)
            new = ioc.raw[:hs] + mapper.host(ioc.raw[hs:he]) + ioc.raw[he:]
        elif ioc.type == "ipv4":
            new = mapper.ip(ioc.raw)
        elif ioc.type == "domain":
            new = mapper.domain(ioc.raw)
        elif ioc.type == "email":
            local, domain = ioc.raw.split("@", 1)
            new = f"{local}@{mapper.domain(domain)}"
        else:
            new = mapper.hash(ioc.raw)
        out += [text[pos:ioc.start], new]
        pos = ioc.end
        mapping.setdefault(ioc.raw, {"type": ioc.type, "original": ioc.raw, "replacement": new})
    out.append(text[pos:])
    return "".join(out), list(mapping.values())


def unified_diff(original: str, variant: str, name: str) -> str:
    return "".join(difflib.unified_diff(original.splitlines(keepends=True), variant.splitlines(keepends=True),
                                        fromfile=f"{name} (orig)", tofile=f"{name} (mut)"))


def build_variants(scenarios: dict, model_cfg: ModelConfig, known_iocs_path: Path) -> list[dict]:
    """`mut` variant of every prepared scenario + the organization's generated known IoCs (D-62)."""
    logs, known = [], []
    seed = model_cfg.variants.seed
    for sc in scenarios.values():
        if not sc.stripped.exists():
            continue
        original = sc.stripped.read_text(encoding="utf-8")
        variant, mapping = make_variant(original, model_cfg.ioc, seed=seed, salt=sc.name)
        sc.variant.write_text(variant, encoding="utf-8")
        sc.variant_diff.write_text(unified_diff(original, variant, sc.stripped.name), encoding="utf-8")
        counts = {t: sum(m["type"] == t for m in mapping) for t in sorted({m["type"] for m in mapping})}
        log = {"scenario": sc.name, "seed": seed, "salt": sc.name, "source": sc.stripped.name,
               "variant": sc.variant.name, "replacements_by_type": counts, "mapping": mapping}
        write_json(sc.variant_log, log)
        logs.append(log)
        known += select_known_iocs(extract_iocs(original, model_cfg.ioc), model_cfg.baseline, scenario=sc.name)
    b = model_cfg.baseline
    doc = {
        "note": "Generado por `aem make-variants`; no editar a mano (docs/DECISIONS.md D-62).",
        "policy": {"known_ioc_fraction": b.known_ioc_fraction, "min_matches": b.min_matches, "seed": b.seed,
                   "source": "versión orig (stripped) de cada escenario"},
        "known_iocs": [k.model_dump() for k in known],
    }
    Path(known_iocs_path).write_text(yaml.safe_dump(doc, allow_unicode=True, sort_keys=False), encoding="utf-8")
    return logs
