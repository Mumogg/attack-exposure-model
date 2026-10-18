"""`mut` variant of a report: same behavior, different indicators (indicator 3).

Hashes → random hex of the same length and case; IPv4 → RFC 5737 documentation
ranges; domains (also URL hosts) → random `.invalid` names; hashes inside URL
paths too; qTox IDs → random characters of the same length; accounts →
`acct-` + random letters. Everything else is left byte-for-byte intact. The
seed is fixed and recorded with a diff. `check_variant` verifies that no IoC
of the original survives in the variant (D-66, D-70).
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
from eval.baseline_ioc import _HASH, DOT, Ioc, extract_iocs, refang, scan, select_known_iocs, url_host

DOC_NETWORKS = tuple(ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))


def _restyle(raw: str, new: str) -> str:
    """Keep the defang style of the original: same separator in the same position when possible."""
    seps = re.findall(r"\[\.\]|\.", raw)
    parts = new.split(".")
    if len(parts) - 1 == len(seps):
        return "".join(p + (seps[i] if i < len(seps) else "") for i, p in enumerate(parts))
    return new.replace(".", "[.]") if "[.]" in raw else new


class VariantLeak(ValueError):
    """An IoC of the original report is still present in the mut variant."""


def variant_ioc_config(model_cfg: ModelConfig) -> IocConfig:
    """IoC rules used to build the variant: the baseline's rules, but optionally without requiring defang."""
    return model_cfg.ioc.model_copy(update={"require_defang": model_cfg.variants.require_defang})


class _Mapper:
    def __init__(self, seed: int, salt: str):
        self.rng = random.Random(f"{seed}:{salt}")
        pool = [str(h) for net in DOC_NETWORKS for h in net.hosts()]
        self.rng.shuffle(pool)
        self.ip_pool = pool
        self.ips: dict[str, str] = {}
        self.domains: dict[str, str] = {}
        self.hashes: dict[str, str] = {}
        self.accounts: dict[str, str] = {}

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

    def account(self, raw: str) -> str:
        key = raw.lower()
        while key not in self.accounts:
            name = "acct-" + "".join(self.rng.choice(string.ascii_lowercase) for _ in range(8))
            if name not in self.accounts.values():
                self.accounts[key] = name
        return self.accounts[key]

    def host(self, raw: str) -> str:
        try:
            ipaddress.ip_address(refang(raw))
            return self.ip(raw)
        except ValueError:
            return self.domain(raw)


def _with_mentions(text: str, cfg: IocConfig) -> list[Ioc]:
    """IoCs found by `scan` plus every other mention of the same value, defanged or not.

    E.g. a domain listed defanged in a table and written plainly in a sentence (D-66).
    """
    found = scan(text, cfg)
    taken = [(i.start, i.end) for i, _ in found]
    iocs = [i for i, excluded in found if not excluded]
    for kind, value in sorted({(i.type, i.value) for i in iocs if i.type in ("domain", "ipv4", "email")}):
        pattern = DOT.join(re.escape(part) for part in value.split("."))
        for m in re.finditer(rf"(?<![\w.@-]){pattern}(?![\w-]|\.[a-z0-9])", text, re.IGNORECASE):
            if all(m.end() <= a or m.start() >= b for a, b in taken):
                taken.append(m.span())
                iocs.append(Ioc(kind, value, m.group(0), *m.span()))
    return sorted(iocs, key=lambda i: i.start)


def make_variant(text: str, cfg: IocConfig, seed: int, salt: str) -> tuple[str, list[dict]]:
    mapper = _Mapper(seed, salt)
    out: list[str] = []
    mapping: dict[str, dict] = {}
    pos = 0
    for ioc in _with_mentions(text, cfg):
        if ioc.type == "url":
            hs, he = url_host(ioc.raw)
            path = _HASH.sub(lambda h: _remember(mapping, "hash_in_url", h.group(0), mapper.hash(h.group(0))),
                             ioc.raw[he:])
            new = ioc.raw[:hs] + mapper.host(ioc.raw[hs:he]) + path
        elif ioc.type == "ipv4":
            new = mapper.ip(ioc.raw)
        elif ioc.type == "domain":
            new = mapper.domain(ioc.raw)
        elif ioc.type == "account":
            new = mapper.account(ioc.raw)
        elif ioc.type == "email":
            local, domain = ioc.raw.split("@", 1)
            new = f"{local}@{mapper.domain(domain)}"
        else:
            new = mapper.hash(ioc.raw)
        out += [text[pos:ioc.start], new]
        pos = ioc.end
        _remember(mapping, ioc.type, ioc.raw, new)
    out.append(text[pos:])
    return "".join(out), list(mapping.values())


def _remember(mapping: dict, kind: str, raw: str, new: str) -> str:
    mapping.setdefault(raw, {"type": kind, "original": raw, "replacement": new, "occurrences": 0})["occurrences"] += 1
    return new


def check_variant(original: str, variant: str, cfg: IocConfig) -> list[dict]:
    """IoCs of the original still present in the variant, with the variant line where each appears.

    Searches the original with the strict rules and without requiring defang, plus every hash-like
    token (also inside URLs); each is looked for in the variant refanged and case-insensitively.
    """
    loose = cfg.model_copy(update={"require_defang": False})
    wanted: dict[str, str] = {}
    for rules in (cfg, loose):
        for ioc in extract_iocs(original, rules):
            wanted.setdefault(ioc.value.lower(), ioc.type)
    for m in _HASH.finditer(refang(original)):
        wanted.setdefault(m.group(0).lower(), "hash")
    haystack = re.sub(r"hxxp", "http", variant.replace("[.]", ".").replace("[:]", ":"), flags=re.IGNORECASE)
    leaks = []
    for value, kind in wanted.items():
        m = re.search(rf"(?<![\w-]){re.escape(value)}(?![\w-])", haystack, re.IGNORECASE)
        if m:
            leaks.append({"type": kind, "value": value, "line": haystack.count("\n", 0, m.start()) + 1})
    return sorted(leaks, key=lambda x: (x["line"], x["value"]))


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
        variant, mapping = make_variant(original, variant_ioc_config(model_cfg), seed=seed, salt=sc.name)
        leaks = check_variant(original, variant, model_cfg.ioc)
        if leaks:
            detail = "; ".join(f"{x['type']} {x['value']} (línea {x['line']})" for x in leaks)
            raise VariantLeak(f"La variante mut de {sc.name} aún contiene IoC del original: {detail}")
        sc.variant.write_text(variant, encoding="utf-8")
        sc.variant_diff.write_text(unified_diff(original, variant, sc.stripped.name), encoding="utf-8")
        counts = {t: sum(m["type"] == t for m in mapping) for t in sorted({m["type"] for m in mapping})}
        occurrences = sum(m["occurrences"] for m in mapping)
        log = {"scenario": sc.name, "seed": seed, "salt": sc.name, "source": sc.stripped.name,
               "variant": sc.variant.name, "replacements_by_type": counts,
               "unique_replaced": len(mapping), "occurrences_replaced": occurrences, "leak_check": "ok", "mapping": mapping}
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
