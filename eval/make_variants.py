"""`mut` variant of a report: same behavior, different indicators (indicator 3).

Hashes → random hex of the same length and case; IPv4 → RFC 5737 documentation
ranges; domains (also URL hosts and every plain mention of a detected one) →
random `.invalid` names; e-mail local parts → random letters; hashes inside any
URL too; qTox IDs → random characters of the same length; accounts → `acct-` +
random letters. Everything else is left byte-for-byte intact. The
seed is fixed and recorded with a diff. `check_variant` verifies that no IoC
of the original survives in the variant (D-66, D-70).

`anon` = `mut` + the threat's own names (actor, ransomware family, malware) replaced
consistently by generic ones (ActorX, LoaderX…) from `data/anon_names.yaml`;
`check_anon` verifies that none survives (D-72).
"""

from __future__ import annotations

import difflib
import ipaddress
import random
import re
import string

from dataclasses import dataclass
from pathlib import Path

import yaml

from aem.config import ANON_NAMES_FILE, IocConfig, ModelConfig, load_yaml
from aem.output import write_json
from eval.baseline_ioc import _HASH, _HASH_TYPES, DOT, Ioc, extract_iocs, refang, scan, select_known_iocs, url_host

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
        self.locals: dict[str, str] = {}

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

    def local(self, raw: str) -> str:
        """Local part of an e-mail address (review A6)."""
        key = raw.lower()
        while key not in self.locals:
            name = "".join(self.rng.choice(string.ascii_lowercase) for _ in range(10))
            if name not in self.locals.values():
                self.locals[key] = name
        return self.locals[key]

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


_HEX_RUN = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{32,}(?![0-9a-fA-F])")


def _with_mentions(text: str, cfg: IocConfig) -> list[tuple[Ioc, bool]]:
    """`scan` results plus every other mention of a detected value (also URL hosts), defanged or not.

    E.g. a domain listed defanged in a table and written plainly in a sentence (D-66). Tokens that
    are only IoC-like when written plainly (file names, services, versions) are not mentions (review A1).
    """
    found = scan(text, cfg)
    taken = [(i.start, i.end) for i, _ in found]
    iocs = [i for i, excluded in found if not excluded]
    values = {(i.type, i.value) for i in iocs if i.type in ("domain", "ipv4", "email")}
    for i in iocs:
        if i.type == "url":
            hs, he = url_host(i.raw)
            host = refang(i.raw[hs:he]).lower()
            values.add(("ipv4" if re.fullmatch(r"[\d.]+", host) else "domain", host))
    for kind, value in sorted(values):
        pattern = DOT.join(re.escape(part) for part in value.split("."))
        for m in re.finditer(rf"(?<![\w.@-]){pattern}(?![\w-]|\.[a-z0-9])", text, re.IGNORECASE):
            if all(m.end() <= a or m.start() >= b for a, b in taken):
                taken.append(m.span())
                found.append((Ioc(kind, value, m.group(0), *m.span()), False))
    return sorted(found, key=lambda x: x[0].start)


def make_variant(text: str, cfg: IocConfig, seed: int, salt: str) -> tuple[str, list[dict]]:
    mapper = _Mapper(seed, salt)
    out: list[str] = []
    mapping: dict[tuple[str, str], dict] = {}
    pos = 0

    def path_hashes(path: str) -> str:  # hashes inside any URL, also reference links (review A1)
        return _HASH.sub(lambda h: _remember(mapping, _HASH_TYPES[len(h.group(0))], h.group(0).lower(), h.group(0),
                                             mapper.hash(h.group(0))), path)

    for ioc, excluded in _with_mentions(text, cfg):
        if ioc.type == "url":
            hs, he = url_host(ioc.raw)
            if excluded:
                new = ioc.raw[:he] + path_hashes(ioc.raw[he:])
                if new == ioc.raw:
                    continue
                out += [text[pos:ioc.start], new]
                pos = ioc.end
                continue
            new = ioc.raw[:hs] + mapper.host(ioc.raw[hs:he]) + path_hashes(ioc.raw[he:])
        elif excluded:
            continue
        elif ioc.type == "ipv4":
            new = mapper.ip(ioc.raw)
        elif ioc.type == "domain":
            new = mapper.domain(ioc.raw)
        elif ioc.type == "account":
            new = mapper.account(ioc.raw)
        elif ioc.type == "email":
            local, domain = ioc.raw.split("@", 1)
            new = f"{mapper.local(local)}@{mapper.domain(domain)}"
        else:
            new = mapper.hash(ioc.raw)
        out += [text[pos:ioc.start], new]
        pos = ioc.end
        _remember(mapping, ioc.type, ioc.value, ioc.raw, new)
    out.append(text[pos:])
    return "".join(out), list(mapping.values())


def _remember(mapping: dict, kind: str, value: str, raw: str, new: str) -> str:
    """One entry per (type, normalized value), with every spelling seen (review A7)."""
    entry = mapping.setdefault((kind, value), {"type": kind, "value": value, "original": raw, "replacement": new,
                                               "spellings": [], "occurrences": 0})
    if raw not in entry["spellings"]:
        entry["spellings"].append(raw)
    entry["occurrences"] += 1
    return new


def _refanged(text: str) -> str:
    return re.sub(r"hxxp", "http", text.replace("[.]", ".").replace("[:]", ":"), flags=re.IGNORECASE)


def _find(values: dict[str, str], variant: str) -> list[dict]:
    haystack = _refanged(variant)
    hits = []
    for value, kind in values.items():
        m = re.search(rf"(?<![\w-]){re.escape(value)}(?![\w-])", haystack, re.IGNORECASE)
        if m:
            hits.append({"type": kind, "value": value, "line": haystack.count("\n", 0, m.start()) + 1})
    return sorted(hits, key=lambda x: (x["line"], x["value"]))


def _ioc_values(original: str, cfg: IocConfig) -> dict[str, str]:
    """Every IoC value of the original (D-63 rules) plus URL hosts and any run of >= 32 hex characters."""
    wanted: dict[str, str] = {}
    for ioc in extract_iocs(original, cfg):
        wanted.setdefault(ioc.value.lower(), ioc.type)
        if ioc.type == "url":
            hs, he = url_host(ioc.raw)
            wanted.setdefault(refang(ioc.raw[hs:he]).lower(), "url_host")
    for m in _HEX_RUN.finditer(original):
        wanted.setdefault(m.group(0).lower(), _HASH_TYPES.get(len(m.group(0)), "hex"))
    return wanted


def check_variant(original: str, variant: str, cfg: IocConfig) -> list[dict]:
    """IoCs of the original still present in the variant, with the variant line where each appears.

    Each value is searched in the variant defanged or not and case-insensitively.
    """
    return _find(_ioc_values(original, cfg), variant)


def plain_candidates(original: str, variant: str, cfg: IocConfig) -> list[dict]:
    """IoC-like tokens written only without defang that remain in the variant, for a manual look at the diff.

    They are not replaced: most are file names, services or reference links (review A1).
    """
    known = _ioc_values(original, cfg)
    loose = cfg.model_copy(update={"require_defang": False})
    extra = {i.value.lower(): i.type for i in extract_iocs(original, loose) if i.value.lower() not in known}
    return _find(extra, variant)


@dataclass(frozen=True)
class AnonName:
    name: str
    replacement: str
    role: str = ""


def load_anon_names(path: Path = ANON_NAMES_FILE) -> dict[str, list[AnonName]]:
    return {sc: [AnonName(str(d["name"]), str(d["replacement"]), str(d.get("role", ""))) for d in items or []]
            for sc, items in load_yaml(path).items()}


def _name_pattern(name: str) -> str:
    """Whole name, case-insensitive, never inside another word; a space also matches a URL-slug hyphen."""
    body = r"[\s-]+".join(re.escape(w) for w in name.split())
    return rf"(?<![A-Za-z]){body}(?![A-Za-z])"


def anonymize(text: str, names: list[AnonName]) -> tuple[str, list[dict]]:
    ordered = sorted(names, key=lambda n: -len(n.name))  # longest first: "Interlock RAT" before "Interlock"
    pattern = re.compile("|".join(f"(?P<n{i}>{_name_pattern(n.name)})" for i, n in enumerate(ordered)),
                         re.IGNORECASE)
    counts = {n.name: 0 for n in names}

    def sub(m: re.Match) -> str:
        n = ordered[int(m.lastgroup[1:])]
        counts[n.name] += 1
        return n.replacement

    new = pattern.sub(sub, text) if names else text
    return new, [{"name": n.name, "replacement": n.replacement, "role": n.role, "occurrences": counts[n.name]}
                 for n in names]


def check_anon(text: str, names: list[AnonName]) -> list[dict]:
    """Original names still present (first line where each appears)."""
    leaks = []
    for n in names:
        m = re.search(_name_pattern(n.name), text, re.IGNORECASE)
        if m:
            leaks.append({"name": n.name, "line": text.count("\n", 0, m.start()) + 1})
    return sorted(leaks, key=lambda x: (x["line"], x["name"]))


def unified_diff(original: str, variant: str, name: str) -> str:
    return "".join(difflib.unified_diff(original.splitlines(keepends=True), variant.splitlines(keepends=True),
                                        fromfile=f"{name} (orig)", tofile=f"{name} (mut)"))


def build_variants(scenarios: dict, model_cfg: ModelConfig, known_iocs_path: Path,
                   anon_names_path: Path = ANON_NAMES_FILE, private_known_iocs_path: Path | None = None) -> list[dict]:
    """`mut` and `anon` versions of every prepared scenario + the organization's generated known IoCs (D-62).
    Known IoCs of copyrighted scenarios go only to `private_known_iocs_path` (git-ignored, D-76)."""
    all_names = load_anon_names(anon_names_path)
    logs, known, known_private = [], [], []
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
        candidates = plain_candidates(original, variant, model_cfg.ioc)
        sc.variant.write_text(variant, encoding="utf-8")
        sc.variant_diff.write_text(unified_diff(original, variant, sc.stripped.name), encoding="utf-8")
        counts = {t: sum(m["type"] == t for m in mapping) for t in sorted({m["type"] for m in mapping})}
        occurrences = sum(m["occurrences"] for m in mapping)
        log = {"scenario": sc.name, "seed": seed, "salt": sc.name, "source": sc.stripped.name,
               "variant": sc.variant.name, "replacements_by_type": counts,
               "unique_replaced": len(mapping), "occurrences_replaced": occurrences, "leak_check": "ok",
               "plain_candidates_kept": candidates, "mapping": mapping}
        write_json(sc.variant_log, log)

        if not all_names.get(sc.name):
            raise ValueError(f"No hay nombres para la versión anon de {sc.name} en {anon_names_path}")
        names = all_names[sc.name]
        anon, name_log = anonymize(variant, names)
        problems = [f"nombre {x['name']} (línea {x['line']})" for x in check_anon(anon, names)]
        problems += [f"{x['type']} {x['value']} (línea {x['line']})" for x in check_variant(original, anon, model_cfg.ioc)]
        if problems:
            raise VariantLeak(f"La versión anon de {sc.name} aún contiene: " + "; ".join(problems))
        sc.anon.write_text(anon, encoding="utf-8")
        sc.anon_diff.write_text(unified_diff(original, anon, sc.stripped.name).replace(" (mut)", " (anon)"),
                                encoding="utf-8")
        write_json(sc.anon_log, {"scenario": sc.name, "source": sc.variant.name, "anon": sc.anon.name,
                                 "names_file": Path(anon_names_path).name, "names": name_log,
                                 "names_replaced": sum(e["occurrences"] for e in name_log), "leak_check": "ok",
                                 "ioc_replacements": f"ver {sc.variant_log.name}"})
        log["anon"] = {"file": sc.anon.name, "names_replaced": sum(e["occurrences"] for e in name_log),
                       "names_absent": [e["name"] for e in name_log if not e["occurrences"]]}
        logs.append(log)
        selected = select_known_iocs(extract_iocs(original, model_cfg.ioc), model_cfg.baseline, scenario=sc.name)
        (known_private if sc.copyrighted else known).extend(selected)
    if known_private and private_known_iocs_path is None:
        raise ValueError("Hay IoC de un escenario con derechos de autor y no se indicó el archivo privado (D-76).")
    b = model_cfg.baseline
    policy = {"known_ioc_fraction": b.known_ioc_fraction, "min_matches": b.min_matches, "seed": b.seed,
              "source": "versión orig (stripped) de cada escenario"}
    doc = {"note": "Generado por `aem make-variants`; no editar a mano (docs/DECISIONS.md D-62).",
           "policy": policy, "known_iocs": [k.model_dump() for k in known]}
    Path(known_iocs_path).write_text(yaml.safe_dump(doc, allow_unicode=True, sort_keys=False), encoding="utf-8")
    if known_private:
        private = Path(private_known_iocs_path)
        private.parent.mkdir(parents=True, exist_ok=True)
        doc = {"note": "Generado por `aem make-variants`; IoC de escenarios con derechos de autor. NO versionar "
                       "(docs/DECISIONS.md D-76).",
               "policy": policy, "known_iocs": [k.model_dump() for k in known_private]}
        private.write_text(yaml.safe_dump(doc, allow_unicode=True, sort_keys=False), encoding="utf-8")
    return logs
