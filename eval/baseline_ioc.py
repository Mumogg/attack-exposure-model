"""Traditional IoC-based approach (comparison baseline for indicator 3, D-62/D-63).

IoCs are extracted with regular expressions and compared with the organization's
`known_iocs`. With at least `baseline.min_matches` matches the threat is
"recognized" (all of its techniques); otherwise none. This is a deliberate
simplification, pending confirmation by Sebas.
"""

from __future__ import annotations

import math
import random
import re
import string
from dataclasses import dataclass

from aem.config import BaselineConfig, IocConfig
from aem.models import KnownIoc

DOT = r"(?:\.|\[\.\])"
_URL = re.compile(r"\b(?:https?|hxxps?)(?::|\[:\])//(?:\[\.\]|\[:\]|[^\s<>\"'()\[\]|])+", re.IGNORECASE)
_HASH = re.compile(r"(?<![0-9A-Za-z])(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})(?![0-9A-Za-z])")
_IPV4 = re.compile(rf"(?<![\d.])(?:\d{{1,3}}{DOT}){{3}}\d{{1,3}}(?!\d|\.\d)")
_LABELS = rf"(?:[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?{DOT})+[a-z]{{2,24}}"
_EMAIL = re.compile(rf"(?<![\w.+-])[\w.+-]+@{_LABELS}(?![\w-]|\.[a-z0-9])", re.IGNORECASE)
_DOMAIN = re.compile(rf"(?<![\w.-]){_LABELS}(?![\w-]|\.[a-z0-9])", re.IGNORECASE)
_QTOX = re.compile(r"(?<![0-9A-Za-z])[0-9A-Za-z]{76}(?![0-9A-Za-z])")
_HASH_TYPES = {32: "md5", 40: "sha1", 64: "sha256"}


@dataclass(frozen=True)
class Ioc:
    type: str  # md5 | sha1 | sha256 | ipv4 | domain | url | email | qtox | account
    value: str  # normalized (refanged, lower-case where case does not matter)
    raw: str
    start: int
    end: int


def refang(text: str) -> str:
    text = text.replace("[.]", ".").replace("[:]", ":")
    return re.sub(r"^hxxp", "http", text, flags=re.IGNORECASE)


def _valid_ipv4(raw: str) -> bool:
    return all(int(o) <= 255 for o in refang(raw).split("."))


def _defanged(raw: str) -> bool:
    return "[.]" in raw or "[:]" in raw or raw.lower().startswith("hxxp")


def _excluded(host: str, cfg: IocConfig) -> bool:
    host = host.lower()
    return any(host == d or host.endswith("." + d) for d in cfg.excluded_domains)


def url_host(raw_url: str) -> tuple[int, int]:
    """Span of the host inside a (possibly defanged) URL."""
    start = raw_url.index("//") + 2
    m = re.match(r"(?:\[\.\]|[^/:?#\[])+", raw_url[start:])
    return start, start + (m.end() if m else 0)


def _normalize_url(raw: str) -> str:
    url = refang(raw)
    scheme, rest = url.split("//", 1)
    host, sep, path = rest.partition("/")
    return f"{scheme.lower()}//{host.lower()}{sep}{path}"


def _is_qtox(raw: str, cfg: IocConfig) -> bool:
    """qTox ID: 76 characters, almost all hexadecimal (tolerates transcription typos, D-70)."""
    return sum(c in string.hexdigits for c in raw) >= cfg.qtox_min_hex


def table_accounts(text: str, columns: list[str]) -> list[str]:
    """Values of the markdown-table columns whose header is one of `columns` (case-insensitive)."""
    wanted = {c.strip().lower() for c in columns}
    found: list[str] = []
    col = None
    for line in text.splitlines():
        if not line.lstrip().startswith("|"):
            col = None
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        heads = [i for i, c in enumerate(cells) if c.lower() in wanted]
        if heads:
            col = heads[0]
        elif col is not None and col < len(cells) and cells[col] and not set(cells[col]) <= set("-: "):
            if cells[col] not in found:
                found.append(cells[col])
    return found


def scan(text: str, cfg: IocConfig) -> list[tuple[Ioc, bool]]:
    """All IoC-like spans with an `excluded` flag; excluded spans still block overlapping matches."""
    taken: list[tuple[int, int]] = []
    found: list[tuple[Ioc, bool]] = []

    def free(a: int, b: int) -> bool:
        return all(b <= s or a >= e for s, e in taken)

    for m in _URL.finditer(text):
        raw = m.group(0).rstrip(".,;:")
        a, b = m.start(), m.start() + len(raw)
        hs, he = url_host(raw)
        taken.append((a, b))
        excluded = _excluded(refang(raw[hs:he]), cfg) or (cfg.require_defang and not _defanged(raw))
        found.append((Ioc("url", _normalize_url(raw), raw, a, b), excluded))
    tlds = {t.lower() for t in cfg.domain_tlds}

    def plausible_host(raw: str) -> bool:
        if cfg.require_defang:
            return _defanged(raw)
        return _defanged(raw) or refang(raw).lower().rsplit(".", 1)[-1] in tlds

    for m in _EMAIL.finditer(text):
        domain_raw = m.group(0).split("@", 1)[1]
        if free(m.start(), m.end()) and plausible_host(domain_raw):
            taken.append(m.span())
            found.append((Ioc("email", refang(m.group(0)).lower(), m.group(0), *m.span()),
                          _excluded(refang(domain_raw), cfg)))
    for m in _HASH.finditer(text):
        if free(m.start(), m.end()):
            taken.append(m.span())
            found.append((Ioc(_HASH_TYPES[len(m.group(0))], m.group(0).lower(), m.group(0), *m.span()), False))
    for m in _IPV4.finditer(text):
        if free(m.start(), m.end()) and _valid_ipv4(m.group(0)) and \
                (_defanged(m.group(0)) or not cfg.require_defang):
            taken.append(m.span())
            found.append((Ioc("ipv4", refang(m.group(0)), m.group(0), *m.span()), False))
    for m in _DOMAIN.finditer(text):
        raw = m.group(0)
        if not free(m.start(), m.end()) or not plausible_host(raw):
            continue  # also file names such as main.exe or psexec.py (D-63)
        host = refang(raw).lower()
        taken.append(m.span())
        found.append((Ioc("domain", host, raw, *m.span()), _excluded(host, cfg)))
    if "qtox" in cfg.extra_types:
        for m in _QTOX.finditer(text):
            if free(m.start(), m.end()) and _is_qtox(m.group(0), cfg):
                taken.append(m.span())
                found.append((Ioc("qtox", m.group(0).lower(), m.group(0), *m.span()), False))
    if "account" in cfg.extra_types:
        for name in table_accounts(text, cfg.account_columns):
            for m in re.finditer(rf"(?<![\w-]){re.escape(name)}(?![\w-])", text, re.IGNORECASE):
                if free(m.start(), m.end()):
                    taken.append(m.span())
                    found.append((Ioc("account", name.lower(), m.group(0), *m.span()), False))
    return sorted(found, key=lambda x: x[0].start)


def extract_iocs(text: str, cfg: IocConfig) -> list[Ioc]:
    return [ioc for ioc, excluded in scan(text, cfg) if not excluded]


def select_known_iocs(iocs: list[Ioc], cfg: BaselineConfig, scenario: str) -> list[KnownIoc]:
    """Fixed, reproducible portion of the report's IoCs that the organization 'already knows' (D-62)."""
    unique = sorted({(i.type, i.value) for i in iocs})
    k = math.ceil(cfg.known_ioc_fraction * len(unique))
    chosen = sorted(random.Random(f"{cfg.seed}:{scenario}").sample(unique, k))
    return [KnownIoc(type=t, value=v, scenario=scenario) for t, v in chosen]


def baseline_recognizes(text: str, known: list[KnownIoc], ioc_cfg: IocConfig,
                        cfg: BaselineConfig) -> tuple[bool, list[str]]:
    present = {(i.type, i.value) for i in extract_iocs(text, ioc_cfg)}
    matches = sorted(f"{t}:{v}" for t, v in {(k.type, k.value) for k in known} & present)
    return len(matches) >= cfg.min_matches, matches
