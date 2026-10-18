"""Candidate threat names for the `anon` version (`aem suggest-anon-names`, D-72).

It only proposes: a person decides what goes into `data/anon_names.yaml`. The criteria are
deliberately simple and are printed with the results (CRITERIA):

Candidates
- capitalized words that appear capitalized more often than in lower case in the text and at least
  once in running prose, after a lower-case word (so ordinary words such as "Network" or "Later" and
  Title Case words of cited titles or author names drop out);
- tokens with internal capitals or letters and digits (`AdaptixC2`, `SystemBC`, `NodeSnake`);
- sequences of 2-3 capitalized words that end in a malware/group suffix (`Lumma Stealer`,
  `Golden Community`) or are followed by a threat word (`… group`);
- a footnote number glued to a word is removed (`Conti1` -> `Conti`);
- short all-caps acronyms (FBI, RDP, VPN), ATT&CK IDs, CVE IDs and long hexadecimal strings are
  skipped (the latter are IoCs, already handled by `mut`).

Classification
- "probable herramienta legítima/general": in the explicit list of known legitimate tools, products,
  platforms and organizations (LEGIT_NAMES);
- otherwise "probable amenaza" if the name ends in a threat suffix, or if at least half of its
  occurrences have a threat word (ransomware, loader, backdoor, actors, alias…) within 3 words;
- otherwise "probable herramienta legítima/general".
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from eval.make_variants import AnonName, _name_pattern

THREAT = "probable amenaza"
LEGIT = "probable herramienta legítima/general"

THREAT_WORDS = {
    "ransomware", "malware", "loader", "loaders", "backdoor", "backdoors", "rat", "rats", "stealer", "stealers",
    "infostealer", "trojan", "botnet", "implant", "dropper", "payload", "encryptor", "c2", "framework", "actor",
    "actors", "group", "gang", "affiliate", "affiliates", "operators", "alias", "aliases", "variant", "variants",
    "family", "families", "campaign", "strain",
}
SUFFIXES = {"stealer", "rat", "loader", "backdoor", "botnet", "ransomware", "locker", "community", "group", "team",
            "gang", "spider", "panda", "bear", "kitten", "tempest", "typhoon", "blizzard", "sleet", "c2"}
# Legitimate or general-purpose tools, platforms, vendors and organizations (lower case).
LEGIT_NAMES = {
    "powershell", "cmd", "rdp", "anydesk", "psexec", "impacket", "rclone", "filezilla", "cobalt", "cobalt strike",
    "strike", "mimikatz", "winscp", "putty", "7-zip", "adfind", "nltest", "netscan", "advanced ip scanner",
    "teamviewer", "screenconnect", "splashtop", "atera", "rubeus", "bloodhound", "sharphound", "vssadmin", "wmic",
    "certutil", "bitsadmin", "rundll32", "regsvr32", "mshta", "sysinternals", "procdump", "windows", "linux",
    "macos", "freebsd", "microsoft", "google", "chrome", "edge", "azure", "aws", "vmware", "esxi", "hyper-v",
    "fortinet", "fortios", "fortiproxy", "cisco", "active directory", "onedrive", "sharepoint", "office", "tor",
    "qtox", "telegram", "github", "virustotal", "mitre", "cisa", "fbi", "nsa", "bing", "teams", "outlook",
    "exchange", "veeam", "azcopy", "hiware", "md5", "sha1", "sha-1", "sha256", "sha-256", "sha512", "openssh", "ssh", "python", "java", "node", "nodejs", "javascript", "dropbox", "mega",
    "storageexplorer", "bitcoin", "monero", "kerberos", "ntlm", "ldap", "smb", "wireshark", "nmap", "sentinelone",
    "crowdstrike", "defender", "sophos", "talos", "sekoia", "mcafee", "cloudsek", "cyfirma", "trend micro",
    "trendmicro", "breakglass", "fortra", "bleeping computer", "dfir", "sigma", "yara", "snort", "suricata",
}
CRITERIA = __doc__.split("\n\n", 1)[1]

_TOKEN = re.compile(r"[A-Z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)*")
_WORD = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*")


@dataclass
class Candidate:
    name: str
    count: int
    label: str
    reason: str
    contexts: list[str] = field(default_factory=list)


def _clean(token: str) -> str:
    """Drop a footnote number glued to a word: `Conti1` -> `Conti` (not `AdaptixC2`, `R3ADM3`)."""
    return re.sub(r"(?<=[a-z]{2})\d{1,2}$", "", token)


def _is_acronym(token: str) -> bool:
    return token.isalpha() and token.isupper() and len(token) <= 5


def _shape(token: str) -> bool:
    """Internal capitals or letters mixed with digits."""
    return bool(re.search(r"[a-z][A-Z]|[A-Za-z]\d|\d[A-Za-z]", token)) and not _is_acronym(token)


_NOT_A_NAME = re.compile(r"^(?:TA?\d{4}(?:\.\d{3})?|CVE-\d{4}-\d+|[0-9A-Fa-f]{16,}|[0-9A-Za-z]{40,})$")
ARTICLES = {"the", "a", "an", "this", "these", "those", "that"}
MONTHS = {"january", "february", "march", "april", "may", "june", "july", "august", "september", "october",
          "november", "december"}


def _after_lower_word(text: str, pos: int) -> bool:
    """Running prose: the previous word starts with a lower-case letter (`the Rhysida`, `and SystemBC`)."""
    prev = re.search(r"([A-Za-z][\w-]*)[,;]?\s+$", text[max(0, pos - 40):pos])
    return bool(prev) and prev.group(1)[0].islower()


def _sentence_start(text: str, pos: int) -> bool:
    before = text[:pos].rstrip(" \t\"'“(")
    return not before or before[-1] in ".!?:\n#|-*"


def _raw_candidates(text: str) -> set[str]:
    found: set[str] = set()
    tokens = [(m.group(0), m.start(), m.end()) for m in _TOKEN.finditer(text)]
    lower = Counter(w.lower() for w in _WORD.findall(text) if w.islower())
    capital = Counter(_clean(t) for t, _, _ in tokens)
    prose = Counter(_clean(t) for t, s, _ in tokens if not _sentence_start(text, s) and _after_lower_word(text, s))
    for tok in capital:
        if _NOT_A_NAME.match(tok) or tok.lower() in MONTHS:
            continue
        if tok.lower() in LEGIT_NAMES:
            found.add(tok)
        elif (_shape(tok) or (not _is_acronym(tok) and len(tok) >= 3 and capital[tok] > lower[tok.lower()])) \
                and prose[tok]:
            found.add(tok)
    # sequences of 2-3 capitalized words separated by single spaces
    for i in range(len(tokens)):
        for n in (2, 3):
            seq = tokens[i:i + n]
            if len(seq) < n or any(text[a[2]:b[1]] != " " for a, b in zip(seq, seq[1:])):
                continue
            words = [_clean(t) for t, _, _ in seq]
            if words[0].lower() in ARTICLES:
                continue
            if re.sub(r"\d+$", "", words[-1]).lower() in SUFFIXES:  # footnote after a suffix: `Interlock RAT5`
                words[-1] = re.sub(r"\d+$", "", words[-1])
            name = " ".join(words)
            nxt = _WORD.match(text, seq[-1][2] + 1) if text[seq[-1][2]:seq[-1][2] + 1] == " " else None
            if words[-1].lower() in SUFFIXES or name.lower() in LEGIT_NAMES or \
                    (nxt and nxt.group(0).lower() in THREAT_WORDS):
                found.add(name)
    return found


def _occurrences(text: str, name: str) -> list[re.Match]:
    return list(re.finditer(_name_pattern(name), text, re.IGNORECASE))


def _context(text: str, m: re.Match, words: int = 5) -> str:
    left = text[:m.start()].split()[-words:]
    right = text[m.end():].split()[:words]
    return " ".join(left + [m.group(0)] + right)


def _classify(text: str, name: str, matches: list[re.Match]) -> tuple[str, str]:
    low = name.lower()
    if low in LEGIT_NAMES or low.split()[0] in LEGIT_NAMES:
        return LEGIT, "en la lista de herramientas, productos u organizaciones conocidas"
    if low.split()[-1] in SUFFIXES or re.sub(r"\d+$", "", low.split()[-1]) in SUFFIXES:
        return THREAT, f"termina en «{name.split()[-1]}»"
    near = 0
    for m in matches:
        window = [w.lower() for w in (text[:m.start()].split()[-3:] + text[m.end():].split()[:3])]
        if any(re.sub(r"[^a-z0-9]", "", w) in THREAT_WORDS for w in window):
            near += 1
    if matches and near * 2 >= len(matches):
        return THREAT, f"palabra de amenaza a ≤ 3 palabras en {near} de {len(matches)} apariciones"
    return LEGIT, f"sin contexto de amenaza suficiente ({near} de {len(matches)} apariciones)"


def suggest(text: str) -> list[Candidate]:
    out = []
    for name in _raw_candidates(text):
        matches = _occurrences(text, name)
        if not matches:
            continue
        label, reason = _classify(text, name, matches)
        out.append(Candidate(name, len(matches), label, reason, [_context(text, m) for m in matches[:2]]))
    return sorted(out, key=lambda c: (c.label != THREAT, -c.count, c.name.lower()))


def _covers(listed: AnonName, cand: Candidate) -> bool:
    return bool(re.match(_name_pattern(listed.name), cand.name, re.IGNORECASE))


def coverage(text: str, cands: list[Candidate], names: list[AnonName]) -> dict:
    """Which listed names the suggester proposed, which appear in the text without being proposed (warn),
    which are not in the text at all, and which threat candidates are not listed yet."""
    covered, missing, absent = [], [], []
    for n in names:
        if any(_covers(n, c) for c in cands):
            covered.append(n.name)
        elif _occurrences(text, n.name):
            missing.append(n.name)
        else:
            absent.append(n.name)
    pattern_hits = [c.name for c in cands if c.label == THREAT and not any(_covers(n, c) or
                    re.search(_name_pattern(n.name), c.name, re.IGNORECASE) for n in names)]
    return {"covered": covered, "missing_in_text": missing, "absent": absent, "threats_not_listed": pattern_hits}


def _replacement_hint(c: Candidate) -> str:
    low = (c.name + " " + " ".join(c.contexts)).lower()
    for word, hint in (("loader", "LoaderX"), ("stealer", "StealerX"), ("rat", "RatX"), ("backdoor", "BackdoorX"),
                       ("c2", "C2FrameworkX"), ("ransomware", "ActorX"), ("group", "ActorY")):
        if re.search(rf"\b{word}\b", low):
            return hint
    return "MalwareX"


def write_candidates(out_dir: Path, scenario: str, text: str, cands: list[Candidate], names: list[AnonName]) -> Path:
    """Markdown with the candidates (contains short report fragments: the folder is git-ignored)."""
    cov = coverage(text, cands, names)
    out = Path(out_dir) / f"{scenario}_anon_candidates.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"# Candidatos a anonimizar — {scenario}", "",
             "Generado por `aem suggest-anon-names`. **No modifica `data/anon_names.yaml`**: copie a mano las filas "
             "aprobadas (sección final) y vuelva a ejecutar `aem make-variants`. Este archivo contiene fragmentos "
             "del reporte y está en una carpeta ignorada por git.", "", "## Criterio", "", CRITERIA.strip(), "",
             "## Candidatos", "", "| # | Candidato | Apariciones | Clasificación | Motivo | Contexto |",
             "|---|---|---|---|---|---|"]
    for i, c in enumerate(cands, 1):
        ctx = " · ".join(f"«{x}»" for x in c.contexts).replace("|", "\\|")
        lines.append(f"| {i} | {c.name} | {c.count} | {c.label} | {c.reason} | {ctx} |")
    lines += ["", "## Comparación con `data/anon_names.yaml`", "",
              f"- Ya listados y propuestos: {', '.join(cov['covered']) or 'ninguno'}",
              f"- **Listados que aparecen en el texto pero el sugeridor no propuso:** "
              f"{', '.join(cov['missing_in_text']) or 'ninguno'}",
              f"- Listados que no aparecen en el texto: {', '.join(cov['absent']) or 'ninguno'}",
              f"- «Probable amenaza» aún no listados: {', '.join(cov['threats_not_listed']) or 'ninguno'}", "",
              "## Filas para copiar a `data/anon_names.yaml` (solo las que apruebe)", "",
              f"Bajo `{scenario}:`; revise `replacement` (sugerido por el contexto) y `role`. Una herramienta legítima "
              "o de uso general no se agrega.", "", "```yaml"]
    for c in cands:
        if c.label == THREAT and c.name in cov["threats_not_listed"]:
            lines.append(f"  - {{name: {c.name}, replacement: {_replacement_hint(c)}, role: <revisar>}}")
    lines += ["```", ""]
    out.write_text("\n".join(lines), encoding="utf-8")
    return out
