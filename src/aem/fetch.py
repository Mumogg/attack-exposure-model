"""Downloads with SHA-256 verification against a committed checksum file."""

from __future__ import annotations

import hashlib
import urllib.request
from collections.abc import Callable
from pathlib import Path

USER_AGENT = "attack-exposure-model/0.1 (thesis reproducibility prototype)"


class ChecksumMismatch(RuntimeError):
    pass


def http_get(url: str, timeout: int = 120) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_checksums(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    sums = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            digest, name = line.split(maxsplit=1)
            sums[name.strip()] = digest
    return sums


def write_checksum(path: Path, name: str, digest: str) -> None:
    sums = read_checksums(path)
    sums[name] = digest
    path.write_text("".join(f"{d}  {n}\n" for n, d in sorted(sums.items())), encoding="utf-8")


def fetch_verified(
    url: str, dest: Path, checksums: Path, download: Callable[[str], bytes] = http_get
) -> str:
    """Download `url` to `dest` and verify (or record) its SHA-256. Returns the digest."""
    expected = read_checksums(checksums).get(dest.name)
    if dest.exists() and expected and sha256_bytes(dest.read_bytes()) == expected:
        return expected
    data = download(url)
    digest = sha256_bytes(data)
    if expected and digest != expected:
        raise ChecksumMismatch(
            f"El SHA-256 de {dest.name} ({digest}) no coincide con el registrado ({expected}). "
            "El archivo publicado cambió: revise antes de continuar."
        )
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)
    if not expected:
        write_checksum(checksums, dest.name, digest)
    return digest
