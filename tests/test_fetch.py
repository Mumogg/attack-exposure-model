import hashlib

import pytest

from aem.fetch import ChecksumMismatch, fetch_verified

PAYLOAD = b'{"type": "bundle"}'
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()


def fake_download(payload):
    calls = []

    def _dl(url):
        calls.append(url)
        return payload

    _dl.calls = calls
    return _dl


def test_records_checksum_when_missing(tmp_path):
    dest, sums = tmp_path / "a.json", tmp_path / "CHECKSUMS.sha256"
    fetch_verified("http://x/a.json", dest, sums, download=fake_download(PAYLOAD))
    assert dest.read_bytes() == PAYLOAD
    assert sums.read_text(encoding="utf-8") == f"{DIGEST}  a.json\n"


def test_accepts_matching_checksum(tmp_path):
    dest, sums = tmp_path / "a.json", tmp_path / "CHECKSUMS.sha256"
    sums.write_text(f"{DIGEST}  a.json\n", encoding="utf-8")
    fetch_verified("http://x/a.json", dest, sums, download=fake_download(PAYLOAD))
    assert dest.exists()


def test_rejects_mismatch_and_leaves_no_file(tmp_path):
    dest, sums = tmp_path / "a.json", tmp_path / "CHECKSUMS.sha256"
    sums.write_text(f"{'0' * 64}  a.json\n", encoding="utf-8")
    with pytest.raises(ChecksumMismatch):
        fetch_verified("http://x/a.json", dest, sums, download=fake_download(PAYLOAD))
    assert not dest.exists()


def test_skips_download_when_existing_file_matches(tmp_path):
    dest, sums = tmp_path / "a.json", tmp_path / "CHECKSUMS.sha256"
    dest.write_bytes(PAYLOAD)
    sums.write_text(f"{DIGEST}  a.json\n", encoding="utf-8")
    dl = fake_download(PAYLOAD)
    fetch_verified("http://x/a.json", dest, sums, download=dl)
    assert dl.calls == []
