"""`aem check-repo`: secrets, DFIR text and private files in tracked files and the whole git history."""

import subprocess

import pytest

from aem.repo_check import check_repo, distinctive_phrases

# Built at runtime so this test file itself never contains a key-shaped string.
FAKE_KEY = "AI" + "za" + "Sy" + "0123456789abcdefghijABCDEFGHIJ_-x"
DFIR = ("Initial access was gained through a trojanized installer that the victim downloaded after an advertised "
        "search result redirected the browser to a lookalike site.\n"
        "Within hours the operators staged a second-stage implant on the workstation and began enumerating the "
        "domain from that foothold using built-in utilities.\n")


def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "r"
    r.mkdir()
    git(r, "init", "-q")
    git(r, "config", "user.email", "t@example.invalid")
    git(r, "config", "user.name", "t")
    (r / "README.md").write_text("clean\n", encoding="utf-8")
    git(r, "add", "-A")
    git(r, "commit", "-q", "-m", "init")
    return r


def commit(repo, path, content, msg="c"):
    p = repo / path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", msg)


def test_clean_repo_has_no_findings(repo):
    assert check_repo(repo, phrases=distinctive_phrases(DFIR))["findings"] == []


def test_key_removed_later_is_still_found_in_history(repo):
    commit(repo, "config.txt", f"key = {FAKE_KEY}\n")
    (repo / "config.txt").unlink()
    git(repo, "commit", "-q", "-am", "remove")
    findings = check_repo(repo, phrases=[])["findings"]
    assert len(findings) == 1 and findings[0]["kind"] == "API key de Google"
    assert "config.txt:1" in findings[0]["where"] and FAKE_KEY not in str(findings)  # never print the key


def test_env_and_private_paths(repo):
    commit(repo, ".env", "GEMINI_API_KEY=\n")
    commit(repo, "runs/2026-10-20/private/akira/orig/r0/run_record.json", "{}")
    kinds = {f["kind"] for f in check_repo(repo, phrases=[])["findings"]}
    assert kinds == {"archivo .env versionado", "archivo dentro de una carpeta private/"}


def test_dfir_text_is_found_by_distinctive_phrases(repo):
    commit(repo, "notes/copy.md", "Some notes.\n" + DFIR.splitlines()[1] + "\n")
    findings = check_repo(repo, phrases=distinctive_phrases(DFIR))["findings"]
    assert [f["kind"] for f in findings] == ["texto del reporte de DFIR"]
    assert "notes/copy.md:2" in findings[0]["where"]


def test_staged_but_uncommitted_files_are_checked(repo):
    (repo / "staged.txt").write_text(f"{FAKE_KEY}\n", encoding="utf-8")
    git(repo, "add", "staged.txt")
    assert any("índice" in f["where"] for f in check_repo(repo, phrases=[])["findings"])


def test_distinctive_phrases_skip_short_lines_and_attack_ids():
    phrases = distinctive_phrases("Short line.\nCredential dumping - T1003.001 and a long enough line to qualify "
                                  "as prose but it has an ID in it so it is skipped.\n" + DFIR)
    assert phrases and all("T1003" not in p and len(p) >= 60 for p in phrases)


def test_the_real_repository_is_clean():
    from aem.config import REPO_ROOT
    assert check_repo(REPO_ROOT, phrases=[])["findings"] == []


def test_cli_exit_code_and_locations(repo, tmp_path):
    from typer.testing import CliRunner
    from aem.cli import app
    runner = CliRunner()
    text = tmp_path / "dfir.txt"
    text.write_text(DFIR, encoding="utf-8")
    ok = runner.invoke(app, ["check-repo", "--repo", str(repo), "--dfir-text", str(text)])
    assert ok.exit_code == 0, ok.output
    commit(repo, "copy.md", DFIR.splitlines()[0] + "\n")
    bad = runner.invoke(app, ["check-repo", "--repo", str(repo), "--dfir-text", str(text)])
    out = bad.output.replace("\n", " ")
    assert bad.exit_code == 1 and "copy.md:1" in out and "texto del reporte de DFIR" in out
    missing = runner.invoke(app, ["check-repo", "--repo", str(repo), "--dfir-text", str(tmp_path / "no.txt")])
    assert "AVISO" in missing.output and missing.exit_code == 0
