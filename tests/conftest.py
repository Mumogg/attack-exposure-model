from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def mini_attack():
    from aem.attack_data import AttackData

    return AttackData.load(FIXTURES / "mini_attack.json")


# --- the tests never call the real API -----------------------------------------------------------
# Any attempt to build the official SDK client or to use a real `GenaiTransport` fails the test at once
# (pytest.fail is not an Exception, so no `except Exception` in the code can swallow it) and the whole session
# (CI included) ends with a non-zero status. `fakes.as_real_transport` bypasses this on purpose: it replaces
# the network methods of the instance and never builds a client.
API_ATTEMPTS: list[str] = []


def _blocked(what):
    def fail(*args, **kwargs):
        API_ATTEMPTS.append(what)
        pytest.fail(f"un test intentó llamar a la API real de Gemini ({what})", pytrace=True)
    return fail


@pytest.fixture(autouse=True)
def _no_real_api(monkeypatch):
    from google import genai

    from aem.llm import GenaiTransport

    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setattr(genai, "Client", _blocked("google.genai.Client"))
    monkeypatch.setattr(GenaiTransport, "__init__", _blocked("GenaiTransport()"))
    monkeypatch.setattr(GenaiTransport, "get_model", _blocked("GenaiTransport.get_model"))
    monkeypatch.setattr(GenaiTransport, "generate", _blocked("GenaiTransport.generate"))


def pytest_sessionfinish(session, exitstatus):
    if API_ATTEMPTS:
        session.exitstatus = 1
