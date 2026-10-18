"""The guard of conftest.py: a test that reaches the real Gemini SDK fails."""

import pytest
from _pytest.outcomes import Failed

import conftest


def test_building_the_real_transport_fails_the_test():
    from aem.llm import GenaiTransport

    before = len(conftest.API_ATTEMPTS)
    with pytest.raises(Failed, match="API real"):
        GenaiTransport("clave-falsa")
    del conftest.API_ATTEMPTS[before:]  # this attempt is the expected one


def test_sdk_client_is_blocked_too():
    from google import genai

    before = len(conftest.API_ATTEMPTS)
    with pytest.raises(Failed):
        genai.Client(api_key="clave-falsa")
    del conftest.API_ATTEMPTS[before:]


def test_api_key_is_never_in_the_test_environment():
    import os

    assert "GEMINI_API_KEY" not in os.environ
