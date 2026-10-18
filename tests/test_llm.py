import hashlib
import json

import pytest

from aem.config import Settings
from aem.llm import CacheMiss, GeminiClient, LLMCache, LLMError, MissingApiKey, ModelUnavailable, TransportError
from fakes import FakeClock, FakeTransport

SCHEMA = {"type": "object", "properties": {"x": {"type": "integer"}}, "required": ["x"]}


def settings(key="k", model="gemini-3.8-flash", rpm=10, retries=3):
    return Settings(gemini_api_key=key, gemini_model=model, gemini_fallback_model="gemini-3.5-flash-lite",
                    gemini_rpm=rpm, gemini_max_retries=retries)


def client(tmp_path, transport, demo=False, **kw):
    clock = FakeClock()
    c = GeminiClient(settings(**kw), LLMCache(tmp_path / "cache"), demo=demo, transport=transport,
                     sleep=clock.sleep, clock=clock.now)
    return c, clock


def test_calls_api_with_temperature_zero_and_records_meta(tmp_path):
    t = FakeTransport([{"x": 1}])
    c, _ = client(tmp_path, t)
    res = c.generate_json("hola", SCHEMA, purpose="test")
    assert res.data == {"x": 1}
    assert t.calls[0]["temperature"] == 0 and t.calls[0]["schema"] == SCHEMA
    m = res.meta
    assert m["model"] == "gemini-3.8-flash" and m["model_version"] == "gemini-3.8-flash-001"
    assert m["temperature"] == 0 and m["prompt_sha256"] == hashlib.sha256(b"hola").hexdigest()
    assert m["timestamp"] and m["from_cache"] is False and m["purpose"] == "test"


def test_second_call_hits_cache(tmp_path):
    t = FakeTransport([{"x": 1}])
    c, _ = client(tmp_path, t)
    c.generate_json("hola", SCHEMA, purpose="test")
    res = c.generate_json("hola", SCHEMA, purpose="test")
    assert res.meta["from_cache"] is True and len(t.calls) == 1


def test_replicates_have_separate_cache_entries(tmp_path):
    t = FakeTransport([{"x": 1}, {"x": 2}])
    c, _ = client(tmp_path, t)
    a = c.generate_json("hola", SCHEMA, purpose="test", replicate=1)
    b = c.generate_json("hola", SCHEMA, purpose="test", replicate=2)
    assert (a.data, b.data) == ({"x": 1}, {"x": 2}) and a.meta["cache_key"] != b.meta["cache_key"]
    assert "replicate" not in t.calls[0]["prompt"]


def test_cache_key_depends_on_model(tmp_path):
    cache = LLMCache(tmp_path)
    k1 = cache.key("m1", "p", {"temperature": 0}, SCHEMA, 0)
    assert k1 != cache.key("m2", "p", {"temperature": 0}, SCHEMA, 0)
    assert k1 != cache.key("m1", "p2", {"temperature": 0}, SCHEMA, 0)
    assert k1 == cache.key("m1", "p", {"temperature": 0}, SCHEMA, 0)


def test_demo_uses_only_cache_and_needs_no_key(tmp_path):
    c, _ = client(tmp_path, FakeTransport([{"x": 5}]))
    c.generate_json("hola", SCHEMA, purpose="test")
    demo, _ = client(tmp_path, FakeTransport([]), demo=True, key=None)
    assert demo.generate_json("hola", SCHEMA, purpose="test").data == {"x": 5}


def test_demo_cache_miss_fails_clearly(tmp_path):
    t = FakeTransport([{"x": 5}])
    demo, _ = client(tmp_path, t, demo=True, key=None)
    with pytest.raises(CacheMiss, match="(?i)modo demo"):
        demo.generate_json("otro", SCHEMA, purpose="test")
    assert t.calls == []


def test_missing_key_outside_demo(tmp_path):
    c, _ = client(tmp_path, FakeTransport([{"x": 1}]), key=None)
    with pytest.raises(MissingApiKey, match="GEMINI_API_KEY"):
        c.generate_json("hola", SCHEMA, purpose="test")


def test_retries_429_with_exponential_backoff(tmp_path):
    t = FakeTransport([TransportError(429, "quota"), TransportError(429, "quota"), {"x": 1}])
    c, clock = client(tmp_path, t, rpm=600)  # rate-limit gap (0.1 s) stays below the backoff floor
    assert c.generate_json("hola", SCHEMA, purpose="test").data == {"x": 1}
    backoffs = [s for s in clock.sleeps if s >= 2]
    assert backoffs == [2, 4]


def test_gives_up_after_max_retries(tmp_path):
    t = FakeTransport([TransportError(429, "quota")] * 4)
    c, _ = client(tmp_path, t, retries=3)
    with pytest.raises(LLMError, match="429"):
        c.generate_json("hola", SCHEMA, purpose="test")
    assert len(t.calls) == 4


def test_non_retryable_error_is_raised(tmp_path):
    t = FakeTransport([TransportError(400, "bad request")])
    c, _ = client(tmp_path, t)
    with pytest.raises(LLMError, match="400"):
        c.generate_json("hola", SCHEMA, purpose="test")
    assert len(t.calls) == 1


def test_model_checked_once_and_unknown_model_suggests_fallback(tmp_path):
    t = FakeTransport([{"x": 1}, {"x": 2}])
    c, _ = client(tmp_path, t)
    c.generate_json("a", SCHEMA, purpose="t")
    c.generate_json("b", SCHEMA, purpose="t")
    assert t.model_checks == ["gemini-3.8-flash"]
    bad, _ = client(tmp_path, FakeTransport([{"x": 1}]), model="gemini-9-imaginary")
    with pytest.raises(ModelUnavailable, match="gemini-3.5-flash-lite"):
        bad.generate_json("a", SCHEMA, purpose="t")


def test_rate_limit_spaces_calls(tmp_path):
    t = FakeTransport([{"x": 1}, {"x": 2}])
    c, clock = client(tmp_path, t, rpm=10)
    c.generate_json("a", SCHEMA, purpose="t")
    c.generate_json("b", SCHEMA, purpose="t")
    assert clock.sleeps == [pytest.approx(6.0)]


def test_invalid_json_fails_and_keeps_raw(tmp_path):
    t = FakeTransport(["esto no es json"])
    c, _ = client(tmp_path, t)
    with pytest.raises(LLMError, match="JSON"):
        c.generate_json("a", SCHEMA, purpose="t")
    failures = list((tmp_path / "cache" / "failures").glob("*.json"))
    assert len(failures) == 1
    assert json.loads(failures[0].read_text(encoding="utf-8"))["response_text"] == "esto no es json"
    # failure is not cached: a retry calls the API again
    c.transport.responses.append({"x": 3})
    assert c.generate_json("a", SCHEMA, purpose="t").data == {"x": 3}


def test_api_errors_and_bad_output_are_distinguishable(tmp_path):
    """run_experiments stops on API errors but records a bad response as a failed run."""
    from aem.llm import ApiError, InvalidResponse

    c, _ = client(tmp_path, FakeTransport([TransportError(400, "bad request")]))
    with pytest.raises(ApiError):
        c.generate_json("hola", SCHEMA, purpose="test")
    c, _ = client(tmp_path, FakeTransport(["no json"]))
    with pytest.raises(InvalidResponse):
        c.generate_json("otro", SCHEMA, purpose="test")
