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


def test_private_requests_use_the_private_cache(tmp_path):
    """Copyrighted report text (DFIR) must never land in the committed cache (runs/llm_cache)."""
    clock = FakeClock()
    c = GeminiClient(settings(), LLMCache(tmp_path / "cache"), transport=FakeTransport([{"x": 1}, "no json"]),
                     sleep=clock.sleep, clock=clock.now, private_cache=LLMCache(tmp_path / "private"))
    c.generate_json("texto con derechos", SCHEMA, purpose="t", private=True)
    assert list((tmp_path / "private").rglob("*.json"))
    assert not (tmp_path / "cache").exists()
    with pytest.raises(LLMError):
        c.generate_json("otro texto con derechos", SCHEMA, purpose="t", private=True)
    assert not (tmp_path / "cache").exists()  # failure dumps also stay private


def test_private_request_without_private_cache_is_refused(tmp_path):
    c, _ = client(tmp_path, FakeTransport([{"x": 1}]))
    with pytest.raises(LLMError, match="privada"):
        c.generate_json("texto", SCHEMA, purpose="t", private=True)


# --- provenance: results produced with a fake LLM must never pass as real -------------------------


def test_fake_transport_is_recorded_as_fake(tmp_path):
    c, _ = client(tmp_path, FakeTransport([{"x": 1}]))
    res = c.generate_json("hola", SCHEMA, purpose="test")
    assert res.meta["source"] == "fake:FakeTransport"
    assert c.provenance()["real"] is False and c.provenance()["sources"] == ["fake:FakeTransport"]
    # the cached entry keeps the label, so a later cache hit is still fake
    again, _ = client(tmp_path, transport=None, demo=True)
    assert again.generate_json("hola", SCHEMA, purpose="test").meta["source"] == "fake:FakeTransport"
    assert again.provenance()["real"] is False


def test_real_transport_is_recorded_as_real(tmp_path):
    from fakes import as_real_transport
    c, _ = client(tmp_path, as_real_transport(FakeTransport([{"x": 1}])))
    assert c.generate_json("hola", SCHEMA, purpose="test").meta["source"] == "gemini-api"
    p = c.provenance()
    assert p["real"] is True and p["model_versions"] == ["gemini-3.8-flash-001"]


def test_cache_entry_without_source_is_not_real(tmp_path):
    c, _ = client(tmp_path, FakeTransport([{"x": 1}]))
    c.generate_json("hola", SCHEMA, purpose="test")
    for f in (tmp_path / "cache").rglob("*.json"):
        entry = json.loads(f.read_text(encoding="utf-8"))
        del entry["meta"]["source"]
        f.write_text(json.dumps(entry), encoding="utf-8")
    d, _ = client(tmp_path, transport=None, demo=True)
    assert d.generate_json("hola", SCHEMA, purpose="test").meta["source"] == "desconocida"
    assert d.provenance()["real"] is False


def test_no_calls_is_not_real(tmp_path):
    c, _ = client(tmp_path, FakeTransport())
    assert c.provenance()["real"] is False


# --- 429 detail, retryDelay and daily quota ----------------------------------------------------
# Synthetic error bodies in the shape the Gemini API uses (google.rpc QuotaFailure + RetryInfo).

FAKE_KEY = "AIza" + "X" * 35


def _quota_body(quota_id, metric, retry_delay=None, leak_key=False):
    details = [{"@type": "type.googleapis.com/google.rpc.QuotaFailure",
                "violations": [{"quotaMetric": metric, "quotaId": quota_id, "quotaValue": "10",
                                "quotaDimensions": {"model": "gemini-3.8-flash", "location": "global"}}]}]
    if retry_delay:
        details.append({"@type": "type.googleapis.com/google.rpc.RetryInfo", "retryDelay": retry_delay})
    msg = "You exceeded your current quota." + (f" key={FAKE_KEY}" if leak_key else "")
    return {"error": {"code": 429, "message": msg, "status": "RESOURCE_EXHAUSTED", "details": details}}


PER_MINUTE = ("GenerateRequestsPerMinutePerProjectPerModel-FreeTier",
              "generativelanguage.googleapis.com/generate_content_free_tier_requests")
PER_DAY = ("GenerateRequestsPerDayPerProjectPerModel-FreeTier",
           "generativelanguage.googleapis.com/generate_content_free_tier_requests_per_day")


def test_429_detail_is_logged_and_retry_delay_respected(tmp_path):
    body = _quota_body(*PER_MINUTE, retry_delay="31s", leak_key=True)
    t = FakeTransport([TransportError(429, f"429 RESOURCE_EXHAUSTED. {body}", body), {"x": 1}])
    c, clock = client(tmp_path, t, key=FAKE_KEY, rpm=600)
    c.event_log = tmp_path / "run" / "api_events.jsonl"
    assert c.generate_json("hola", SCHEMA, purpose="test").data == {"x": 1}
    assert 31 in clock.sleeps and 2 not in clock.sleeps  # retryDelay (31 s) beats the 2 s backoff
    [event] = c.api_events
    assert event["code"] == 429 and event["status"] == "RESOURCE_EXHAUSTED" and event["retry_delay_s"] == 31
    assert event["violations"][0]["quotaId"] == PER_MINUTE[0]
    assert event["violations"][0]["quotaMetric"] == PER_MINUTE[1]
    assert event["daily"] is False and event["action"] == "reintento tras 31 s" and event["purpose"] == "test"
    logged = (tmp_path / "run" / "api_events.jsonl").read_text(encoding="utf-8")
    assert FAKE_KEY not in logged and "[CLAVE OCULTA]" in logged and PER_MINUTE[0] in logged
    assert json.loads(logged.splitlines()[0])["retry_delay_s"] == 31
    assert c.event_counts() == {"http_429": 1, "retries": 1, "errors_total": 1}


def test_backoff_wins_when_longer_than_retry_delay(tmp_path):
    body = _quota_body(*PER_MINUTE, retry_delay="0.5s")
    t = FakeTransport([TransportError(429, "q", body), {"x": 1}])
    c, clock = client(tmp_path, t, rpm=600)
    c.generate_json("hola", SCHEMA, purpose="test")
    assert 2 in clock.sleeps and c.api_events[0]["retry_delay_s"] == 0.5


def test_daily_quota_stops_without_retrying_and_keeps_cache(tmp_path):
    from aem.llm import ApiError, DailyQuotaExhausted

    ok = FakeTransport([{"x": 1}])
    c, _ = client(tmp_path, ok)
    c.generate_json("first", SCHEMA, purpose="test")
    cached = sorted(p.name for p in (tmp_path / "cache").rglob("*.json"))

    body = _quota_body(*PER_DAY, retry_delay="40s")
    t = FakeTransport([TransportError(429, "q", body), {"x": 2}])
    c, clock = client(tmp_path, t, rpm=600)
    c.event_log = tmp_path / "api_events.jsonl"
    with pytest.raises(DailyQuotaExhausted, match="DIARIA") as err:
        c.generate_json("second", SCHEMA, purpose="test")
    assert isinstance(err.value, ApiError) and PER_DAY[0] in str(err.value)
    assert len(t.calls) == 1 and not [s for s in clock.sleeps if s >= 2]  # no retry, no backoff
    assert c.api_events[0]["daily"] is True and c.api_events[0]["action"].startswith("detenido")
    assert c.event_counts() == {"http_429": 1, "retries": 0, "errors_total": 1}
    assert sorted(p.name for p in (tmp_path / "cache").rglob("*.json")) == cached  # cache untouched
    assert (tmp_path / "api_events.jsonl").exists()


def test_429_without_body_still_logged(tmp_path):
    t = FakeTransport([TransportError(429, "quota"), {"x": 1}])
    c, _ = client(tmp_path, t, rpm=600)
    c.generate_json("hola", SCHEMA, purpose="test")
    e = c.api_events[0]
    assert e["code"] == 429 and e["body"] is None and e["violations"] == [] and e["retry_delay_s"] is None


def test_genai_transport_keeps_the_error_body():
    from google.genai import errors

    from aem.llm import GenaiTransport

    body = _quota_body(*PER_MINUTE, retry_delay="7s")
    tr = GenaiTransport.__new__(GenaiTransport)  # no client, no network

    def boom(**kw):
        raise errors.ClientError(429, body)

    with pytest.raises(TransportError) as err:
        tr._wrap(boom)
    assert err.value.code == 429 and err.value.details == body


def test_429_with_a_quota_that_is_not_per_minute_stops(tmp_path):
    from aem.llm import QuotaError, UnexpectedQuota

    body = _quota_body("GenerateContentInputTokensPerModelPerDayOrSomethingElse-Paid".replace("PerDay", "Per"),
                       "generativelanguage.googleapis.com/some_other_quota", retry_delay="5s")
    t = FakeTransport([TransportError(429, "q", body), {"x": 1}])
    c, clock = client(tmp_path, t, rpm=600)
    with pytest.raises(UnexpectedQuota, match="no es por minuto") as err:
        c.generate_json("hola", SCHEMA, purpose="test")
    assert isinstance(err.value, QuotaError) and len(t.calls) == 1
    assert c.api_events[0]["action"].startswith("detenido") and c.api_events[0]["body"] == body


def test_per_minute_429_is_retried_and_persistent_one_is_a_quota_error(tmp_path):
    from aem.llm import QuotaError

    body = _quota_body(*PER_MINUTE)
    t = FakeTransport([TransportError(429, "q", body)] * 3)
    c, _ = client(tmp_path, t, rpm=600, retries=2)
    with pytest.raises(QuotaError, match="persistente"):
        c.generate_json("hola", SCHEMA, purpose="test")
    assert len(t.calls) == 3
    assert c.event_counts() == {"http_429": 3, "retries": 2, "errors_total": 3}
