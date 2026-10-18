"""Gemini client with on-disk cache, demo mode, rate limiting and retries.

Every response is cached under SHA-256(model + prompt + params + schema + replicate).
`demo=True` reads only from the cache, so results can be reproduced without an API key.
Requests built from copyrighted text (`private=True`, the DFIR report) go to a separate,
git-ignored cache so that text never reaches the repository.
The replicate number is part of the key but never sent to the API (docs/DECISIONS.md D-12).
Each response records its `source`: "gemini-api" only when it came from the real SDK
transport; anything else (test doubles, cache entries without a source) is not real (D-71).
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Protocol

from aem.config import Settings

TEMPERATURE = 0
RETRYABLE = {429, 500, 502, 503, 504}
BACKOFF_BASE_SECONDS = 2
REAL_SOURCE = "gemini-api"
UNKNOWN_SOURCE = "desconocida"


class LLMError(RuntimeError):
    pass


class CacheMiss(LLMError):
    pass


class MissingApiKey(LLMError):
    pass


class ModelUnavailable(LLMError):
    pass


class ApiError(LLMError):
    """The API call itself failed (after retries for 429/5xx)."""


class QuotaError(ApiError):
    """HTTP 429 that must stop the whole run, not degrade one output (D-74): nothing is retried after it."""


class DailyQuotaExhausted(QuotaError):
    """HTTP 429 whose quota is per day: retrying cannot help today, so the run stops (cache stays intact)."""


class UnexpectedQuota(QuotaError):
    """HTTP 429 naming quotas, none of them per minute (e.g. tokens or a paid-tier limit): logged and stopped."""


class InvalidResponse(LLMError):
    """The API answered, but the output is not usable (e.g. not JSON or outside the schema)."""


class TransportError(Exception):
    def __init__(self, code: int | None, message: str, details: dict | None = None):
        super().__init__(f"HTTP {code}: {message}")
        self.code = code
        self.message = message
        self.details = details  # parsed JSON error body, when the API sent one


API_KEY_PATTERN = re.compile(r"AIza[0-9A-Za-z_\-]{20,}")


def redact(text: str, api_key: str | None = None) -> str:
    """Error bodies must never carry the key into a log."""
    if api_key and len(api_key) >= 8:  # a too-short value would mangle unrelated text
        text = text.replace(api_key, "[CLAVE OCULTA]")
    return API_KEY_PATTERN.sub("[CLAVE OCULTA]", text)


def _seconds(value) -> float | None:
    """`retryDelay` comes as a protobuf Duration string, e.g. "31s" or "1.5s"."""
    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)s\s*", str(value)) if value is not None else None
    return float(m.group(1)) if m else None


def quota_info(details) -> dict:
    """quota metric / id / value, retryDelay and whether the exhausted quota is per day, from a Gemini error body."""
    err = details.get("error", details) if isinstance(details, dict) else {}
    violations, retry_delay = [], None
    for d in err.get("details") or []:
        if not isinstance(d, dict):
            continue
        for v in d.get("violations") or []:
            if isinstance(v, dict) and ("quotaId" in v or "quotaMetric" in v):
                violations.append({k: v.get(k) for k in ("quotaMetric", "quotaId", "quotaValue", "quotaDimensions")
                                   if k in v})
        if "retryDelay" in d:
            retry_delay = _seconds(d["retryDelay"])
    daily = any("perday" in str(v.get("quotaId", "")).lower() or "per_day" in str(v.get("quotaMetric", "")).lower()
                for v in violations)
    return {"status": err.get("status"), "message": err.get("message"), "violations": violations,
            "retry_delay_s": retry_delay, "daily": daily}


class Transport(Protocol):
    def get_model(self, model: str) -> None: ...

    def generate(self, model: str, prompt: str, schema: dict, temperature: float) -> tuple[str, str]: ...


class GenaiTransport:
    """Thin adapter over the official `google-genai` SDK (verified against v2.31)."""

    def __init__(self, api_key: str):
        from google import genai

        self._client = genai.Client(api_key=api_key)

    def _wrap(self, fn, *args, **kwargs):
        from google.genai import errors

        try:
            return fn(*args, **kwargs)
        except errors.APIError as exc:
            details = exc.details if isinstance(exc.details, dict) else None
            raise TransportError(exc.code, str(exc), details) from exc

    def get_model(self, model: str) -> None:
        self._wrap(self._client.models.get, model=model)

    def generate(self, model: str, prompt: str, schema: dict, temperature: float) -> tuple[str, str]:
        from google.genai import types

        config = types.GenerateContentConfig(
            temperature=temperature, response_mime_type="application/json", response_json_schema=schema
        )
        resp = self._wrap(self._client.models.generate_content, model=model, contents=prompt, config=config)
        return resp.text or "", getattr(resp, "model_version", None) or model


def transport_source(transport: Transport) -> str:
    """Exact type check: a subclass or a stand-in of the SDK transport does not count as real."""
    return REAL_SOURCE if type(transport) is GenaiTransport else f"fake:{type(transport).__name__}"


@dataclass
class LLMResult:
    data: dict
    raw_text: str
    meta: dict = field(default_factory=dict)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class LLMCache:
    def __init__(self, root: Path):
        self.root = Path(root)

    @staticmethod
    def key(model: str, prompt: str, params: dict, schema: dict, replicate: int) -> str:
        blob = json.dumps({"model": model, "prompt": prompt, "params": params, "schema": schema,
                           "replicate": replicate}, sort_keys=True, ensure_ascii=False)
        return _sha256(blob)

    def _path(self, key: str) -> Path:
        return self.root / key[:2] / f"{key}.json"

    def get(self, key: str) -> dict | None:
        p = self._path(key)
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None

    def put(self, key: str, entry: dict) -> None:
        p = self._path(key)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(entry, indent=1, ensure_ascii=False), encoding="utf-8")

    def put_failure(self, key: str, entry: dict) -> Path:
        p = self.root / "failures" / f"{entry['meta']['timestamp'].replace(':', '')}_{key[:16]}.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(entry, indent=1, ensure_ascii=False), encoding="utf-8")
        return p


class GeminiClient:
    def __init__(self, settings: Settings, cache: LLMCache, demo: bool = False, transport: Transport | None = None,
                 sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic,
                 private_cache: LLMCache | None = None):
        self.settings = settings
        self.cache = cache
        self.private_cache = private_cache
        self.demo = demo
        self.transport = transport
        self._sleep = sleep
        self._clock = clock
        self._last_call: float | None = None
        self._model_checked = False
        self.call_log: list[dict] = []  # meta of every answer served (cache hits included), for provenance
        self.api_events: list[dict] = []  # every failed API attempt (429, 5xx…), key redacted
        self.event_log: Path | None = None  # if set, each event is also appended there as one JSON line

    def provenance(self, start: int = 0) -> dict:
        """Where the answers since call number `start` came from; `real` only if every one is from the API."""
        calls = self.call_log[start:]
        sources = sorted({c["source"] for c in calls})
        return {"real": bool(calls) and sources == [REAL_SOURCE], "sources": sources,
                "model_versions": sorted({c.get("model_version") or c.get("model") or "" for c in calls})}

    @property
    def model(self) -> str:
        return self.settings.gemini_model

    def _transport(self) -> Transport:
        if not self.settings.gemini_api_key:
            raise MissingApiKey(
                "Falta GEMINI_API_KEY en .env. Copie .env.example a .env y agregue su clave, "
                "o use --demo para reproducir con las respuestas guardadas."
            )
        if self.transport is None:
            self.transport = GenaiTransport(self.settings.gemini_api_key)
        return self.transport

    def _check_model(self, transport: Transport) -> None:
        if self._model_checked:
            return
        try:
            transport.get_model(self.model)
        except TransportError as exc:
            if exc.code == 404:
                raise ModelUnavailable(
                    f"El modelo «{self.model}» no está disponible en la API de Gemini. "
                    f"Pruebe con el alternativo: GEMINI_MODEL={self.settings.gemini_fallback_model}"
                ) from exc
            raise LLMError(f"No se pudo verificar el modelo «{self.model}»: {exc}") from exc
        self._model_checked = True

    def _throttle(self) -> None:
        interval = 60.0 / max(self.settings.gemini_rpm, 1)
        if self._last_call is not None:
            wait = self._last_call + interval - self._clock()
            if wait > 0:
                self._sleep(wait)
        self._last_call = self._clock()

    def generate_json(self, prompt: str, schema: dict, *, purpose: str, replicate: int = 0,
                      private: bool = False) -> LLMResult:
        cache = self.cache
        if private:
            if self.private_cache is None:
                raise LLMError("Solicitud con texto protegido por derechos de autor sin caché privada configurada.")
            cache = self.private_cache
        params = {"temperature": TEMPERATURE, "response_mime_type": "application/json"}
        key = cache.key(self.model, prompt, params, schema, replicate)
        hit = cache.get(key)
        if hit is not None:
            meta = dict(hit["meta"], from_cache=True)
            meta.setdefault("source", UNKNOWN_SOURCE)
            self.call_log.append(meta)
            return LLMResult(data=json.loads(hit["response_text"]), raw_text=hit["response_text"], meta=meta)
        if self.demo:
            raise CacheMiss(
                f"Modo demo: no hay respuesta guardada para esta solicitud ({purpose}, modelo {self.model}, "
                f"réplica {replicate}, clave {key[:12]}…"
                + (", caché privada" if private else "") + "). Ejecute primero sin --demo con una API key."
            )

        transport = self._transport()
        self._check_model(transport)
        text, version = self._call_with_retries(transport, prompt, schema, purpose)
        meta = {
            "purpose": purpose, "model": self.model, "model_version": version,
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "temperature": TEMPERATURE, "prompt_sha256": _sha256(prompt), "replicate": replicate,
            "cache_key": key, "source": transport_source(transport),
        }
        self.call_log.append(meta)
        entry = {"meta": meta, "params": params, "schema": schema, "prompt": prompt, "response_text": text}
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            path = cache.put_failure(key, entry)
            raise InvalidResponse(f"La respuesta del LLM no es JSON válido ({purpose}); guardada en {path}") from exc
        cache.put(key, entry)
        return LLMResult(data=data, raw_text=text, meta=dict(meta, from_cache=False))

    def event_counts(self) -> dict:
        return {"http_429": sum(e["code"] == 429 for e in self.api_events),
                "retries": sum(e["action"].startswith("reintento") for e in self.api_events),
                "errors_total": len(self.api_events)}

    def _record_event(self, event: dict) -> None:
        # the whole event goes through redact(): any field of the error body could echo the key
        event = json.loads(redact(json.dumps(event, ensure_ascii=False), self.settings.gemini_api_key))
        self.api_events.append(event)
        if self.event_log is not None:
            self.event_log.parent.mkdir(parents=True, exist_ok=True)
            with self.event_log.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(event, ensure_ascii=False) + "\n")

    def _call_with_retries(self, transport: Transport, prompt: str, schema: dict,
                           purpose: str = "") -> tuple[str, str]:
        attempt = 0
        while True:
            self._throttle()
            try:
                return transport.generate(self.model, prompt, schema, TEMPERATURE)
            except TransportError as exc:
                key = self.settings.gemini_api_key
                info = quota_info(exc.details)
                event = {"timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"), "purpose": purpose,
                         "model": self.model, "attempt": attempt + 1, "code": exc.code, **info,
                         "error": str(exc), "body": exc.details}
                if exc.code == 429 and info["daily"]:
                    event["action"] = "detenido: cuota diaria agotada"
                    self._record_event(event)
                    quotas = ", ".join(str(v.get("quotaId")) for v in info["violations"])
                    raise DailyQuotaExhausted(
                        f"Cuota DIARIA de la API de Gemini agotada ({quotas}). No se reintenta: espere a que se "
                        "renueve la cuota y repita el mismo comando; lo ya obtenido sigue en la caché.") from exc
                quota_ids = [str(v.get("quotaId", "")) for v in info["violations"]]
                if exc.code == 429 and quota_ids and not any("perminute" in q.lower() for q in quota_ids):
                    event["action"] = "detenido: 429 con cuota que no es por minuto"
                    self._record_event(event)
                    raise UnexpectedQuota(
                        f"HTTP 429 por una cuota que no es por minuto ({', '.join(quota_ids)}). No se reintenta; "
                        "el cuerpo completo quedó en api_events.jsonl y lo ya obtenido sigue en la caché.") from exc
                if exc.code == 429 and attempt >= self.settings.gemini_max_retries:
                    event["action"] = "detenido: 429 persistente tras los reintentos"
                    self._record_event(event)
                    raise QuotaError(f"HTTP 429 persistente tras {attempt + 1} intento(s): "
                                     f"{redact(str(exc), key)}") from exc
                if exc.code not in RETRYABLE or attempt >= self.settings.gemini_max_retries:
                    event["action"] = "error final"
                    self._record_event(event)
                    raise ApiError(f"Error de la API de Gemini tras {attempt + 1} intento(s): "
                                   f"{redact(str(exc), key)}") from exc
                wait = max(BACKOFF_BASE_SECONDS * 2**attempt, info["retry_delay_s"] or 0)
                event["action"] = f"reintento tras {wait:g} s"
                self._record_event(event)
                self._sleep(wait)
                attempt += 1
