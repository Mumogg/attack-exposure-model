import json

from aem.llm import TransportError


class FakeTransport:
    """Stands in for the Gemini API. `responses` is a list of str (JSON text) or TransportError to raise."""

    def __init__(self, responses=(), models=("gemini-3.8-flash", "gemini-3.5-flash-lite")):
        self.responses = list(responses)
        self.models = set(models)
        self.calls = []
        self.model_checks = []

    def get_model(self, model):
        self.model_checks.append(model)
        if model not in self.models:
            raise TransportError(404, f"models/{model} is not found")

    def generate(self, model, prompt, schema, temperature):
        self.calls.append({"model": model, "prompt": prompt, "schema": schema, "temperature": temperature})
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        if not isinstance(item, str):
            item = json.dumps(item)
        return item, f"{model}-001"


class FakeClock:
    def __init__(self):
        self.t = 1000.0
        self.sleeps = []

    def now(self):
        return self.t

    def sleep(self, s):
        self.sleeps.append(s)
        self.t += s


def as_real_transport(inner):
    """A genuine `GenaiTransport` object whose network methods are replaced by `inner`'s.

    Only for testing what happens *with* real provenance; it never touches the network.
    """
    from aem.llm import GenaiTransport

    t = GenaiTransport.__new__(GenaiTransport)
    t.get_model = inner.get_model
    t.generate = inner.generate
    return t
