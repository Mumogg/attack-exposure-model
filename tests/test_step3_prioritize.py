import inspect
import itertools

import pytest
from pydantic import ValidationError

import aem.step3_prioritize as step3
from aem.config import SSVC_TREE_FILE, CoverageConfig
from aem.models import ACTION_ORDER
from aem.step2_coverage import assess_coverage
from aem.step3_prioritize import (
    GLOBAL_QUESTION, AutoAnalyst, InteractiveAnalyst, SsvcTree, chain_order, decide, load_tree, order_for_output,
    prioritize,
)
from helpers import make_org

BASE = {
    ("cubierta", "baja"): "Track", ("cubierta", "media"): "Track", ("cubierta", "alta"): "Track*",
    ("parcial", "baja"): "Track", ("parcial", "media"): "Track*", ("parcial", "alta"): "Attend",
    ("sin cobertura", "baja"): "Track*", ("sin cobertura", "media"): "Attend", ("sin cobertura", "alta"): "Act",
}


@pytest.fixture(scope="module")
def tree():
    return load_tree(SSVC_TREE_FILE)


@pytest.mark.parametrize("cov,crit", list(BASE))
def test_base_table_non_initial_access(tree, cov, crit):
    assert decide(cov, crit, None, False, tree) == BASE[(cov, crit)]


@pytest.mark.parametrize("cov,crit,exp", list(itertools.product(
    ["cubierta", "parcial", "sin cobertura"], ["baja", "media", "alta"], ["internet", "interna", "aislada"])))
def test_initial_access_exposure_shift(tree, cov, crit, exp):
    i = ACTION_ORDER.index(BASE[(cov, crit)])
    shift = {"internet": 1, "interna": 0, "aislada": -1}[exp]
    expected = ACTION_ORDER[min(max(i + shift, 0), len(ACTION_ORDER) - 1)]
    assert decide(cov, crit, exp, True, tree) == expected


def test_shift_caps(tree):
    assert decide("sin cobertura", "alta", "internet", True, tree) == "Act"
    assert decide("cubierta", "baja", "aislada", True, tree) == "Track"


def test_exposure_ignored_outside_initial_access(tree):
    assert decide("parcial", "media", "internet", False, tree) == "Track*"


def test_initial_access_requires_exposure(tree):
    with pytest.raises(ValueError):
        decide("parcial", "media", None, True, tree)


def test_tree_rejects_incomplete_table():
    with pytest.raises(ValidationError):
        SsvcTree.model_validate({"base_table": {"cubierta": {"baja": "Track"}},
                                 "initial_access_exposure_shift": {"internet": 1, "interna": 0, "aislada": -1}})


def test_tree_rejects_unknown_action():
    data = {"base_table": {c: {k: "Panic" for k in ("baja", "media", "alta")}
                           for c in ("cubierta", "parcial", "sin cobertura")},
            "initial_access_exposure_shift": {"internet": 1, "interna": 0, "aislada": -1}}
    with pytest.raises(ValidationError):
        SsvcTree.model_validate(data)


def test_step3_never_uses_llm():
    src = inspect.getsource(step3)
    assert "llm" not in src.lower().replace("no llm", "")


def _setup(mini_attack):
    org = make_org(detections=[("T1059.003", 5, []), ("T1021.001", 2, [])],
                   entries=[("T1190", "web"), ("T1021.001", "web")], default_asset="ws")
    cov = assess_coverage(["T1059.003", "T1021.001", "T1190", "T1078"], org, CoverageConfig())
    return org, cov


def test_prioritize_auto(mini_attack, tree):
    org, cov = _setup(mini_attack)
    items = {i.technique_id: i for i in prioritize(cov, mini_attack, AutoAnalyst(org), tree)}
    t1190 = items["T1190"]
    assert (t1190.coverage_validated, t1190.criticality, t1190.exposure, t1190.action) == (
        "sin cobertura", "alta", "internet", "Act")
    assert t1190.context_source == "analyst_context"
    rdp = items["T1021.001"]
    assert (rdp.criticality, rdp.exposure, rdp.action) == ("alta", None, "Attend")
    cmd = items["T1059.003"]
    assert (cmd.asset_id, cmd.context_source, cmd.action) == ("ws", "default_asset", "Track")
    # T1078 is initial access (multi-tactic) on default asset ws (interna): sin cobertura, media -> Attend
    assert (items["T1078"].exposure, items["T1078"].action) == ("interna", "Attend")
    assert all(i.coverage_original == i.coverage_validated and i.coverage_change_reason == "" for i in items.values())


def test_order_for_output_groups_by_action_then_chain(mini_attack, tree):
    org, cov = _setup(mini_attack)
    ordered = order_for_output(prioritize(cov, mini_attack, AutoAnalyst(org), tree), mini_attack)
    assert [i.technique_id for i in ordered] == ["T1190", "T1078", "T1021.001", "T1059.003"]
    # T1078 (initial-access first in matrix) and T1021.001 are both Attend: chain order decides
    assert [i.action for i in ordered] == ["Act", "Attend", "Attend", "Track"]


def test_chain_order_by_tactic(mini_attack, tree):
    org, cov = _setup(mini_attack)
    ordered = chain_order(prioritize(cov, mini_attack, AutoAnalyst(org), tree), mini_attack)
    assert [i.technique_id for i in ordered] == ["T1078", "T1190", "T1059.003", "T1021.001"]


def test_auto_global_review_is_unanswered(mini_attack, tree):
    org, cov = _setup(mini_attack)
    items = prioritize(cov, mini_attack, AutoAnalyst(org), tree)
    gr = AutoAnalyst(org).global_review(chain_order(items, mini_attack), mini_attack)
    assert gr.question == GLOBAL_QUESTION
    assert gr.answer is None and gr.mode == "auto" and gr.tactics == []
    assert [t.technique_id for t in gr.techniques_shown] == ["T1078", "T1190", "T1059.003", "T1021.001"]


class Scripted:
    def __init__(self, answers):
        self.answers = list(answers)
        self.asked = []

    def __call__(self, prompt, default=None, choices=None):
        self.asked.append(prompt)
        ans = self.answers.pop(0)
        return default if ans == "" else ans


def test_interactive_analyst_overrides_and_records(mini_attack, tree):
    org = make_org(entries=[("T1190", "web")])
    cov = assess_coverage(["T1190"], org, CoverageConfig())
    # coverage: change to parcial + reason; criticality: keep default (alta); exposure: aislada
    ask = Scripted(["parcial", "WAF administrado no registrado en el YAML", "", "aislada"])
    analyst = InteractiveAnalyst(org, ask=ask, console=None)
    [item] = prioritize(cov, mini_attack, analyst, tree)
    assert (item.coverage_original, item.coverage_validated) == ("sin cobertura", "parcial")
    assert item.coverage_change_reason == "WAF administrado no registrado en el YAML"
    assert (item.criticality, item.exposure, item.context_source) == ("alta", "aislada", "interactive")
    assert item.action == "Track*"  # parcial/alta = Attend, aislada -> one level down


def test_interactive_does_not_ask_exposure_outside_initial_access(mini_attack, tree):
    org = make_org()
    cov = assess_coverage(["T1059.003"], org, CoverageConfig())
    ask = Scripted(["", "baja"])
    [item] = prioritize(cov, mini_attack, InteractiveAnalyst(org, ask=ask, console=None), tree)
    assert len(ask.asked) == 2 and item.exposure is None and item.criticality == "baja"


def test_interactive_global_review(mini_attack, tree):
    org = make_org()
    cov = assess_coverage(["T1059.003"], org, CoverageConfig())
    items = prioritize(cov, mini_attack, AutoAnalyst(org), tree)
    ask = Scripted(["si", "Execution, Lateral Movement", "EDR en ejecución"])
    gr = InteractiveAnalyst(org, ask=ask, console=None).global_review(chain_order(items, mini_attack), mini_attack)
    assert (gr.answer, gr.tactics, gr.note, gr.mode) == (True, ["Execution", "Lateral Movement"], "EDR en ejecución",
                                                         "interactive")
    assert GLOBAL_QUESTION in ask.asked[0]
