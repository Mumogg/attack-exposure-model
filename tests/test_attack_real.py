"""Checks against the real ATT&CK v19.2 bundle. Skipped if `aem fetch-data` has not been run."""

import pytest

from aem.config import ATTACK_FILE

pytestmark = pytest.mark.skipif(not ATTACK_FILE.exists(), reason="ATT&CK v19.2 no descargado")


@pytest.fixture(scope="module")
def attack():
    from aem.attack_data import AttackData

    return AttackData.load(ATTACK_FILE)


def test_version(attack):
    assert attack.version == "19.2"


def test_v19_split_of_defense_evasion(attack):
    assert "stealth" in attack.tactic_order and "defense-impairment" in attack.tactic_order
    assert "defense-evasion" not in attack.tactic_order
    assert attack.tactic_order[0] == "reconnaissance" and attack.tactic_order[-1] == "impact"


def test_rdp_reference(attack):
    ref = attack.reference_bundle(["T1021.001"])["T1021.001"]
    assert ("M1032", "Multi-factor Authentication") in ref.mitigations
    assert "Logon Session Creation" in ref.data_components
    assert ref.groups
