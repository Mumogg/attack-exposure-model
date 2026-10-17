from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def mini_attack():
    from aem.attack_data import AttackData

    return AttackData.load(FIXTURES / "mini_attack.json")
