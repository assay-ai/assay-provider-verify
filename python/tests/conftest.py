import json
from pathlib import Path

import pytest

VECTORS = Path(__file__).resolve().parents[2] / "test-vectors"


@pytest.fixture(scope="session")
def v1():
    return json.loads((VECTORS / "v1.json").read_text())


@pytest.fixture(scope="session")
def neg():
    return json.loads((VECTORS / "negative.json").read_text())
