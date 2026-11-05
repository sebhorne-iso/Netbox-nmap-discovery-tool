import sys
from pathlib import Path

import pytest

# Make the repository importable without installing it; the engine has no NetBox dependency.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixture_text():
    def load(name):
        return (FIXTURES / name).read_text()
    return load
