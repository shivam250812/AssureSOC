import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["ASSURESOC_OFFLINE"] = "1"  # tests never call the real API

from assuresoc.pipeline import analyse  # noqa: E402
from assuresoc.scenario import generate  # noqa: E402

ANCHOR = datetime(2026, 10, 15, 8, 30, tzinfo=timezone.utc)
NOW = datetime(2026, 10, 15, 11, 10, tzinfo=timezone.utc)


@pytest.fixture(scope="session")
def ws():
    return analyse(generate(ANCHOR), label="test", now=NOW)


@pytest.fixture(scope="session")
def samples():
    return ROOT / "samples"
