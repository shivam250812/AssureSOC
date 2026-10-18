"""Backward-compatible facade forwarding to assuresoc.detection.anomaly."""

import sys
from .detection import anomaly as _mod

sys.modules[__name__] = _mod
