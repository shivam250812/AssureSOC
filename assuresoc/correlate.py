"""Backward-compatible facade forwarding to assuresoc.detection.correlate."""

import sys
from .detection import correlate as _mod

sys.modules[__name__] = _mod
