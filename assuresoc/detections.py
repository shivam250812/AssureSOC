"""Backward-compatible facade forwarding to assuresoc.detection.rules."""

import sys
from .detection import rules as _mod

sys.modules[__name__] = _mod
