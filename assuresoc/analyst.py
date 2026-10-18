"""Backward-compatible facade forwarding to assuresoc.intelligence.analyst."""

import sys
from .intelligence import analyst as _mod

sys.modules[__name__] = _mod
