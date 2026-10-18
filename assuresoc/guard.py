"""Backward-compatible facade forwarding to assuresoc.defense.guard."""

import sys
from .defense import guard as _mod

sys.modules[__name__] = _mod
