"""Backward-compatible facade forwarding to assuresoc.core.models."""

import sys
from .core import models as _mod

sys.modules[__name__] = _mod
