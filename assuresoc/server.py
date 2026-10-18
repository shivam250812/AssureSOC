"""Backward-compatible facade forwarding to assuresoc.api.server."""

import sys
from .api import server as _mod

sys.modules[__name__] = _mod
