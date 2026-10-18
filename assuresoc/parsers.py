"""Backward-compatible facade forwarding to assuresoc.ingestion.parsers."""

import sys
from .ingestion import parsers as _mod

sys.modules[__name__] = _mod
