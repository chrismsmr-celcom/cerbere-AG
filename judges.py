"""Compat shim: le code vit dans agentguard/judges.py (inclus dans le wheel pip)."""

from agentguard.judges import *
from agentguard.judges import (  # noqa: F401
    _DIDACTIC_MARKERS,
    _SECRET_SCRUB_PATTERNS,
    _cache_get,
    _cache_key,
    _cache_set,
    _scrub_before_external_call,
)
