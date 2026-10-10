"""Compat shim: le code vit dans agentguard/judges.py (inclus dans le wheel pip)."""
from agentguard.judges import *  # noqa: F401,F403
from agentguard.judges import (  # noqa: F401
    _scrub_before_external_call, _cache_key, _cache_get, _cache_set,
    _DIDACTIC_MARKERS, _SECRET_SCRUB_PATTERNS,
)
