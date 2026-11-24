"""Native integrations for AI coding-agent hook protocols."""

from .hooks import normalize_hook_event
from .registry import Integration, get_integration, list_integrations

__all__ = [
    "Integration",
    "get_integration",
    "list_integrations",
    "normalize_hook_event",
]
