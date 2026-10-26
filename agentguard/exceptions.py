"""Module de compatibilité.

Les exceptions AgentGuard vivent historiquement dans ``agentguard.models``.
Ce module réexporte les classes pour les outils/tests générés qui importent
``agentguard.exceptions``.
"""

from .models import (
    AgentDisconnectedException,
    ApprovalRejectedException,
    ApprovalRequiredException,
    SecurityException,
)

__all__ = [
    "AgentDisconnectedException",
    "ApprovalRejectedException",
    "ApprovalRequiredException",
    "SecurityException",
]
