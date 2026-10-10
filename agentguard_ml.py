"""Compat shim: le code vit dans agentguard/ml.py (inclus dans le wheel pip)."""
from agentguard.ml import *  # noqa: F401,F403
from agentguard.ml import MLDetector, TORCH_AVAILABLE  # noqa: F401
try:  # InjectionDetector n'existe peut-etre pas selon la version
    from agentguard.ml import InjectionDetector  # noqa: F401
except ImportError:
    pass
