"""Auto-instrumentation : bloque l'exfiltration de données sensibles via requests.

Points clés de sécurité :
- Les patchs ne sont appliqués qu'à l'appel explicite de
  ``enable_auto_instrumentation()`` — JAMAIS à l'import du module.
- Patch direct des fonctions de module de ``requests`` (post/get/...),
  SANS wrapt : aucune dépendance à une extension C fragile selon la
  version de CPython (wrapt échouait silencieusement sur Python 3.14).
- Une seule fois par process, avec restauration en cas d'échec partiel.
- Les requêtes vers le collector Cerbere sont exemptées : le SDK doit
  toujours pouvoir envoyer sa télémétrie (masquée) et interroger les
  approbations, sinon un blocage créerait un deadlock.
"""

from __future__ import annotations

import logging
from typing import Any

import requests

from .models import SecurityException
from .taint import FlowTracker, TaintLevel

logger = logging.getLogger(__name__)

_taint_tracker: FlowTracker | None = None
_excluded_urls: tuple[str, ...] = ()
_instrumented = False
_originals: dict[str, Any] = {}

# Surface interceptée : les fonctions de module de requests.
# (requests.Session.request appelé directement n'est PAS intercepté —
# les agents qui bypassent l'API module doivent utiliser guard_tool_call.)
PATCHED_METHODS = ("post", "put", "patch", "delete", "get", "head", "options")


def set_taint_tracker(
    tracker: FlowTracker | None,
    excluded_urls: tuple[str, ...] = (),
) -> None:
    """Branche le tracker de taint utilisé par les wrappers.

    ``excluded_urls`` : préfixes d'URL jamais bloqués (le collector).
    """
    global _taint_tracker, _excluded_urls
    _taint_tracker = tracker
    _excluded_urls = tuple(excluded_urls)


def _url_of(args: tuple, kwargs: dict) -> str:
    url = kwargs.get("url")
    if not url and args:
        url = args[0]
    return url if isinstance(url, str) else ""


def _payloads_of(args: tuple, kwargs: dict) -> list[Any]:
    """Données sortantes potentiellement contaminées."""
    payloads = []
    for key in ("json", "data", "params"):
        value = kwargs.get(key)
        if value is not None:
            payloads.append(value)
    return payloads


def _check_for_taint(args: tuple, kwargs: dict) -> None:
    """Lève SecurityException si un payload contient des données marquées.

    ATTENTION : FlowTracker.level_in() renvoie TOUJOURS un TaintLabel
    (PUBLIC au minimum) — on teste le niveau, jamais la vérité de l'objet.
    """
    if _taint_tracker is None:
        return

    url = _url_of(args, kwargs)

    for excluded in _excluded_urls:
        if excluded and url.startswith(excluded):
            return

    for payload in _payloads_of(args, kwargs):
        if _taint_tracker.level_in(payload).level >= TaintLevel.SECRET:
            raise SecurityException(
                "AgentGuard BLOCK: exfiltration de données sensibles "
                "détectée (taint tracking)"
            )


def _make_wrapper(method: str, original: Any):
    def _wrapper(*args: Any, **kwargs: Any):
        _check_for_taint(args, kwargs)
        logger.debug("auto_instrument_validated", method=method)
        return original(*args, **kwargs)

    return _wrapper


def enable_auto_instrumentation() -> None:
    """Patche requests (une seule fois par process).

    À appeler explicitement au démarrage de l'agent, jamais à l'import.
    """
    global _instrumented

    if _instrumented:
        return

    _instrumented = True

    try:
        for method in PATCHED_METHODS:
            original = getattr(requests, method)
            _originals[method] = original
            setattr(requests, method, _make_wrapper(method, original))

        logger.info(
            "auto_instrument_enabled",
            extra={"methods": list(PATCHED_METHODS)},
        )

    except Exception as exc:
        # Restaure tout en cas d'échec partiel : jamais de patch à moitié.
        for method, original in _originals.items():
            setattr(requests, method, original)
        _originals.clear()
        _instrumented = False
        logger.warning("auto_instrument_failed: %s", exc)


def disable_auto_instrumentation() -> None:
    """Restaure les fonctions originales (tests, arrêt propre)."""
    global _instrumented

    for method, original in _originals.items():
        setattr(requests, method, original)
    _originals.clear()
    _instrumented = False
