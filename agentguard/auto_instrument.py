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
- Plusieurs agents dans un même process : TOUS les trackers enregistrés sont
  consultés (un secret connu d'un agent est bloqué pour tous), et l'exemption
  "collector" d'un agent ne s'applique qu'à SON propre tracker.
- Couverture : fonctions de module de ``requests`` ET ``Session.request``
  (donc ``requests.Session().post(...)``). NON couverts : httpx, aiohttp,
  urllib3 direct, sockets natifs, sous-processus (curl...).
"""

from __future__ import annotations

import inspect
import logging
import os
import threading
from typing import Any

import requests

from .models import SecurityException
from .taint import FlowTracker, TaintLevel

logger = logging.getLogger(__name__)

# Registre des trackers (un par AgentGuard) -> préfixes d'URL exemptés POUR CE
# tracker uniquement. Références FORTES (set_taint_tracker(FlowTracker()) doit
# continuer à fonctionner) : AgentGuard désenregistre son tracker quand il est
# libéré (weakref.finalize), voir remove_taint_tracker().
_trackers: dict[FlowTracker, tuple[str, ...]] = {}
_registry_lock = threading.RLock()
_instrumented = False
_originals: dict[str, Any] = {}
_session_original: Any = None
_reentry = threading.local()

# Surface interceptée : fonctions de module de requests + Session.request.
PATCHED_METHODS = ("post", "put", "patch", "delete", "get", "head", "options")

# ── Matrice de décision d'egress HTTP ───────────────────────────────────────
# Explicite, plutôt qu'une comparaison numérique des niveaux (qui mélange
# sensibilité et confiance dans la provenance).
#   CONFIDENTIAL (PII) : autorisé par défaut (une adresse e-mail dans un appel
#   API légitime est courante) ; AGENTGUARD_HTTP_BLOCK_CONFIDENTIAL=true bloque.
_EGRESS_BLOCK = {
    TaintLevel.SECRET,
    TaintLevel.UNTRUSTED,
    TaintLevel.MALICIOUS,
}


def egress_decision(level: TaintLevel) -> str:
    """'allow' ou 'block' pour un niveau de taint sortant en HTTP."""
    if level in _EGRESS_BLOCK:
        return "block"
    if level == TaintLevel.CONFIDENTIAL and os.environ.get(
        "AGENTGUARD_HTTP_BLOCK_CONFIDENTIAL", ""
    ).lower() in {"1", "true", "yes", "on"}:
        return "block"
    return "allow"


def set_taint_tracker(
    tracker: FlowTracker | None,
    excluded_urls: tuple[str, ...] = (),
) -> None:
    """Enregistre un tracker de taint consulté par les wrappers.

    Plusieurs trackers peuvent coexister (un par agent) : ils s'ajoutent au lieu
    de se remplacer. ``excluded_urls`` : préfixes d'URL jamais bloqués POUR CE
    tracker (le collector de cet agent). ``None`` désenregistre tous les trackers.
    """
    with _registry_lock:
        if tracker is None:
            _trackers.clear()
            return
        _trackers[tracker] = tuple(excluded_urls)


def remove_taint_tracker(tracker: FlowTracker) -> None:
    """Désenregistre un tracker (fin de vie d'un agent)."""
    with _registry_lock:
        _trackers.pop(tracker, None)


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
    with _registry_lock:
        trackers = list(_trackers.items())
    if not trackers:
        return

    url = _url_of(args, kwargs)
    payloads = _payloads_of(args, kwargs)
    if not payloads:
        return

    all_excluded = [ex for _, excl in trackers for ex in excl if ex]

    for tracker, excluded_urls in trackers:
        # Exemption propre à CE tracker uniquement.
        if any(ex and url.startswith(ex) for ex in excluded_urls):
            continue
        for payload in payloads:
            label = tracker.level_in(payload)
            # Un tracker saturé (plancher fail-closed) ne doit pas bloquer la
            # télémétrie / le polling d'approbation d'un AUTRE agent vers son
            # collector : seules les valeurs réellement suivies comptent là.
            if label.source == "tracker_saturated" and any(
                url.startswith(ex) for ex in all_excluded
            ):
                continue
            if egress_decision(label.level) == "block":
                raise SecurityException(
                    "AgentGuard BLOCK: exfiltration de données sensibles "
                    f"détectée (taint tracking, niveau {label.level.name})"
                )


def _make_wrapper(method: str, original: Any):
    def _wrapper(*args: Any, **kwargs: Any):
        _check_for_taint(args, kwargs)
        # logging stdlib : pas de kwargs libres (TypeError dès que le niveau
        # DEBUG est actif), on formate le message.
        logger.debug("auto_instrument_validated method=%s", method)
        # Les fonctions de module passent ensuite par Session.request : on évite
        # le double contrôle.
        _reentry.active = True
        try:
            return original(*args, **kwargs)
        finally:
            _reentry.active = False

    return _wrapper


_SESSION_SIG = None


def _make_session_wrapper(original: Any):
    def _session_request(self, *args: Any, **kwargs: Any):
        if getattr(_reentry, "active", False):
            return original(self, *args, **kwargs)
        # Session.request(method, url, params, data, headers, ..., json=...)
        global _SESSION_SIG
        if _SESSION_SIG is None:
            _SESSION_SIG = inspect.signature(original)
        try:
            bound = _SESSION_SIG.bind_partial(self, *args, **kwargs)
            normalized = {
                k: v
                for k, v in bound.arguments.items()
                if k in ("url", "params", "data", "json")
            }
        except TypeError:
            normalized = dict(kwargs)
        _check_for_taint((), normalized)
        return original(self, *args, **kwargs)

    return _session_request


def enable_auto_instrumentation() -> None:
    """Patche requests (une seule fois par process).

    À appeler explicitement au démarrage de l'agent, jamais à l'import.
    """
    global _instrumented, _session_original

    if _instrumented:
        return

    _instrumented = True

    try:
        for method in PATCHED_METHODS:
            original = getattr(requests, method)
            _originals[method] = original
            setattr(requests, method, _make_wrapper(method, original))

        # Sessions (requests.Session().post(...), clients qui réutilisent une session).
        _session_original = requests.sessions.Session.request
        requests.sessions.Session.request = _make_session_wrapper(_session_original)

        logger.info(
            "auto_instrument_enabled",
            extra={"methods": list(PATCHED_METHODS)},
        )

    except Exception as exc:
        # Restaure tout en cas d'échec partiel : jamais de patch à moitié.
        for method, original in _originals.items():
            setattr(requests, method, original)
        _originals.clear()
        if _session_original is not None:
            requests.sessions.Session.request = _session_original
            _session_original = None
        _instrumented = False
        logger.warning("auto_instrument_failed: %s", exc)


def disable_auto_instrumentation() -> None:
    """Restaure les fonctions originales (tests, arrêt propre)."""
    global _instrumented, _session_original

    for method, original in _originals.items():
        setattr(requests, method, original)
    _originals.clear()
    if _session_original is not None:
        requests.sessions.Session.request = _session_original
        _session_original = None
    _instrumented = False
