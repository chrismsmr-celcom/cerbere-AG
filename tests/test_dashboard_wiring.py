"""Couverture du wiring onclick du dashboard (issue #4).

MISE A JOUR (commit bb413fb "Move dashboard.js to static directory") :
le JS du dashboard a ete externalise vers collector/static/dashboard.js.
Le HTML reste expose par collector.dashboard.DASHBOARD_HTML.
Les handlers (definitions de fonctions, endpoints) vivent desormais
dans le JS ; les id/panneaux et les onclick= restent dans le HTML.
On concatene les deux sources.
"""
<<<<<<< HEAD
=======
Garde-fou dashboard : chaque onclick="fn(...)" doit pointer vers une fonction réellement définie.

Le dashboard sépare maintenant :
- collector/templates/dashboard.html
- collector/static/dashboard.js

Le test doit donc analyser les deux sources.
"""
>>>>>>> 29287aae0d099b19152f3113c66925a501bd24c4

import re
from pathlib import Path

from collector.dashboard import DASHBOARD_HTML as _DASHBOARD_HTML

<<<<<<< HEAD
_STATIC_DIR = Path(__file__).resolve().parents[1] / "collector" / "static"
_JS_PATH = _STATIC_DIR / "dashboard.js"

# Retro-compatible : si le JS n'est pas (encore) externalise,
# DASHBOARD_HTML contient deja tout et la combined = HTML seul.
if _JS_PATH.exists():
    DASHBOARD_COMBINED = (
        _DASHBOARD_HTML
        + "\n"
        + _JS_PATH.read_text(encoding="utf-8")
    )
else:
    DASHBOARD_COMBINED = _DASHBOARD_HTML
=======

DASHBOARD_JS = (
    Path(__file__).resolve().parents[1]
    / "collector"
    / "static"
    / "dashboard.js"
).read_text(encoding="utf-8")


# Source complète utilisée uniquement pour vérifier les fonctions JavaScript.
DASHBOARD_SOURCE = DASHBOARD_HTML + "\n" + DASHBOARD_JS


BUILTINS = {
    "if",
    "event",
    "this",
    "stopPropagation",
    "preventDefault",
    "closest",
    "querySelector",
    "getElementById",
    "contains",
    "add",
    "remove",
    "toggle",
    "focus",
    "select",
    "click",
}


def _defined_functions():
    names = set(
        re.findall(
            r"function\s+([A-Za-z_$][\w$]*)\s*\(",
            DASHBOARD_SOURCE,
        )
    )

    names |= set(
        re.findall(
            r"window\.([A-Za-z_$][\w$]*)\s*=\s*function",
            DASHBOARD_SOURCE,
        )
    )

    names |= set(
        re.findall(
            r"(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*="
            r"\s*(?:async\s*)?(?:function|\()",
            DASHBOARD_SOURCE,
        )
    )

    return names
>>>>>>> 29287aae0d099b19152f3113c66925a501bd24c4


def _onclick_calls():
    """Noms des fonctions appelees directement depuis les onclick du HTML.

    Les handlers inline peuvent contenir du JavaScript de controle,
    par exemple:
        onclick="if(event.target===this)closeHelpModal()"

    Dans ce cas, ``if`` est un mot-cle du langage et non une fonction
    appelee par le dashboard ; on cherche donc les appels de fonctions
    presents dans l'expression et on ignore les mots-cles JavaScript.
    """
    calls = set()

<<<<<<< HEAD
    for handler in re.findall(r'onclick="([^"]*)"', _DASHBOARD_HTML):
        # Tous les appels de fonctions presents dans le handler.
        for name in re.findall(r'\b([A-Za-z_$][\w$]*)\s*\(', handler):
            if name not in {"if", "for", "while", "switch", "catch", "with"}:
                calls.add(name)

    return calls

def _defined_functions():
    """Fonctions definies dans le JS (ou dans un <script> inline)."""
    return (
        set(re.findall(r'function\s+(\w+)\s*\(', DASHBOARD_COMBINED))
        | set(re.findall(r'(?:^|\n)\s*(\w+)\s*:\s*function\s*\(', DASHBOARD_COMBINED))
        | set(re.findall(r'(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\(', DASHBOARD_COMBINED))
    )
=======
    for value in re.findall(
        r'onclick=\\?"([^"]*)\\?"',
        DASHBOARD_HTML,
    ):
        for name in re.findall(
            r"([A-Za-z_$][\w$]*)\s*\(",
            value,
        ):
            calls.add(name)

    return calls - BUILTINS
>>>>>>> 29287aae0d099b19152f3113c66925a501bd24c4


def test_every_onclick_handler_is_defined():
    missing = sorted(_onclick_calls() - _defined_functions())

    assert not missing, (
        "onclick pointe vers des fonctions inexistantes : "
        f"{missing}"
    )


def test_approval_and_agent_panels_are_present():
    for marker in (
<<<<<<< HEAD
        'id="approvalsPanel"', 'id="agentsPanel"',
        'id="btnApprovals"', 'id="btnAgents"',
        "/api/approvals?status=", "/api/agents",
        "toggleAgent(", "resolveApproval(",
    ):
        assert marker in DASHBOARD_COMBINED, marker
=======
        'id="approvalsPanel"',
        'id="agentsPanel"',
        'id="btnApprovals"',
        'id="btnAgents"',
        "/api/approvals?status=",
        "/api/agents",
        "toggleAgent(",
        "resolveApproval(",
    ):
        assert marker in DASHBOARD_SOURCE, marker

    # Plus de doublon "AI Agents" / "+ Connection",
    # plus d'ancienne bannière jaune.
    assert "approval-pill" not in DASHBOARD_SOURCE
    assert 'onclick="openConnectModal()"' not in DASHBOARD_SOURCE
>>>>>>> 29287aae0d099b19152f3113c66925a501bd24c4

