"""Couverture du wiring onclick du dashboard (issue #4).

Le JS du dashboard a ete externalise vers collector/static/dashboard.js
(commit bb413fb "Move dashboard.js to static directory").
Le HTML reste expose par collector.dashboard.DASHBOARD_HTML.
Les handlers (definitions de fonctions, endpoints) vivent desormais
dans le JS ; les id/panneaux et les onclick= restent dans le HTML.
On analyse donc les deux sources.
"""

import re
from pathlib import Path

from collector.dashboard import DASHBOARD_HTML as _DASHBOARD_HTML

_STATIC_DIR = Path(__file__).resolve().parents[1] / "collector" / "static"
_JS_PATH = _STATIC_DIR / "dashboard.js"

# Retro-compatible : si le JS n'est pas (encore) externalise,
# DASHBOARD_HTML contient deja tout et la source combinee = HTML seul.
if _JS_PATH.exists():
    DASHBOARD_COMBINED = _DASHBOARD_HTML + "\n" + _JS_PATH.read_text(encoding="utf-8")
else:
    DASHBOARD_COMBINED = _DASHBOARD_HTML

# Mots-cles JS et methodes DOM qui apparaissent dans les handlers inline
# mais ne sont pas des fonctions definies par le dashboard.
_IGNORED_CALLS = {
    "if", "for", "while", "switch", "catch", "with",
    "stopPropagation", "preventDefault", "closest", "querySelector",
    "getElementById", "contains", "add", "remove", "toggle",
    "focus", "select", "click",
}


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

    for handler in re.findall(r'onclick=\\?"([^"]*)\\?"', _DASHBOARD_HTML):
        for name in re.findall(r"\b([A-Za-z_$][\w$]*)\s*\(", handler):
            calls.add(name)

    return calls - _IGNORED_CALLS


def _defined_functions():
    """Fonctions definies dans le JS (ou dans un <script> inline)."""
    src = DASHBOARD_COMBINED
    return (
        set(re.findall(r"function\s+([A-Za-z_$][\w$]*)\s*\(", src))
        | set(re.findall(r"window\.([A-Za-z_$][\w$]*)\s*=\s*function", src))
        | set(re.findall(r"(?:^|\n)\s*(\w+)\s*:\s*function\s*\(", src))
        | set(
            re.findall(
                r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function|\()",
                src,
            )
        )
    )


def test_every_onclick_handler_is_defined():
    missing = sorted(_onclick_calls() - _defined_functions())

    assert not missing, (
        "onclick pointe vers des fonctions inexistantes : "
        f"{missing}"
    )


def test_approval_and_agent_panels_are_present():
    for marker in (
        'id="approvalsPanel"',
        'id="agentsPanel"',
        'id="btnApprovals"',
        'id="btnAgents"',
        "/api/approvals?status=",
        "/api/agents",
        "toggleAgent(",
        "resolveApproval(",
    ):
        assert marker in DASHBOARD_COMBINED, marker

    # Plus de doublon "AI Agents" / "+ Connection",
    # plus d'ancienne banniere jaune.
    assert "approval-pill" not in DASHBOARD_COMBINED
    assert 'onclick="openConnectModal()"' not in DASHBOARD_COMBINED
