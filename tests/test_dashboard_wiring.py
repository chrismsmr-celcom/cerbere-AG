"""Couverture du wiring onclick du dashboard (issue #4).

MISE A JOUR (commit bb413fb "Move dashboard.js to static directory") :
le JS du dashboard a ete externalise vers collector/static/dashboard.js.
Le HTML reste expose par collector.dashboard.DASHBOARD_HTML.
Les handlers (definitions de fonctions, endpoints) vivent desormais
dans le JS ; les id/panneaux et les onclick= restent dans le HTML.
On concatene les deux sources.
"""

import re
from pathlib import Path

from collector.dashboard import DASHBOARD_HTML as _DASHBOARD_HTML

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


def test_every_onclick_handler_is_defined():
    missing = sorted(_onclick_calls() - _defined_functions())
    assert not missing, f"onclick pointe vers des fonctions inexistantes : {missing}"


def test_approval_and_agent_panels_are_present():
    for marker in (
        'id="approvalsPanel"', 'id="agentsPanel"',
        'id="btnApprovals"', 'id="btnAgents"',
        "/api/approvals?status=", "/api/agents",
        "toggleAgent(", "resolveApproval(",
    ):
        assert marker in DASHBOARD_COMBINED, marker