"""
Garde-fou dashboard : chaque onclick="fn(...)" doit pointer vers une fonction réellement définie.

Le dashboard sépare maintenant :
- collector/templates/dashboard.html
- collector/static/dashboard.js

Le test doit donc analyser les deux sources.
"""

import re
from pathlib import Path

from collector.dashboard import DASHBOARD_HTML


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


def _onclick_calls():
    calls = set()

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
        assert marker in DASHBOARD_SOURCE, marker

    # Plus de doublon "AI Agents" / "+ Connection",
    # plus d'ancienne bannière jaune.
    assert "approval-pill" not in DASHBOARD_SOURCE
    assert 'onclick="openConnectModal()"' not in DASHBOARD_SOURCE
