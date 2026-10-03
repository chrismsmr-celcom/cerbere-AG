"""Démo : une action sensible attend l'approbation d'un humain, puis reprend.

Scénario :
    Un agent "finance-bot" prépare un export clients et veut l'envoyer par
    email à une adresse personnelle (gmail.com). La règle DLP de Cerbère
    suspend l'action et crée une demande dans la file "Approvals" du
    dashboard.

    L'agent attend. Un humain (CISO) clique sur Approve, et l'agent reprend
    automatiquement, sans nouvel appel ni changement de code.

    Sur Reject, l'action est bloquée.

Prérequis :
    - un collector joignable avec dashboard ;
    - une clé API valide.

PowerShell :
    $env:AGENTGUARD_COLLECTOR_URL="https://app.cerbereag.site"
    $env:AGENTGUARD_API_KEY="ag-..."
    python examples/approval_demo.py

Linux/macOS :
    export AGENTGUARD_COLLECTOR_URL=https://app.cerbereag.site
    export AGENTGUARD_API_KEY=ag-...
    python examples/approval_demo.py

Pendant la démo :
    Ouvrez le dashboard et cliquez sur "Approvals".

Options :
    --agent-id NAME
        Identité de l'agent dans le dashboard.
        Défaut : finance-bot

    --timeout SEC
        Durée maximale d'attente d'une décision.
        Défaut : 300

    --to ADDRESS
        Destinataire de l'email.
        Utilisez un domaine personnel (ex. gmail.com) pour déclencher
        la règle DLP correspondante.

Chaque exécution utilise un identifiant d'export unique. L'identifiant
d'approbation est déterministe (agent + outil + paramètres), donc sans
cet identifiant unique, une approbation déjà accordée lors d'une exécution
précédente pourrait libérer immédiatement l'action.
"""

import argparse
import logging
import os
import sys
import time
import uuid

import requests

# Permet l'exécution directe depuis la racine du repository.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Réduire le bruit du SDK pendant la démo.
logging.disable(logging.CRITICAL)

import structlog  # noqa: E402

structlog.configure(
    wrapper_class=structlog.make_filtering_bound_logger(logging.CRITICAL)
)

from agentguard.models import (  # noqa: E402
    ApprovalRejectedException,
    ApprovalRequiredException,
    SecurityException,
)
from agentguard.sdk import AgentGuard  # noqa: E402


# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------

parser = argparse.ArgumentParser(
    description="Cerbère human-approval demo"
)

parser.add_argument(
    "--agent-id",
    default="finance-bot",
    help="Identity of the agent in the dashboard (default: finance-bot)",
)

parser.add_argument(
    "--timeout",
    type=float,
    default=300.0,
    help="Maximum time to wait for a human decision, in seconds (default: 300)",
)

parser.add_argument(
    "--to",
    default="j.martin@gmail.com",
    help="Email recipient; use a personal domain to trigger the DLP rule",
)

args = parser.parse_args()


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

url = os.getenv(
    "AGENTGUARD_COLLECTOR_URL",
    "http://localhost:8080",
).rstrip("/")

api_key = os.getenv("AGENTGUARD_API_KEY")


def fail(msg: str) -> None:
    """Print a fatal error and exit."""
    print(f"\n✗ {msg}")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Vérifications avant de lancer la scène
# ---------------------------------------------------------------------------

if not api_key:
    fail(
        "AGENTGUARD_API_KEY is not set "
        "(the approval request must reach your dashboard)."
    )

try:
    health_url = f"{url}/health"

    health_response = requests.get(
        health_url,
        timeout=15,
    )

    health_response.raise_for_status()

except requests.exceptions.Timeout as exc:
    fail(
        f"Collector health check timed out at {health_url}. "
        f"Exception: {type(exc).__name__}: {exc!r}"
    )

except requests.exceptions.RequestException as exc:
    fail(
        f"Collector health check failed at {health_url}. "
        f"Exception: {type(exc).__name__}: {exc!r}"
    )

except Exception as exc:
    fail(
        f"Unexpected error while checking collector at {health_url}. "
        f"Exception: {type(exc).__name__}: {exc!r}"
    )


# ---------------------------------------------------------------------------
# AgentGuard
# ---------------------------------------------------------------------------

guard = AgentGuard(
    collector_url=url,
    api_key=api_key,
    agent_id=args.agent_id,
    wait_for_approval=True,
    approval_timeout=args.timeout,
    approval_poll_interval=1.0,
)


# ---------------------------------------------------------------------------
# Identifiant unique de cette exécution
# ---------------------------------------------------------------------------

export_id = uuid.uuid4().hex[:8]


# ---------------------------------------------------------------------------
# Outils de l'agent
# ---------------------------------------------------------------------------

@guard.guard_tool_call("query_customers")
def query_customers(segment: str) -> str:
    return (
        f"3 customer records for segment '{segment}' "
        f"(export {export_id})"
    )


@guard.guard_tool_call("send_email")
def send_email(
    to: str,
    subject: str,
    body: str,
) -> str:
    return f"email sent to {to}"


def step(number: int, title: str) -> None:
    """Print a numbered demo step."""
    print(f"\n[{number}] {title}")


# ---------------------------------------------------------------------------
# Démo
# ---------------------------------------------------------------------------

print(f"Agent '{args.agent_id}' connected to {url}")

step(1, "The agent prepares a customer export")

rows = query_customers(segment="enterprise")

print("    ✓", rows)

step(
    2,
    f"The agent emails the export to a personal address ({args.to})",
)

print(
    "    ⏳ Cerbère paused the action. "
    "Waiting for a human decision..."
)

print("       Open the dashboard → Approvals")

started = time.time()

try:
    result = send_email(
        to=args.to,
        subject=f"customer export {export_id}",
        body=f"Enterprise customer export, reference {export_id}.",
    )

except ApprovalRejectedException as exc:
    step(3, "A human rejected the request")

    reviewer = getattr(exc, "resolved_by", None) or "unknown"

    print(
        f"    ✗ BLOCKED, not executed "
        f"(reviewer: {reviewer})"
    )

    sys.exit(0)

except ApprovalRequiredException as exc:
    step(3, "No decision in time")

    print(f"    ✗ NOT EXECUTED: {exc}")

    sys.exit(0)

except SecurityException as exc:
    step(3, "Blocked before reaching the approval queue")

    message = str(exc).replace("\U0001f6a8 ", "")

    print("    ✗", message)

    sys.exit(0)


# ---------------------------------------------------------------------------
# Résultat
# ---------------------------------------------------------------------------

step(3, "A human approved the request")

elapsed = time.time() - started

print(
    f"    ✓ {result} "
    f"(decision after {elapsed:.0f}s, "
    "no code change, no second call)"
)


# ---------------------------------------------------------------------------
# Trace
# ---------------------------------------------------------------------------

step(4, "Trace recorded")

for span in guard.spans:
    tool = span.input_data.get("tool", "-")
    status = "BLOCKED" if span.blocked else "allowed"
    taint = span.taint_level or "-"
    risk = span.risk_score

    print(
        f"    {tool:<16} "
        f"{status:<8} "
        f"taint={taint:<7} "
        f"risk={risk}"
    )
