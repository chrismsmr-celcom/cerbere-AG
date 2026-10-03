"""Démo : une action sensible attend l'approbation d'un humain, puis reprend.

Scénario : un agent "finance-bot" prépare un export clients et veut l'envoyer
par email à une adresse PERSONNELLE (gmail.com). La règle DLP de Cerbère
suspend l'action et crée une demande dans la file "Approvals" du dashboard.
L'agent attend. Un humain (CISO) clique sur Approve, et l'agent reprend
tout seul, sans nouvel appel ni changement de code. Sur Reject, l'action est bloquée.

Prérequis : un collector joignable (avec dashboard) et une clé API.

    export AGENTGUARD_COLLECTOR_URL=https://app.cerbereag.site   # ou http://localhost:8080
    export AGENTGUARD_API_KEY=ag-...
    python examples/approval_demo.py

Pendant la démo : ouvrez le dashboard, bouton "Approvals" dans la barre du haut.

Options :
    --agent-id NAME   identité de l'agent dans le dashboard (défaut : finance-bot)
    --timeout SEC     durée max d'attente d'une décision (défaut : 300)
    --to ADDRESS      destinataire (doit être un domaine personnel pour déclencher la règle)

Chaque exécution utilise un identifiant d'export unique : l'identifiant d'approbation
est déterministe (agent + outil + paramètres), donc sans ça une approbation déjà
accordée lors d'une prise précédente libérerait l'action immédiatement.
"""
import argparse
import logging
import os
import sys
import time
import uuid

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # exécution depuis le repo

logging.disable(logging.CRITICAL)

import structlog                                                       # noqa: E402
structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.CRITICAL))

from agentguard.sdk import AgentGuard                                  # noqa: E402
from agentguard.models import (                                        # noqa: E402
    ApprovalRejectedException,
    ApprovalRequiredException,
    SecurityException,
)

parser = argparse.ArgumentParser(description="Cerbère human-approval demo")
parser.add_argument("--agent-id", default="finance-bot")
parser.add_argument("--timeout", type=float, default=300.0)
parser.add_argument("--to", default="j.martin@gmail.com")
args = parser.parse_args()

url = os.getenv("AGENTGUARD_COLLECTOR_URL", "http://localhost:8080").rstrip("/")
api_key = os.getenv("AGENTGUARD_API_KEY")


def fail(msg: str) -> None:
    print(f"\n✗ {msg}")
    sys.exit(1)


# ── Vérifications avant de lancer la scène ──────────────────────────────────
if not api_key:
    fail("AGENTGUARD_API_KEY is not set (the approval request must reach your dashboard).")
try:
    requests.get(f"{url}/health", timeout=5).raise_for_status()
except Exception as exc:
    fail(f"Collector not reachable at {url} ({exc.__class__.__name__}).")

guard = AgentGuard(
    collector_url=url,
    api_key=api_key,
    agent_id=args.agent_id,
    wait_for_approval=True,
    approval_timeout=args.timeout,
    approval_poll_interval=1.0,
)

export_id = uuid.uuid4().hex[:8]


# ── Deux outils "normaux" de l'agent ────────────────────────────────────────
@guard.guard_tool_call("query_customers")
def query_customers(segment: str) -> str:
    return f"3 customer records for segment '{segment}' (export {export_id})"


@guard.guard_tool_call("send_email")
def send_email(to: str, subject: str, body: str) -> str:
    return f"email sent to {to}"


def step(n, title):
    print(f"\n[{n}] {title}")


print(f"Agent '{args.agent_id}' connected to {url}")

step(1, "The agent prepares a customer export")
rows = query_customers(segment="enterprise")
print("    ✓", rows)

step(2, f"The agent emails the export to a personal address ({args.to})")
print("    ⏳ Cerbère paused the action. Waiting for a human decision...")
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
    print(f"    ✗ BLOCKED, not executed (reviewer: {exc.resolved_by or 'unknown'})")
    sys.exit(0)
except ApprovalRequiredException as exc:
    step(3, "No decision in time")
    print(f"    ✗ NOT EXECUTED: {exc}")
    sys.exit(0)
except SecurityException as exc:
    step(3, "Blocked before reaching the approval queue")
    print("    ✗", str(exc).replace("\U0001f6a8 ", ""))
    sys.exit(0)

step(3, "A human approved the request")
print(f"    ✓ {result}  (decision after {time.time() - started:.0f}s, no code change, no second call)")

step(4, "Trace recorded")
for s in guard.spans:
    tool = s.input_data.get("tool")
    status = "BLOCKED" if s.blocked else "allowed"
    print(f"    {tool:<16} {status:<8} taint={s.taint_level or '-':<7} risk={s.risk_score}")
