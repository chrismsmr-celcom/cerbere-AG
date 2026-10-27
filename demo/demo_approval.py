"""demo_approval.py — Démo Cerbère AG : une action requiert l'approbation humaine.

Scénario (~60 s à l'écran, plus le temps de réflexion humain) :
  1. finance-bot prépare un export client (normal, pas d'approbation)
  2. il tente de l'envoyer vers une adresse personnelle Gmail
  3. Cerbère met l'action EN PAUSE et pousse une demande dans le dashboard
  4. un humain clique Approve ou Reject dans Approvals
  5. l'agent reprend exactement là où il s'était arrêté

Usage (PowerShell) :
  $env:CERBERE_API_KEY="ag_live_..."      # clé NEUVE générée depuis le dashboard
  $env:CERBERE_URL="https://app.cerbereag.site"
  python demo_approval.py
"""

import os
import time

import requests

from agentguard import (
    AgentGuard,
    ApprovalRejectedException,
    ApprovalRequiredException,
    SecurityException,
)

COLLECTOR = os.environ.get("CERBERE_URL", "https://app.cerbereag.site")
API_KEY = os.environ["CERBERE_API_KEY"]
PAUSE = float(os.environ.get("DEMO_PAUSE", "2.5"))


def preflight() -> None:
    for _ in range(3):
        try:
            r = requests.get(f"{COLLECTOR}/healthz", timeout=30)
        except requests.RequestException as e:
            print(f"✗ collector unreachable: {e}")
            raise SystemExit(1) from e
        if r.status_code != 200:
            print(f"✗ collector unhealthy (HTTP {r.status_code})")
            raise SystemExit(1)
    print("✓ Collector reachable")


def say(msg, color="36"):
    print(f"\n\033[{color}m{msg}\033[0m")
    time.sleep(PAUSE)


# ── Outils simulés du finance-bot ─────────────────────────────────────
def query_customers(segment):
    return f"3 customer records for segment '{segment}' (export 6700a20d)"


def export_csv(segment):
    return "customer_export_2026-10-19.csv (12.4 KB, 3 rows)"


def send_email(to, subject, body):
    return f"email sent to {to}: '{subject}'"


preflight()

guard = AgentGuard(
    collector_url=COLLECTOR,
    api_key=API_KEY,
    agent_id="finance-bot",
    wait_for_approval=True,  # ← l'agent se MET EN PAUSE et attend le clic humain
    approval_timeout=300,  # 5 min pour que l'humain décide pendant la démo
    approval_poll_interval=1.0,
)

# ── 1. Travail normal — aucune friction ──────────────────────────────
say("● finance-bot works normally — routine data task", "36")
out = guard.guard_tool_call(
    "query_customers", params={"segment": "enterprise"}, func=query_customers
)
print(f"  ✓ query_customers → {out}")

csv = guard.guard_tool_call(
    "export_csv", params={"segment": "enterprise"}, func=export_csv
)
print(f"  ✓ export_csv → {csv}")

# ── 2. L'action risquée : envoi vers une adresse PERSONNELLE ──────────
say("● Now the agent tries to email the export to a personal Gmail", "33")
print('  → send_email(to="j.martin@gmail.com", subject="Q3 enterprise customers")')
time.sleep(PAUSE)

say("⏸ CERBÈRE PAUSED THE ACTION — a human must decide.", "35")
print("  Open the dashboard → Approvals → click Approve (or Reject).")
print("  The agent is polling for the decision...")

try:
    res = guard.guard_tool_call(
        "send_email",
        params={
            "to": "j.martin@gmail.com",  # adresse perso = signal de risque
            "subject": "Q3 enterprise customers",
            "body": csv,
        },
        func=send_email,
    )
    say(f"  ✓ approved by a human → executed: {res}", "32")
except ApprovalRejectedException:
    say("  ✗ rejected by a human — the email was NEVER sent", "31")
except ApprovalRequiredException as e:
    say(
        f"  ⏱ nobody decided in time (timed_out={e.timed_out}) — action cancelled", "33"
    )
except SecurityException as e:
    say(f"  ⛔ blocked by Cerbere — {e}", "31")

say(
    "Human-in-the-loop — the agent waited, the human decided, audit trail complete.",
    "32",
)
