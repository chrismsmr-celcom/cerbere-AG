"""demo_llm_cost.py — Démo Cerbère AG : traçabilité et plafond des coûts LLM.

Scénario (~60 s) :
  1. support-bot fait quelques appels LLM normaux (coûts trackés, modèles variés)
  2. un prompt gonfle (contexte énorme) → le coût par appel explose à l'écran
  3. le budget Cerbère est atteint → le prochain appel est BLOQUÉ, pas facturé
  4. bilan : total dépensé vs budget, tel qu'affiché dans le dashboard

Usage (PowerShell) :
  $env:CERBERE_API_KEY="ag_live_..."      # clé NEUVE du dashboard
  $env:CERBERE_URL="https://app.cerbereag.site"
  python demo_llm_cost.py

Variante "seed" pour remplir les graphs de coût avant la vidéo :
  python demo_llm_cost.py --seed 80
"""

import argparse
import os
import random
import time

import requests

from agentguard import AgentGuard, SecurityException

COLLECTOR = os.environ.get("CERBERE_URL", "https://app.cerbereag.site")
API_KEY = os.environ["CERBERE_API_KEY"]
PAUSE = float(os.environ.get("DEMO_PAUSE", "2.5"))

random.seed(7)


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


# ── Faux client LLM — même signature que client.chat.completions.create ─
def fake_llm_create(model="gpt-4o", messages=None, **kwargs):
    """Simule une réponse. Le SDK extrait prompt/messages en entrée et
    content en sortie pour compter les tokens et estimer le coût."""
    question = messages[-1]["content"] if messages else ""
    return {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": f"Answer to '{question[:60]}...': see policy doc, "
                    "refund within 30 days, shipping in 3-5 business days." * 3,
                }
            }
        ],
        "model": model,
    }


PROMPTS = [
    "What is the refund policy?",
    "Customer asks about shipping delays for order ORD-48210.",
    "Summarize our warranty terms for electronics.",
    "How do loyalty points work with gift cards?",
    "Draft a reply for an angry customer about a late invoice.",
]

MODELS = ["gpt-4o", "gpt-4o-mini", "gpt-3.5-turbo", "deepseek-chat"]


def run_demo() -> None:
    guard = AgentGuard(
        collector_url=COLLECTOR,
        api_key=API_KEY,
        agent_id="support-bot",
        max_budget=0.05,  # 5 cents — volontairement bas pour la démo du cutoff
    )
    llm = guard.guard_llm_call(fake_llm_create)

    # ── 1. Appels normaux — coûts trackés modèle par modèle ────────────
    say("● OBSERVE — normal LLM calls, every cent tracked by Cerbère", "36")
    for _ in range(4):
        model = random.choice(MODELS)
        llm(model=model, messages=[{"role": "user", "content": random.choice(PROMPTS)}])
        print(f"  ✓ {model} → ok   (spent so far: ${guard.total_spent:.4f})")
        time.sleep(0.5)

    # ── 2. Le prompt gonfle → coût par appel qui explose ────────────────
    say("● A runaway agent stuffs 20k words of context into every call", "33")
    huge_context = "Customer history: " + "order placed, refunded, reopened. " * 1200
    for _ in range(3):
        llm(
            model="gpt-4o",
            messages=[{"role": "user", "content": huge_context + " Summarize."}],
        )
        print(f"  ⚠ gpt-4o with huge context → ok  (spent: ${guard.total_spent:.4f})")
        time.sleep(0.5)

    # ── 3. Budget atteint → le prochain appel est bloqué AVANT facturation ─
    say(f"● Budget cap reached (${guard.max_budget:.2f}) — next call is blocked", "31")
    try:
        llm(model="gpt-4o", messages=[{"role": "user", "content": huge_context}])
        print("  (still under budget)")
    except SecurityException as e:
        say(f"  ⛔ BLOCKED by Cerbère — {e}", "31")

    print(f"\n  Total spent: ${guard.total_spent:.4f} / budget ${guard.max_budget:.2f}")
    say("Cost governance — see every token, cap the spend, stop the bleed.", "32")


def run_seed(n: int) -> None:
    """Remplit le dashboard de données de coût variées (avant la vidéo)."""
    guard = AgentGuard(
        collector_url=COLLECTOR,
        api_key=API_KEY,
        agent_id="support-bot",
        max_budget=500.0,  # haut : on veut du volume, pas un cutoff
    )
    llm = guard.guard_llm_call(fake_llm_create)

    ok = failed = 0
    t0 = time.time()
    for i in range(n):
        try:
            model = random.choice(MODELS)
            if random.random() < 0.15:
                # 15 % d'appels "fuites de contexte" — chers
                content = "Context: " + "data row. " * 4000 + " Summarize."
            else:
                content = random.choice(PROMPTS)
            llm(model=model, messages=[{"role": "user", "content": content}])
            ok += 1
        except requests.RequestException:
            failed += 1
        except SecurityException:
            pass  # rare avec un gros budget ; on ignore
        if (i + 1) % 10 == 0:
            rate = (i + 1) / (time.time() - t0)
            print(
                f"  {i + 1}/{n} llm calls (ok={ok}, failed={failed}, "
                f"${guard.total_spent:.2f} simulated, {rate:.1f}/s)"
            )

    print(
        f"\n✓ Seed LLM terminé : {ok} appels, "
        f"${guard.total_spent:.2f} de coût simulé tracké dans le dashboard."
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="mode seed : nombre d'appels LLM (ex: 80)",
    )
    args = parser.parse_args()

    preflight()
    if args.seed:
        run_seed(args.seed)
    else:
        run_demo()
