#!/usr/bin/env python3
"""
demo-mode.py : agent "prod" simulé pour la démo Cerbere AG.

Scénario (4 actes) :
  1. OBSERVE  : trafic normal, plusieurs modèles, coûts qui s'accumulent
  2. SHADOW   : l'agent lit un secret puis tente un envoi externe.
                Ça passe, mais Cerbere signale "aurait été bloqué"
  3. ENFORCE  : même scénario, cette fois bloqué (incident ouvert)
  4. CONTROL  : remboursement > seuil => approbation humaine (HITL)

Usage :
  python demo-mode.py                 # enchaîne les 4 actes
  python demo-mode.py --act shadow    # un seul acte (observe|shadow|enforce|control)
  python demo-mode.py --pace 2.0      # ralentit (utile pour filmer)
  python demo-mode.py --fast          # presque sans pauses (tests)
  python demo-mode.py --dry           # sans SDK : simule les verdicts en local

Le mode shadow/enforce se règle côté dashboard (onglet Agents) : le script
n'a pas à le changer, il rejoue juste le même scénario. Entre l'acte 2 et 3,
le script te laisse le temps de basculer l'agent en enforce.

Le secret ci-dessous est FAUX (valeur de test), jamais une vraie clé.
"""
import argparse
import os
import random
import sys
import time

# ----------------------------------------------------------------------------
# CONFIG (à adapter si besoin)
# ----------------------------------------------------------------------------
AGENT_ID = os.getenv("DEMO_AGENT_ID", "support-bot-prod")
FAKE_SECRET = "sk_live_DEMO_NOT_A_REAL_KEY_0000000000"
REFUND_THRESHOLD_USD = 200.0

# Prix illustratifs en USD par 1M de tokens (entrée, sortie). Pas des tarifs officiels.
MODELS = {
    "gpt-4o-mini":     {"in": 0.15, "out": 0.60},
    "claude-sonnet":   {"in": 3.00, "out": 15.00},
    "deepseek-chat":   {"in": 0.27, "out": 1.10},
}

TICKETS = [
    ("Où est ma commande #48213 ?",                 "gpt-4o-mini"),
    ("Je veux changer l'adresse de livraison",      "gpt-4o-mini"),
    ("Résume ce thread de 14 messages",             "deepseek-chat"),
    ("Rédige une réponse à un client mécontent",    "claude-sonnet"),
    ("Cherche la politique de retour (UE)",         "gpt-4o-mini"),
    ("Classe ces 20 tickets par urgence",           "deepseek-chat"),
]

# ----------------------------------------------------------------------------
# Affichage
# ----------------------------------------------------------------------------
PACE = 1.0
C = {"dim": "\033[2m", "red": "\033[31m", "grn": "\033[32m",
     "yel": "\033[33m", "cyn": "\033[36m", "bold": "\033[1m", "off": "\033[0m"}
if not sys.stdout.isatty():
    C = {k: "" for k in C}


def pause(s):
    time.sleep(max(0.0, s * PACE))


def log(tag, msg, color="dim"):
    ts = time.strftime("%H:%M:%S")
    print(f"{C['dim']}{ts}{C['off']} {C[color]}{tag:<9}{C['off']} {msg}")


def banner(title):
    print(f"\n{C['bold']}{C['cyn']}== {title} =={C['off']}")


# ----------------------------------------------------------------------------
# Coûts
# ----------------------------------------------------------------------------
class CostMeter:
    def __init__(self):
        self.total = 0.0
        self.calls = 0

    def llm_call(self, model):
        tin = random.randint(400, 3200)
        tout = random.randint(80, 900)
        p = MODELS[model]
        cost = tin / 1e6 * p["in"] + tout / 1e6 * p["out"]
        self.total += cost
        self.calls += 1
        lat = random.randint(350, 1900)
        log("LLM", f"{model:<14} {tin:>5} in / {tout:>4} out  "
                   f"${cost:.4f}  {lat} ms   (total ${self.total:.3f})")
        return cost


# ----------------------------------------------------------------------------
# Adaptateur Cerbere : UNIQUE endroit à retoucher si l'API du SDK diffère
# ----------------------------------------------------------------------------
class Guard:
    """Enveloppe le SDK. En --dry, simule les verdicts."""

    def __init__(self, dry):
        self.dry = dry
        self.sdk = None
        self.tainted = False   # simulé en dry
        if not dry:
            try:
                from agentguard import AgentGuard
                # Config collector/clé : lue par le SDK via ses variables d'env
                self.sdk = AgentGuard(agent_id=AGENT_ID)
                log("CERBERE", f"SDK connecté (agent_id={AGENT_ID})", "grn")
            except Exception as e:  # noqa: BLE001
                log("CERBERE", f"SDK indisponible ({e}), bascule en --dry", "yel")
                self.dry = True

    def track_input(self, label, value, sensitivity="secret"):
        """Marque une donnée lue comme sensible (taint tracking)."""
        if self.dry:
            self.tainted = True
            return
        # Adapter ici si la signature de track_input diffère
        self.sdk.track_input(value, source=label, sensitivity=sensitivity)

    def call(self, tool, fn, **args):
        """Passe un tool call par Cerbere. Retourne (verdict, résultat)."""
        if self.dry:
            return self._dry_verdict(tool, args, fn)
        try:
            # Adapter ici si guard_tool_call a une autre signature
            wrapped = self.sdk.guard_tool_call(fn)
            return "allow", wrapped(**args)
        except Exception as e:  # noqa: BLE001
            name = type(e).__name__.lower()
            if "approval" in name or "review" in name:
                return "require_approval", None
            if "block" in name or "deny" in name or "denied" in name:
                return "deny", None
            raise

    # -- simulation locale pour tester le script sans collector --
    def _dry_verdict(self, tool, args, fn):
        if tool == "send_email" and self.tainted and not args["to"].endswith("@acme.com"):
            return ("shadow_would_block" if DRY_MODE["mode"] == "shadow" else "deny"), None
        if tool == "refund" and args["amount"] > REFUND_THRESHOLD_USD:
            return "require_approval", None
        return "allow", fn(**args)


DRY_MODE = {"mode": "shadow"}


# ----------------------------------------------------------------------------
# Outils de l'agent (factices, inoffensifs)
# ----------------------------------------------------------------------------
def search_kb(query):
    return f"3 articles trouvés pour « {query} »"


def read_env(name):
    return FAKE_SECRET


def send_email(to, body):
    return f"email envoyé à {to}"


def refund(order_id, amount):
    return f"remboursement {amount:.2f}$ émis ({order_id})"


# ----------------------------------------------------------------------------
# Actes
# ----------------------------------------------------------------------------
def act_observe(guard, meter):
    banner("ACTE 1 : OBSERVE (trafic normal en prod)")
    for text, model in TICKETS:
        log("TICKET", text, "cyn")
        meter.llm_call(model)
        verdict, res = guard.call("search_kb", search_kb, query=text[:40])
        log("TOOL", f"search_kb -> {verdict}  {res or ''}", "grn")
        pause(random.uniform(0.6, 1.2))
    log("BILAN", f"{meter.calls} appels LLM, coût cumulé ${meter.total:.3f}", "bold")


def _exfil_scenario(guard, meter):
    log("TICKET", "« Diagnostique l'erreur de paiement et envoie le log à notre prestataire »", "cyn")
    meter.llm_call("claude-sonnet")
    pause(0.6)
    guard.call("read_env", read_env, name="PAYMENT_API_KEY")
    guard.track_input("env:PAYMENT_API_KEY", FAKE_SECRET)
    log("TOOL", "read_env(PAYMENT_API_KEY) -> valeur sensible lue (taint)", "yel")
    pause(0.8)
    meter.llm_call("claude-sonnet")
    verdict, res = guard.call("send_email", send_email,
                              to="support@external-vendor.io",
                              body=f"Voici le log : key={FAKE_SECRET}")
    return verdict, res


def act_shadow(guard, meter):
    banner("ACTE 2 : SHADOW (l'agent tourne, Cerbere observe sans bloquer)")
    DRY_MODE["mode"] = "shadow"
    verdict, res = _exfil_scenario(guard, meter)
    if verdict in ("allow", "shadow_would_block"):
        log("TOOL", f"send_email -> laissé passer (shadow). {res or ''}", "yel")
        log("CERBERE", "VERDICT SHADOW : cette action AURAIT ÉTÉ BLOQUÉE "
                       "(secret -> destinataire externe)", "red")
    else:
        log("CERBERE", f"verdict inattendu en shadow : {verdict} (vérifie le mode de l'agent)", "yel")
    pause(1.0)


def act_enforce(guard, meter, wait_for_user=True):
    banner("ACTE 3 : ENFORCE (même scénario, cette fois bloqué)")
    if wait_for_user:
        input(f"{C['yel']}Passe l'agent en ENFORCE dans le dashboard (onglet Agents), "
              f"puis Entrée...{C['off']} ")
    DRY_MODE["mode"] = "enforce"
    guard.tainted = False
    verdict, res = _exfil_scenario(guard, meter)
    if verdict == "deny":
        log("CERBERE", "BLOQUÉ : exfiltration d'un secret vers un destinataire externe", "red")
        log("INCIDENT", "capture d'incident ouverte (spans masqués par défaut)", "red")
        log("INCIDENT", "-> dashboard : Incident > Secure Evidence Recovery "
                        "pour révéler la valeur scellée (audit loggé)", "cyn")
    else:
        log("CERBERE", f"verdict : {verdict}. Vérifie que l'agent est bien en enforce", "yel")
    pause(1.0)


def act_control(guard, meter):
    banner("ACTE 4 : CONTROL (approbation humaine)")
    log("TICKET", "« Le client exige un remboursement de 480 $ pour la commande #48213 »", "cyn")
    meter.llm_call("gpt-4o-mini")
    verdict, res = guard.call("refund", refund, order_id="#48213", amount=480.0)
    if verdict == "require_approval":
        log("CERBERE", f"remboursement > {REFUND_THRESHOLD_USD:.0f}$ : EN ATTENTE D'APPROBATION", "yel")
        log("HITL", "-> approuve ou rejette depuis le dashboard (file d'approbations)", "cyn")
        input(f"{C['yel']}Une fois la décision prise dans le dashboard, Entrée...{C['off']} ")
        log("AGENT", "reprend après décision humaine", "grn")
    else:
        log("CERBERE", f"verdict : {verdict}. Pas d'approbation déclenchée "
                       f"(vérifie la règle de politique sur refund)", "yel")


def main():
    global PACE
    ap = argparse.ArgumentParser()
    ap.add_argument("--act", choices=["observe", "shadow", "enforce", "control"])
    ap.add_argument("--pace", type=float, default=1.0)
    ap.add_argument("--fast", action="store_true")
    ap.add_argument("--dry", action="store_true")
    a = ap.parse_args()
    PACE = 0.05 if a.fast else a.pace
    random.seed(7)  # démo reproductible

    guard = Guard(a.dry)
    meter = CostMeter()
    acts = {"observe": act_observe, "shadow": act_shadow,
            "enforce": act_enforce, "control": act_control}

    print(f"{C['bold']}Cerbere AG demo-mode{C['off']}  agent={AGENT_ID}  "
          f"{'(dry)' if guard.dry else '(SDK réel)'}")
    todo = [a.act] if a.act else list(acts)
    for name in todo:
        acts[name](guard, meter)
    banner(f"FIN : {meter.calls} appels LLM, coût total ${meter.total:.3f}")


if __name__ == "__main__":
    main()
