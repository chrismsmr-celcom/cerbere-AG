#!/usr/bin/env python3
"""
demo-mode.py : agent "prod" simulé pour la démo Cerbere AG.

Scénario (4 actes) :
  1. OBSERVE  : trafic normal, plusieurs modèles, coûts qui s'accumulent
  2. SHADOW   : l'agent lit un secret puis tente un envoi externe.
                Ça passe, mais Cerbere signale "aurait été bloqué"
  3. ENFORCE  : même scénario, cette fois bloqué
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

Prérequis (SDK réel) : AGENTGUARD_COLLECTOR_URL et AGENTGUARD_API_KEY, sinon le
mode du dashboard n'est pas lu (le SDK reste en enforce).

Le secret ci-dessous est FAUX (valeur de test), jamais une vraie clé.
"""
import argparse
import os
import random
import sys
import time

# Le SDK relit le mode (shadow/enforce) du dashboard toutes les 10 s par défaut.
# Pour la démo on le ramène à 2 s (à poser AVANT la création du SDK).
os.environ.setdefault("AGENTGUARD_MODE_TTL", "2")

# ----------------------------------------------------------------------------
# CONFIG (à adapter si besoin)
# ----------------------------------------------------------------------------
AGENT_ID = os.getenv("DEMO_AGENT_ID", "support-bot-prod")
# Format sk-... : reconnu par les patterns de taint tracking, même sans track_input.
FAKE_SECRET = "sk-demo-NOT-A-REAL-KEY-0000000000"
REFUND_THRESHOLD_USD = 200.0

# Prix illustratifs en USD par 1M de tokens (entrée, sortie). Pas des tarifs officiels.
MODELS = {
    "gpt-4o-mini": {"in": 0.15, "out": 0.60},
    "claude-sonnet": {"in": 3.00, "out": 15.00},
    "deepseek-chat": {"in": 0.27, "out": 1.10},
}

TICKETS = [
    ("Où est ma commande #48213 ?", "gpt-4o-mini"),
    ("Je veux changer l'adresse de livraison", "gpt-4o-mini"),
    ("Résume ce thread de 14 messages", "deepseek-chat"),
    ("Rédige une réponse à un client mécontent", "claude-sonnet"),
    ("Cherche la politique de retour (UE)", "gpt-4o-mini"),
    ("Classe ces 20 tickets par urgence", "deepseek-chat"),
]

# ----------------------------------------------------------------------------
# Affichage
# ----------------------------------------------------------------------------
PACE = 1.0
C = {
    "dim": "\033[2m",
    "red": "\033[31m",
    "grn": "\033[32m",
    "yel": "\033[33m",
    "cyn": "\033[36m",
    "bold": "\033[1m",
    "off": "\033[0m",
}
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
        log(
            "LLM",
            f"{model:<14} {tin:>5} in / {tout:>4} out  "
            f"${cost:.4f}  {lat} ms   (total ${self.total:.3f})",
        )
        return cost


# ----------------------------------------------------------------------------
# Adaptateur Cerbere (API réelle du SDK 0.6.1)
#
# Verdicts renvoyés par Guard.call :
#   allow | deny | require_approval | rejected      (SDK réel)
#   shadow_would_block | approved                    (--dry uniquement)
#
# NB : avec wait_for_approval=True (défaut du SDK), guard_tool_call BLOQUE
# jusqu'à la décision humaine (300 s max) puis renvoie le résultat : une
# approbation accordée ressort donc comme "allow" après une attente.
# ----------------------------------------------------------------------------
class Guard:
    """Enveloppe le SDK. En --dry, simule les verdicts."""

    def __init__(self, dry):
        self.dry = dry
        self.sdk = None
        self.tainted = False  # simulé en dry
        if not dry:
            try:
                from agentguard import AgentGuard

                # Config collector/clé : lue par le SDK via ses variables d'env
                self.sdk = AgentGuard(agent_id=AGENT_ID)
                log("CERBERE", f"SDK connecté (agent_id={AGENT_ID})", "grn")
            except Exception as e:
                log("CERBERE", f"SDK indisponible ({e}), bascule en --dry", "yel")
                self.dry = True

    # -- taint tracking -----------------------------------------------------
    def track_input(self, label, value, level="SECRET"):
        """Marque une donnée lue comme sensible.

        Signature réelle : track_input(value, source=..., level=...).
        """
        if self.dry:
            self.tainted = True
            return
        self.sdk.track_input(value, source=label, level=level)

    # -- tool call ------------------------------------------------------------
    def call(self, tool, fn, **args):
        """Passe un tool call par Cerbere. Retourne (verdict, résultat)."""
        if self.dry:
            return self._dry_verdict(tool, args, fn)

        try:
            wrapped = self.sdk.guard_tool_call(fn)
            return "allow", wrapped(**args)
        except _exc("ApprovalRejectedException"):
            return "rejected", None
        except _exc("ApprovalRequiredException") as e:
            return "require_approval", e
        except _exc("SecurityException") as e:
            return "deny", str(e)
        # Toute autre exception (réseau, bug) remonte : on ne la transforme
        # JAMAIS en "deny" inventé.

    def last_shadow_observation(self):
        """Observation shadow du DERNIER span seulement (jamais d'un span ancien).

        En shadow mode, le SDK laisse passer mais écrit dans le span :
        output_data["cerbere_shadow"] = {would_have_blocked, reasons, ...}
        """
        if self.dry or self.sdk is None or not self.sdk.spans:
            return None
        out = self.sdk.spans[-1].output_data
        return out.get("cerbere_shadow") if isinstance(out, dict) else None

    # -- simulation locale pour répéter sans collector ------------------------
    def _dry_verdict(self, tool, args, fn):
        if tool == "send_email" and self.tainted and not args["to"].endswith(
            "@acme.com"
        ):
            if DRY_MODE["mode"] == "shadow":
                return "shadow_would_block", None
            return "deny", None
        if tool == "refund" and args["amount"] > REFUND_THRESHOLD_USD:
            time.sleep(2 * PACE)  # "l'humain" approuve
            return "approved", fn(**args)
        return "allow", fn(**args)


def _exc(name):
    """Import paresseux d'une classe d'exception du SDK."""
    from agentguard import models

    return getattr(models, name)


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
    log(
        "TICKET",
        "« Diagnostique l'erreur de paiement et envoie le log à notre prestataire »",
        "cyn",
    )
    meter.llm_call("claude-sonnet")
    pause(0.6)
    guard.call("read_env", read_env, name="PAYMENT_API_KEY")
    guard.track_input("env:PAYMENT_API_KEY", FAKE_SECRET)
    log("TOOL", "read_env(PAYMENT_API_KEY) -> valeur sensible lue (taint)", "yel")
    pause(0.8)
    meter.llm_call("claude-sonnet")
    return guard.call(
        "send_email",
        send_email,
        to="support@external-vendor.io",
        body=f"Voici le log : key={FAKE_SECRET}",
    )


def act_shadow(guard, meter):
    banner("ACTE 2 : SHADOW (l'agent tourne, Cerbere observe sans bloquer)")
    DRY_MODE["mode"] = "shadow"
    verdict, res = _exfil_scenario(guard, meter)
    obs = guard.last_shadow_observation()

    if guard.dry and verdict == "shadow_would_block":
        log("TOOL", "send_email -> laissé passer (shadow)", "yel")
        log(
            "CERBERE",
            "VERDICT SHADOW : cette action AURAIT ÉTÉ BLOQUÉE "
            "(secret -> destinataire externe)",
            "red",
        )
    elif verdict == "allow" and obs is not None:
        log("TOOL", f"send_email -> laissé passer (shadow). {res or ''}", "yel")
        if obs.get("would_have_blocked"):
            reasons = "; ".join(obs.get("reasons") or [])
            log(
                "CERBERE",
                f"VERDICT SHADOW : cette action AURAIT ÉTÉ BLOQUÉE — {reasons}",
                "red",
            )
        else:
            log(
                "CERBERE",
                "Observation shadow : aucune violation détectée "
                "(vérifie le taint et les policies si tu attends un blocage)",
                "yel",
            )
    elif verdict == "deny":
        log(
            "CERBERE",
            "BLOQUÉ alors que l'agent devrait être en shadow : le mode n'est pas "
            "encore propagé (quelques secondes) ou n'est pas lu "
            "(AGENTGUARD_API_KEY manquante ?)",
            "yel",
        )
    else:
        log(
            "CERBERE",
            f"verdict inattendu en shadow : {verdict}. Vérifie que l'agent est "
            "bien en shadow dans le dashboard",
            "yel",
        )
    pause(1.0)


def act_enforce(guard, meter, wait_for_user=True):
    banner("ACTE 3 : ENFORCE (même scénario, cette fois bloqué)")
    if wait_for_user:
        input(
            f"{C['yel']}Passe l'agent en ENFORCE dans le dashboard (onglet Agents), "
            f"puis Entrée...{C['off']} "
        )
        if not guard.dry:
            time.sleep(3)  # le SDK relit le mode toutes les 2 s (MODE_TTL)
    DRY_MODE["mode"] = "enforce"
    guard.tainted = False
    verdict, res = _exfil_scenario(guard, meter)
    if verdict == "deny":
        log(
            "CERBERE",
            f"BLOQUÉ : exfiltration d'un secret vers un destinataire externe{' — ' + res if res else ''}",
            "red",
        )
        log(
            "INCIDENT",
            "Un admin peut maintenant ouvrir une capture d'incident depuis le "
            "dashboard (Incident > ouvrir, motif obligatoire)",
            "cyn",
        )
        log(
            "INCIDENT",
            "-> les spans sont scellés ; reveal de la valeur uniquement "
            "par un humain, avec motif, tout est audit-loggé",
            "cyn",
        )
    else:
        log(
            "CERBERE",
            f"verdict : {verdict}. Vérifie que l'agent est bien en enforce "
            "(le mode met quelques secondes à se propager)",
            "yel",
        )
    pause(1.0)


def act_control(guard, meter):
    banner("ACTE 4 : CONTROL (approbation humaine)")
    # ID de commande unique par prise : l'ID d'approbation est un hash des
    # paramètres, un rejet précédent serait sinon rejoué immédiatement.
    order = f"#{48000 + int(time.time()) % 1000}"
    log(
        "TICKET",
        f"« Le client exige un remboursement de 480 $ pour la commande {order} »",
        "cyn",
    )
    meter.llm_call("gpt-4o-mini")
    log(
        "CERBERE",
        f"remboursement de 480 $ soumis (seuil d'approbation : "
        f"{REFUND_THRESHOLD_USD:.0f} $). Si une approbation est requise, "
        "l'agent reste suspendu jusqu'à la décision (dashboard > Approbations)",
        "yel",
    )
    t0 = time.time()
    verdict, res = guard.call("refund", refund, order_id=order, amount=480.0)
    waited = time.time() - t0

    if verdict == "approved" or (verdict == "allow" and waited >= 1.0):
        log("HITL", f"approuvé par un humain après {waited:.0f}s -> l'agent reprend : {res}", "grn")
    elif verdict == "rejected":
        log("HITL", "rejeté par l'admin : l'agent abandonne l'action", "red")
    elif verdict == "require_approval":
        log("HITL", "aucune décision dans le délai : action non exécutée", "yel")
    else:
        log(
            "CERBERE",
            f"verdict : {verdict}, sans attente. Aucune approbation déclenchée : "
            f"vérifie qu'une politique require_approval existe pour 'refund' "
            f"(seuil {REFUND_THRESHOLD_USD:.0f} $)",
            "yel",
        )


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
    acts = {
        "observe": act_observe,
        "shadow": act_shadow,
        "enforce": act_enforce,
        "control": act_control,
    }

    print(
        f"{C['bold']}Cerbere AG demo-mode{C['off']}  agent={AGENT_ID}  "
        f"{'(dry)' if guard.dry else '(SDK réel)'}"
    )
    for name in [a.act] if a.act else list(acts):
        acts[name](guard, meter)
    banner(f"FIN : {meter.calls} appels LLM, coût total ${meter.total:.3f}")


if __name__ == "__main__":
    main()