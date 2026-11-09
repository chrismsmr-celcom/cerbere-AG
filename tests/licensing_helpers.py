"""Aides de test : fabriquer des licences signées avec une paire de clés jetable."""

import time

from collector import licensing

DAY = 86400


class Issuer:
    def __init__(self, monkeypatch):
        self.private, public = licensing.generate_keypair()
        self.public = public
        monkeypatch.setitem(licensing.PUBLIC_KEYS, "k1", public)

    def token(
        self, plan="team", days=365, issued_days_ago=0, customer="ACME Corp", **extra
    ):
        now = int(time.time())
        issued = now - int(issued_days_ago * DAY)
        payload = {
            "id": "lic_test",
            "customer": customer,
            "plan": plan,
            "issued_at": issued,
            "expires_at": issued + int(days * DAY),
        }
        payload.update(extra)
        return licensing.sign_license(self.private, "k1", payload)


def install(monkeypatch, plan="team", **kw):
    """Active une licence pour le test (variable d'environnement)."""
    issuer = Issuer(monkeypatch)
    monkeypatch.setenv("AGENTGUARD_LICENSE_KEY", issuer.token(plan, **kw))
    return issuer
