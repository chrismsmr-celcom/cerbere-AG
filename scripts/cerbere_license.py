#!/usr/bin/env python3
"""Outil d'émission des licences Cerbere AG — RÉSERVÉ À L'ÉDITEUR.

La clé privée ne doit JAMAIS être déposée dans le dépôt, l'image Docker ou un serveur.
Gardez-la hors ligne (gestionnaire de mots de passe chiffré, clé USB chiffrée, HSM) et sauvegardée.

    # 1. Une seule fois : générer la paire de clés
    python scripts/cerbere_license.py keygen --out cerbere-license-private.key
    -> affiche la ligne à coller dans PUBLIC_KEYS de collector/licensing.py

    # 2. Émettre une licence pour un client
    python scripts/cerbere_license.py issue --key cerbere-license-private.key \\
        --customer "ACME Corp" --plan team --days 365

    # Essai gratuit de 30 jours d'une offre payante
    python scripts/cerbere_license.py issue --key cerbere-license-private.key \\
        --customer "Prospect SA" --plan team --days 30

    # 3. Vérifier / lire une licence (sans la clé privée)
    python scripts/cerbere_license.py inspect "cerbere_lic_v1...."
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from collector import licensing


def cmd_keygen(args) -> int:
    out = Path(args.out)
    if out.exists():
        print(f"Refusing to overwrite {out}", file=sys.stderr)
        return 1
    private, public = licensing.generate_keypair()
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(private + "\n")
    print(f"Private key written to {out} (mode 600). KEEP IT OFFLINE AND BACK IT UP.")
    print(
        "If it is lost you cannot issue or renew licenses; if it leaks anyone can forge them.\n"
    )
    print(
        "Add this line to PUBLIC_KEYS in collector/licensing.py, then rebuild and publish:\n"
    )
    print(f'    "{args.kid}": "{public}",')
    return 0


def cmd_issue(args) -> int:
    private = Path(args.key).read_text().strip()
    now = int(time.time())
    payload = {
        "id": "lic_" + uuid.uuid4().hex[:12],
        "customer": args.customer,
        "plan": args.plan,
        "issued_at": now,
        "expires_at": now + int(args.days * 86400),
    }
    if args.feature:
        payload["features"] = args.feature
    if args.limit:
        payload["limits"] = {
            k: int(v) for k, v in (item.split("=", 1) for item in args.limit)
        }
    token = licensing.sign_license(private, args.kid, payload)

    # Contrôle de bout en bout avec la clé publique embarquée.
    try:
        licensing.verify_license(token)
    except licensing.LicenseError as exc:
        print(
            f"WARNING: this build would reject the license just issued: {exc}",
            file=sys.stderr,
        )
        print(
            "Did you paste the matching public key into collector/licensing.py?",
            file=sys.stderr,
        )
    print(token)
    print(
        f"\n# {payload['id']}  {args.plan}  {args.customer}  "
        f"expires in {args.days} day(s)  — keep this line in your customer records",
        file=sys.stderr,
    )
    return 0


def cmd_inspect(args) -> int:
    try:
        lic = licensing.verify_license(args.token)
    except licensing.LicenseError as exc:
        print(f"INVALID: {exc}")
        return 1
    print(json.dumps(lic.__dict__, indent=2, default=list))
    state = licensing.evaluate(args.token)
    print(f"status: {state.status} — {state.message}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("keygen", help="Generate the signing key pair (once)")
    p.add_argument("--out", required=True)
    p.add_argument("--kid", default="k1", help="Key id (for rotation), default k1")
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("issue", help="Issue a signed license")
    p.add_argument("--key", required=True, help="Path to the private key file")
    p.add_argument("--kid", default="k1")
    p.add_argument("--customer", required=True)
    p.add_argument(
        "--plan",
        required=True,
        choices=[licensing.PRO, licensing.TEAM, licensing.ENTERPRISE],
    )
    p.add_argument(
        "--days",
        type=float,
        required=True,
        help="Validity in days (365 = one year, 30 = trial)",
    )
    p.add_argument(
        "--feature", action="append", help="Extra feature to grant (repeatable)"
    )
    p.add_argument(
        "--limit",
        action="append",
        help="Contractual limit as name=value, e.g. agents=50 (informational)",
    )
    p.set_defaults(func=cmd_issue)

    p = sub.add_parser("inspect", help="Verify and print a license")
    p.add_argument("token")
    p.set_defaults(func=cmd_inspect)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
