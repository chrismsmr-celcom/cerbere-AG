"""CLI d'administration pour une instance self-hosted.

Usage :
    python -m collector.cli create-admin --email admin@corp.com [--org "ACME"] [--name "Alice"]
    python -m collector.cli set-password --email admin@corp.com
    python -m collector.cli list-users
    python -m collector.cli migrate [--status]
    python -m collector.cli license status | install <file|->
    python -m collector.cli report [--period YYYY-MM] [--org ID] [--format pdf|json] [--out FILE]

Le mot de passe est demandé de façon interactive (jamais en argument, pour
ne pas finir dans l'historique du shell). Pour l'automatisation, utiliser
`--password-stdin` ou la variable d'environnement AGENTGUARD_ADMIN_PASSWORD.

Avec Docker :
    docker compose run --rm collector python -m collector.cli create-admin --email ...
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys


def _init_database() -> None:
    from collector.migrations import run_migrations

    run_migrations(init=True)


def _read_password(args, confirm: bool = True) -> str:
    if getattr(args, "password_stdin", False):
        return sys.stdin.readline().rstrip("\r\n")

    env_pw = os.environ.get("AGENTGUARD_ADMIN_PASSWORD")
    if env_pw:
        return env_pw

    password = getpass.getpass("Password (min 12 characters): ")
    if confirm and getpass.getpass("Confirm password: ") != password:
        raise SystemExit("Passwords do not match.")
    return password


def cmd_create_admin(args) -> int:
    from collector.auth.local_password import PasswordError, provision_workspace

    _init_database()
    password = _read_password(args)
    try:
        _user_id, org_id, _tenant = provision_workspace(
            email=args.email,
            password=password,
            display_name=args.name,
            org_name=args.org,
            role=args.role,
        )
    except PasswordError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(f"Created {args.role} {args.email.strip().lower()} (org_id={org_id}).")
    print("You can now sign in on /login.")
    return 0


def cmd_set_password(args) -> int:
    from collector.auth.local_password import PasswordError, set_user_password
    from collector.auth.users import _user_by_email

    _init_database()
    user = _user_by_email(args.email)
    if not user:
        print("Error: no such user.", file=sys.stderr)
        return 1
    password = _read_password(args)
    try:
        set_user_password(user[0], password)
    except PasswordError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print("Password updated.")
    return 0


def cmd_migrate(args) -> int:
    from collector import migrations

    if args.status:
        info = migrations.status()
        for version, name in info["applied"]:
            print(f"applied  {version:04d}  {name}")
        for version, name in info["pending"]:
            print(f"pending  {version:04d}  {name}")
        for version in info["unknown"]:
            print(f"UNKNOWN  {version:04d}  (applied by a newer version of Cerbere)")
        return 1 if info["unknown"] else 0

    try:
        applied = migrations.run_migrations(init=True)
    except migrations.MigrationError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    if applied:
        print("Applied migrations: " + ", ".join(f"{v:04d}" for v in applied))
    else:
        print("Database schema is up to date.")
    return 0


def cmd_license_status(_args) -> int:
    from collector import licensing

    info = licensing.status_dict()
    print(f"Plan:     {info['plan']}  ({info['status']})")
    print(f"Message:  {info['message']}")
    if info["customer"]:
        print(f"Customer: {info['customer']}  (license {info['license_id']})")
        print(f"Expires:  {info['expires_on']}  ({info['days_left']} day(s) left)")
    print("Paid features: " + (", ".join(info["features"]) or "none (Community)"))
    return 0


def cmd_license_install(args) -> int:
    import os
    import tempfile
    from pathlib import Path

    from collector import licensing

    token = (
        sys.stdin.read().strip()
        if args.file == "-"
        else Path(args.file).read_text(encoding="utf-8").strip()
    )
    try:
        lic = licensing.verify_license(token)
    except licensing.LicenseError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    target = os.environ.get("AGENTGUARD_LICENSE_FILE", "").strip()
    if not target:
        print(
            "Error: set AGENTGUARD_LICENSE_FILE (the Docker Compose setup uses /data/license.key), "
            "or put the key in AGENTGUARD_LICENSE_KEY instead.",
            file=sys.stderr,
        )
        return 1
    dest = Path(target)
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(dest.parent))
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(token + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, dest)  # écriture atomique
    print(
        f"Installed {lic.plan} license for {lic.customer} -> {dest}. No restart needed."
    )
    return 0


def cmd_report(args) -> int:
    import json

    from collector import compliance_report as report
    from collector import licensing
    from collector.audit_routes import get_audit_log
    from collector.auth.users import _db_execute

    if not licensing.has_feature("compliance_reports"):
        print(
            "Error: compliance reports are part of the Team and Enterprise plans. "
            "Install a license with `license install`.",
            file=sys.stderr,
        )
        return 1
    _init_database()

    org_id = args.org
    if not org_id:
        rows = _db_execute("SELECT org_id FROM orgs LIMIT 2", fetchall=True)
        if len(rows) != 1:
            print(
                "Error: several organizations exist, pass --org <org_id>.",
                file=sys.stderr,
            )
            return 1
        org_id = rows[0][0]

    try:
        period = report.parse_period(args.period, args.date_from, args.date_to)
    except report.PeriodError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    audit = get_audit_log()
    data = report.build_report_data(org_id, period, audit=audit)
    report.record_generation(audit, org_id, "cli", data)

    out = args.out or f"cerbere-compliance-{data['period']['label']}.{args.format}"
    if args.format == "json":
        with open(out, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
    else:
        with open(out, "wb") as handle:
            handle.write(report.render_pdf(data))
    status = data["integrity"]["status"]
    print(f"Report {data['report_id']} written to {out} (audit chain: {status}).")
    # Code de sortie distinct pour l'automatisation (cron) : le rapport est écrit, mais l'audit est suspect.
    return 2 if status == "failed" else 0


def cmd_list_users(_args) -> int:
    from collector.auth.users import _db_execute

    _init_database()
    rows = _db_execute(
        "SELECT email, role, active, org_id FROM users ORDER BY email", fetchall=True
    )
    if not rows:
        print("No users yet. Create one with: python -m collector.cli create-admin")
        return 0
    for email, role, active, org_id in rows:
        print(
            f"{email}\t{role}\t{'active' if bool(active) else 'disabled'}\torg={org_id}"
        )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="collector.cli", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("create-admin", help="Create a workspace and its first admin")
    p.add_argument("--email", required=True)
    p.add_argument("--name")
    p.add_argument("--org", help="Organization / workspace name")
    p.add_argument(
        "--role",
        default="admin",
        choices=["admin", "developer", "auditor", "viewer"],
    )
    p.add_argument("--password-stdin", action="store_true")
    p.set_defaults(func=cmd_create_admin)

    p = sub.add_parser("set-password", help="Set or reset a user's password")
    p.add_argument("--email", required=True)
    p.add_argument("--password-stdin", action="store_true")
    p.set_defaults(func=cmd_set_password)

    p = sub.add_parser("migrate", help="Apply pending database migrations")
    p.add_argument(
        "--status", action="store_true", help="Show applied and pending migrations"
    )
    p.set_defaults(func=cmd_migrate)

    p = sub.add_parser("license", help="Show or install the license key")
    lic_sub = p.add_subparsers(dest="license_command", required=True)
    q = lic_sub.add_parser("status", help="Show the current plan and expiry")
    q.set_defaults(func=cmd_license_status)
    q = lic_sub.add_parser("install", help="Verify and install a license key")
    q.add_argument("file", help="File holding the license key, or - for stdin")
    q.set_defaults(func=cmd_license_install)

    p = sub.add_parser(
        "report", help="Generate the compliance report (Team and Enterprise)"
    )
    p.add_argument(
        "--org", help="Organization id (optional if the instance has only one)"
    )
    p.add_argument("--period", help="Calendar month, YYYY-MM (default: previous month)")
    p.add_argument("--from", dest="date_from", help="Start date YYYY-MM-DD (with --to)")
    p.add_argument("--to", dest="date_to", help="End date YYYY-MM-DD, inclusive")
    p.add_argument("--format", choices=["pdf", "json"], default="pdf")
    p.add_argument("--out", help="Output file")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("list-users", help="List users")
    p.set_defaults(func=cmd_list_users)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
