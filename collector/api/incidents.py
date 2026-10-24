"""Capture d'incident : preuves scellées, TTL, accès humain audité.

Principe : le masquage reste irréversible par défaut. Un ADMIN HUMAIN peut
ouvrir, pour un agent précis et une durée limitée, une capture dont les
valeurs sensibles sont scellées avec une clé publique. Le collector garde la
clé privée (chiffrée par AGENTGUARD_INCIDENT_MASTER_KEY) ; seule une session
humaine admin, avec un motif, peut rouvrir une valeur, et chaque accès est
écrit dans l'audit chaîné.

Désactivé par défaut : AGENTGUARD_INCIDENT_ENABLED=true ET clé maître valide.
Une clé API d'agent ne peut jamais ouvrir, fermer ni rouvrir un incident.

Humain (cookie de session, rôle admin) :
    POST /api/incidents                      ouvre (agent_id, ttl_seconds, reason)
    GET  /api/incidents                      liste (sans aucune valeur)
    POST /api/incidents/<id>/close           arrête la capture (purge=true : détruit tout)
    POST /api/incidents/<id>/reveal          rouvre une valeur (token, reason)
Agent (clé API) :
    GET  /v1/incident/active                 clé PUBLIQUE de l'incident ouvert pour lui
    POST /v1/incident/sealed                dépose des blobs chiffrés
"""

import os
import re
import secrets
import time

from flask import g, jsonify, request

from collector.api.helpers import (
    _audit_human_action,
    _db_run,
    _human_auth,
    _request_agent_id,
    api_bp,
    logger,
)
from collector.auth import require_auth
from collector.db import get_db, is_postgres
from collector.incident_crypto import (
    IncidentCryptoError,
    generate_incident_keypair,
    master_key_ready,
    open_sealed,
)

MIN_TTL_SECONDS = 60
DEFAULT_TTL_SECONDS = 6 * 3600
MAX_TTL_SECONDS = int(os.getenv("AGENTGUARD_INCIDENT_MAX_TTL_SECONDS", str(24 * 3600)))
MAX_ENTRIES_PER_REQUEST = 500
MAX_ENTRIES_PER_INCIDENT = 20000
MAX_BLOB_BYTES = 8192 + 32 + 12 + 16
REVEALS_PER_HOUR = int(os.getenv("AGENTGUARD_INCIDENT_REVEALS_PER_HOUR", "30"))
MIN_REASON_LENGTH = 10

_TOKEN_RE = re.compile("^\u27e6CERB:[0-9a-f]{16}\u27e7$")
_reveal_log: dict[tuple[str, str], list[float]] = {}


# ── garde-fous communs ──────────────────────────────────────────────────────


def _truthy(value):
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def _gate():
    """None si la fonctionnalité est utilisable, sinon la réponse à renvoyer."""
    if not _truthy(os.getenv("AGENTGUARD_INCIDENT_ENABLED")):
        return jsonify({"error": "incident capture is disabled"}), 404
    if not master_key_ready():
        logger.error("incident_master_key_missing_or_invalid")
        return jsonify({"error": "incident capture unavailable"}), 503
    return None


_INCIDENT_COLUMNS = [
    ("org_id", "TEXT"),
    ("agent_id", "TEXT"),
    ("status", "TEXT"),
    ("reason", "TEXT"),
    ("opened_by", "TEXT"),
    ("created_at", "DOUBLE PRECISION"),
    ("expires_at", "DOUBLE PRECISION"),
    ("closed_at", "DOUBLE PRECISION"),
    ("public_key", "TEXT"),
    ("wrapped_private_key", "TEXT"),
]


def _prepare_tables():
    _db_run(
        """CREATE TABLE IF NOT EXISTS incidents (
            id TEXT PRIMARY KEY,
            org_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            status TEXT NOT NULL,
            reason TEXT,
            opened_by TEXT,
            created_at DOUBLE PRECISION NOT NULL,
            expires_at DOUBLE PRECISION NOT NULL,
            closed_at DOUBLE PRECISION,
            public_key TEXT NOT NULL,
            wrapped_private_key TEXT NOT NULL
        )""",
        commit=True,
    )
    _db_run(
        """CREATE TABLE IF NOT EXISTS incident_sealed (
            incident_id TEXT NOT NULL,
            token TEXT NOT NULL,
            ciphertext TEXT NOT NULL,
            created_at DOUBLE PRECISION NOT NULL,
            PRIMARY KEY (incident_id, token)
        )""",
        commit=True,
    )
    _ensure_incident_columns()


def _ensure_incident_columns():
    """MIGRATION idempotente : « ADD COLUMN IF NOT EXISTS » est du Postgres
    pur et lève OperationalError en SQLite. On vérifie donc l'existence des
    colonnes à la main en SQLite."""
    if is_postgres():
        for col, dtype in _INCIDENT_COLUMNS:
            _db_run(
                f"ALTER TABLE incidents ADD COLUMN IF NOT EXISTS {col} {dtype}",
                commit=True,
            )
        return
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("PRAGMA table_info(incidents)")
        existing = {row[1] for row in cur.fetchall()}
        for col, dtype in _INCIDENT_COLUMNS:
            if col not in existing:
                cur.execute(f"ALTER TABLE incidents ADD COLUMN {col} {dtype}")
        conn.commit()
    finally:
        conn.close()

def _purge_expired():
    """Détruit chiffrés ET clé privée des incidents expirés (crypto-shredding)."""
    now = time.time()
    _db_run(
        """DELETE FROM incident_sealed WHERE incident_id IN
           (SELECT id FROM incidents WHERE expires_at <= ? AND status <> 'purged')""",
        (now,),
        commit=True,
    )
    _db_run(
        """UPDATE incidents SET status = 'purged', wrapped_private_key = ''
           WHERE expires_at <= ? AND status <> 'purged'""",
        (now,),
        commit=True,
    )


def _setup():
    gate = _gate()
    if gate:
        return gate
    _prepare_tables()
    _purge_expired()
    return None


def _is_admin():
    try:
        from agentguard.identity import Role
        from collector.auth.identity_resolution import resolve_full_identity

        identity = resolve_full_identity()
        return bool(identity) and identity.role == Role.ADMIN
    except Exception:
        return False


def _human_admin_or_error():
    """Session humaine (jamais une clé API) ET rôle admin."""
    if not _human_auth():
        return jsonify({"error": "Human session required"}), 401
    if not _is_admin():
        return jsonify({"error": "Admin role required"}), 403
    return None


def _json_body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _actor():
    return getattr(g, "human_email", None) or f"org:{g.org_id}"


def _reveal_allowed(org_id, actor):
    now = time.time()
    key = (org_id, actor)
    recent = [t for t in _reveal_log.get(key, []) if now - t < 3600]
    if len(recent) >= REVEALS_PER_HOUR:
        _reveal_log[key] = recent
        return False
    recent.append(now)
    _reveal_log[key] = recent
    return True


# ── humain : ouvrir / lister / fermer / rouvrir ─────────────────────────────


@api_bp.route("/api/incidents", methods=["POST"], endpoint="api_incident_open")
def api_incident_open():
    err = _setup() or _human_admin_or_error()
    if err:
        return err
    body = _json_body()
    agent_id = str(body.get("agent_id") or "").strip()[:64]
    reason = str(body.get("reason") or "").strip()
    try:
        ttl = int(body.get("ttl_seconds", DEFAULT_TTL_SECONDS))
    except (TypeError, ValueError):
        return jsonify({"error": "ttl_seconds must be an integer"}), 400
    if not agent_id:
        return jsonify({"error": "agent_id is required"}), 400
    if len(reason) < MIN_REASON_LENGTH:
        return jsonify(
            {"error": f"reason is required ({MIN_REASON_LENGTH} characters minimum)"}
        ), 400
    if not MIN_TTL_SECONDS <= ttl <= MAX_TTL_SECONDS:
        return jsonify(
            {
                "error": f"ttl_seconds must be between {MIN_TTL_SECONDS} and {MAX_TTL_SECONDS}"
            }
        ), 400

    now = time.time()
    open_row, _ = _db_run(
        "SELECT id FROM incidents WHERE org_id = ? AND agent_id = ? AND status = 'open' AND expires_at > ?",
        (g.org_id, agent_id, now),
        fetch="one",
    )
    if open_row:
        return jsonify({"error": "an incident is already open for this agent"}), 409

    incident_id = "inc_" + secrets.token_urlsafe(12)
    public_key, wrapped = generate_incident_keypair(incident_id)
    _db_run(
        """INSERT INTO incidents (id, org_id, agent_id, status, reason, opened_by,
               created_at, expires_at, public_key, wrapped_private_key)
           VALUES (?, ?, ?, 'open', ?, ?, ?, ?, ?, ?)""",
        (
            incident_id,
            g.org_id,
            agent_id,
            reason,
            _actor(),
            now,
            now + ttl,
            public_key,
            wrapped,
        ),
        commit=True,
    )
    _audit_human_action(
        "INCIDENT_OPENED",
        f"incident:{incident_id}",
        "opened",
        {
            "incident_id": incident_id,
            "agent_id": agent_id,
            "ttl_seconds": ttl,
            "reason": reason,
        },
    )
    return jsonify(
        {"incident_id": incident_id, "agent_id": agent_id, "expires_at": now + ttl}
    ), 201


@api_bp.route("/api/incidents", methods=["GET"], endpoint="api_incident_list")
def api_incident_list():
    err = _setup() or _human_admin_or_error()
    if err:
        return err
    rows, _ = _db_run(
        """SELECT i.id, i.agent_id, i.status, i.reason, i.opened_by, i.created_at,
                  i.expires_at, i.closed_at,
                  (SELECT COUNT(*) FROM incident_sealed s WHERE s.incident_id = i.id)
           FROM incidents i WHERE i.org_id = ? ORDER BY i.created_at DESC LIMIT 100""",
        (g.org_id,),
        fetch="all",
    )
    return jsonify(
        {
            "incidents": [
                {
                    "id": r[0],
                    "agent_id": r[1],
                    "status": r[2],
                    "reason": r[3],
                    "opened_by": r[4],
                    "created_at": r[5],
                    "expires_at": r[6],
                    "closed_at": r[7],
                    "sealed_values": int(r[8]),
                }
                for r in rows
            ]
        }
    ), 200


@api_bp.route(
    "/api/incidents/<incident_id>/close",
    methods=["POST"],
    endpoint="api_incident_close",
)
def api_incident_close(incident_id):
    err = _setup() or _human_admin_or_error()
    if err:
        return err
    purge = bool(_json_body().get("purge"))
    now = time.time()
    if purge:
        row, _ = _db_run(
            "SELECT id FROM incidents WHERE id = ? AND org_id = ?",
            (incident_id, g.org_id),
            fetch="one",
        )
        if not row:
            return jsonify({"error": "incident not found"}), 404
        _db_run(
            "DELETE FROM incident_sealed WHERE incident_id = ?",
            (incident_id,),
            commit=True,
        )
        _db_run(
            "UPDATE incidents SET status = 'purged', wrapped_private_key = '', closed_at = ? WHERE id = ? AND org_id = ?",
            (now, incident_id, g.org_id),
            commit=True,
        )
        new_status = "purged"
    else:
        _, n = _db_run(
            "UPDATE incidents SET status = 'closed', closed_at = ? WHERE id = ? AND org_id = ? AND status = 'open'",
            (now, incident_id, g.org_id),
            commit=True,
        )
        if n == 0:
            return jsonify({"error": "incident not found or not open"}), 404
        new_status = "closed"
    _audit_human_action(
        "INCIDENT_CLOSED",
        f"incident:{incident_id}",
        new_status,
        {"incident_id": incident_id, "purge": purge},
    )
    return jsonify({"incident_id": incident_id, "status": new_status}), 200


def _reveal_value(incident_id, token, reason):
    """Rouvre une valeur : motif, limite de débit, expiration, audit."""
    actor = _actor()

    def denied(why, status):
        _audit_human_action(
            "INCIDENT_REVEAL_DENIED",
            f"incident:{incident_id}",
            why,
            {
                "incident_id": incident_id,
                "token": token[:40],
                "why": why,
                "reason": reason,
            },
        )
        return jsonify({"error": why}), status

    if not _TOKEN_RE.match(token):
        return jsonify({"error": "invalid token"}), 400
    if len(reason) < MIN_REASON_LENGTH:
        return jsonify(
            {"error": f"reason is required ({MIN_REASON_LENGTH} characters minimum)"}
        ), 400
    if not _reveal_allowed(g.org_id, actor):
        return denied("reveal rate limit reached", 429)

    inc, _ = _db_run(
        "SELECT wrapped_private_key, expires_at, status FROM incidents WHERE id = ? AND org_id = ?",
        (incident_id, g.org_id),
        fetch="one",
    )
    if not inc:
        return jsonify({"error": "incident not found"}), 404
    wrapped, expires_at, status = inc
    if status == "purged" or float(expires_at) <= time.time() or not wrapped:
        return denied("incident expired: evidence destroyed", 410)

    sealed, _ = _db_run(
        "SELECT ciphertext FROM incident_sealed WHERE incident_id = ? AND token = ?",
        (incident_id, token),
        fetch="one",
    )
    if not sealed:
        return denied("token not found", 404)
    try:
        value = open_sealed(wrapped, incident_id, token, bytes.fromhex(sealed[0]))
    except IncidentCryptoError:
        logger.error("incident_reveal_decrypt_failed", incident_id=incident_id)
        return denied("cannot open sealed value", 500)

    _audit_human_action(
        "INCIDENT_REVEALED",
        f"incident:{incident_id}",
        "revealed",
        {
            "incident_id": incident_id,
            "token": token,
            "reason": reason,
            "revealed_by": actor,
        },
    )
    resp = jsonify({"incident_id": incident_id, "token": token, "value": value})
    resp.headers["Cache-Control"] = "no-store"
    return resp, 200


@api_bp.route(
    "/api/incidents/<incident_id>/reveal",
    methods=["POST"],
    endpoint="api_incident_reveal",
)
def api_incident_reveal(incident_id):
    err = _setup() or _human_admin_or_error()
    if err:
        return err
    body = _json_body()
    return _reveal_value(
        incident_id,
        str(body.get("token") or ""),
        str(body.get("reason") or "").strip(),
    )


def _incident_for_token(org_id, token):
    """Incident vivant de l'organisation qui contient ce token, sinon None."""
    row, _ = _db_run(
        """SELECT i.id FROM incident_sealed s JOIN incidents i ON i.id = s.incident_id
           WHERE i.org_id = ? AND s.token = ? AND i.status <> 'purged' AND i.expires_at > ?
           ORDER BY i.created_at DESC LIMIT 1""",
        (org_id, token, time.time()),
        fetch="one",
    )
    return row[0] if row else None


@api_bp.route(
    "/api/incidents/reveal", methods=["POST"], endpoint="api_incident_reveal_token"
)
def api_incident_reveal_token():
    """Rouvre un token sans connaître l'incident (utilisé par le dashboard)."""
    err = _setup() or _human_admin_or_error()
    if err:
        return err
    body = _json_body()
    token = str(body.get("token") or "")
    reason = str(body.get("reason") or "").strip()
    if not _TOKEN_RE.match(token):
        return jsonify({"error": "invalid token"}), 400
    incident_id = _incident_for_token(g.org_id, token)
    if not incident_id:
        return jsonify({"error": "token not found or evidence expired"}), 404
    return _reveal_value(incident_id, token, reason)


@api_bp.route(
    "/api/incidents/available", methods=["POST"], endpoint="api_incident_available"
)
def api_incident_available():
    """Quels tokens d'une liste sont rouvrables ? Ne renvoie aucune valeur."""
    err = _setup() or _human_admin_or_error()
    if err:
        return err
    tokens = _json_body().get("tokens")
    if not isinstance(tokens, list):
        return jsonify({"error": "tokens must be a list"}), 400
    wanted = [
        t
        for t in dict.fromkeys(tokens[:200])
        if isinstance(t, str) and _TOKEN_RE.match(t)
    ]
    available = [t for t in wanted if _incident_for_token(g.org_id, t)]
    return jsonify({"available": available}), 200


@api_bp.route("/api/incidents/config", methods=["GET"], endpoint="api_incident_config")
def api_incident_config():
    """État de la fonctionnalité pour le dashboard (aucun secret)."""
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401
    enabled = _truthy(os.getenv("AGENTGUARD_INCIDENT_ENABLED"))
    ready = enabled and master_key_ready()
    return jsonify(
        {
            "enabled": enabled,
            "ready": ready,
            "can_manage": bool(ready and _is_admin()),
            "max_ttl_seconds": MAX_TTL_SECONDS,
            "min_reason_length": MIN_REASON_LENGTH,
        }
    ), 200


def open_incident_for(org_id, agent_id):
    """incident_id ouvert pour cet agent, sinon None. Ne lève jamais : utilisé
    par /api/agent/status, qui ne doit jamais échouer à cause de cette option."""
    try:
        if _gate():
            return None
        _prepare_tables()
        _purge_expired()
        row, _ = _db_run(
            "SELECT id FROM incidents WHERE org_id = ? AND agent_id = ? AND status = 'open' AND expires_at > ? LIMIT 1",
            (org_id, agent_id, time.time()),
            fetch="one",
        )
        return row[0] if row else None
    except Exception:
        logger.warning("incident_status_lookup_failed")
        return None


# ── agent : clé publique + dépôt de blobs chiffrés ──────────────────────────


@api_bp.route("/v1/incident/active", methods=["GET"], endpoint="api_incident_active")
def api_incident_active():
    err = _setup()
    if err:
        return err
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401
    agent_id = _request_agent_id()
    if not agent_id:
        return jsonify({"error": "agent identity required"}), 400
    row, _ = _db_run(
        """SELECT id, public_key, expires_at FROM incidents
           WHERE org_id = ? AND agent_id = ? AND status = 'open' AND expires_at > ?
           ORDER BY created_at DESC LIMIT 1""",
        (g.org_id, agent_id, time.time()),
        fetch="one",
    )
    if not row:
        return jsonify({"error": "no open incident for this agent"}), 404
    return jsonify(
        {"incident_id": row[0], "public_key": row[1], "expires_at": float(row[2])}
    ), 200


@api_bp.route("/v1/incident/sealed", methods=["POST"], endpoint="api_incident_sealed")
def api_incident_sealed():
    err = _setup()
    if err:
        return err
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401
    agent_id = _request_agent_id()
    body = _json_body()
    incident_id = str(body.get("incident_id") or "")
    sealed = body.get("sealed")
    if not agent_id or not incident_id or not isinstance(sealed, dict) or not sealed:
        return jsonify({"error": "incident_id and sealed are required"}), 400
    if len(sealed) > MAX_ENTRIES_PER_REQUEST:
        return jsonify({"error": "too many entries"}), 413

    inc, _ = _db_run(
        "SELECT expires_at, status FROM incidents WHERE id = ? AND org_id = ? AND agent_id = ?",
        (incident_id, g.org_id, agent_id),
        fetch="one",
    )
    if not inc or inc[1] != "open" or float(inc[0]) <= time.time():
        # Même réponse pour « inconnu », « d'un autre agent » et « fermé » :
        # aucune information sur l'existence d'incidents hors de son périmètre.
        return jsonify({"error": "no open incident"}), 404

    count_row, _ = _db_run(
        "SELECT COUNT(*) FROM incident_sealed WHERE incident_id = ?",
        (incident_id,),
        fetch="one",
    )
    if int(count_row[0]) + len(sealed) > MAX_ENTRIES_PER_INCIDENT:
        return jsonify({"error": "incident evidence quota reached"}), 413

    now = time.time()
    rows = []
    for token, blob_hex in sealed.items():
        if not isinstance(token, str) or not _TOKEN_RE.match(token):
            return jsonify({"error": "invalid token"}), 400
        try:
            blob = bytes.fromhex(blob_hex) if isinstance(blob_hex, str) else b""
        except ValueError:
            blob = b""
        if not 44 + 16 <= len(blob) <= MAX_BLOB_BYTES:
            return jsonify({"error": "invalid sealed blob"}), 400
        rows.append((incident_id, token, blob_hex, now))
    insert_sql = (
        "INSERT INTO incident_sealed (incident_id, token, ciphertext, created_at) "
        "VALUES (?, ?, ?, ?) ON CONFLICT (incident_id, token) DO NOTHING"
    )
    conn = get_db()
    try:
        cur = conn.cursor()
        for row in rows:  # un seul commit : le lot entre en entier ou pas du tout
            cur.execute(
                insert_sql.replace("?", "%s") if is_postgres() else insert_sql, row
            )
        conn.commit()
    finally:
        conn.close()
    return jsonify({"stored": len(rows)}), 200