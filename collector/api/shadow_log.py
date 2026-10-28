"""GET /api/shadow/log : journal du mode shadow (ce que Cerbere AURAIT fait).

En shadow mode, le SDK laisse passer l'action mais écrit dans le span :
    output_data["cerbere_shadow"] = {
        "would_have_action": "ALLOW" | "BLOCK" | "REQUIRE_APPROVAL",
        "reasons": [...], ...}
Ce module relit ces observations (déjà masquées par redact_pii à l'ingestion).

Paramètres : agent_id (optionnel), hours (1-168, défaut 24), limit (1-500),
since_enabled=1 -> pour un agent actuellement en shadow, la fenêtre démarre à
l'activation du shadow (table agent_runtime_modes, celle que le dashboard écrit).

Installation : copier ce fichier dans collector/api/ puis ajouter, juste après
`import collector.api.incidents` dans collector/api/__init__.py :
    import collector.api.shadow_log
"""

import time
from datetime import datetime, timezone

from flask import g, jsonify, request

from collector.api.helpers import _db_run, api_bp
from collector.api.incidents import _as_json, _log_span
from collector.auth import require_auth

MAX_HOURS = 24 * 7


def _to_epoch(value):
    """datetime / ISO / epoch -> epoch UTC (les timestamps SQL naïfs sont en UTC)."""
    try:
        if isinstance(value, (int, float)):
            return float(value)
        dt = value if isinstance(value, datetime) else datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        return None


def _mode_info(org_id, agent_id):
    """(mode, epoch du dernier changement) ; ("enforce", None) si jamais changé ;
    (None, None) si la table est illisible. Ne lève jamais."""
    try:
        row, _ = _db_run(
            "SELECT mode, updated_at FROM agent_runtime_modes WHERE org_id = ? AND agent_id = ?",
            (org_id, agent_id),
            fetch="one",
        )
        if not row:
            return "enforce", None
        return row[0], (_to_epoch(row[1]) if row[1] else None)
    except Exception:
        return None, None


@api_bp.route("/api/shadow/log", methods=["GET"], endpoint="api_shadow_log")
def api_shadow_log():
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401

    agent_id = (request.args.get("agent_id") or "").strip()[:64]
    try:
        hours = max(1, min(int(request.args.get("hours", 24)), MAX_HOURS))
        limit = max(1, min(int(request.args.get("limit", 300)), 500))
    except (TypeError, ValueError):
        hours, limit = 24, 300
    want_since = str(request.args.get("since_enabled", "")).lower() in ("1", "true", "yes")

    now = time.time()
    window_start = now - hours * 3600
    mode_info = None
    since_enabled = False
    if agent_id:
        mode, changed_at = _mode_info(g.org_id, agent_id)
        mode_info = {"mode": mode, "since": changed_at}
        if want_since and mode == "shadow" and changed_at:
            window_start = max(changed_at, now - MAX_HOURS * 3600)
            since_enabled = True

    where = "org_id = ? AND timestamp >= ? AND CAST(output_data AS TEXT) LIKE ?"
    params = [g.org_id, window_start, '%"cerbere_shadow"%']
    if agent_id:
        where += " AND agent_id = ?"
        params.append(agent_id)

    rows, _ = _db_run(
        f"""SELECT span_id, span_type, timestamp, latency_ms, input_data, output_data,
                   security_checks, blocked, block_reason, cost_usd, detection_layer,
                   model, agent_id
            FROM spans WHERE {where} ORDER BY timestamp DESC LIMIT {limit}""",
        tuple(params),
        fetch="all",
    )

    spans = []
    summary = {"total": 0, "would_block": 0, "would_require_approval": 0, "allowed": 0}
    by_tool = {}
    for r in rows:
        d = _log_span(r)
        out = _as_json(r[5], {})
        shadow = out.get("cerbere_shadow") if isinstance(out, dict) else None
        raw = shadow.get("reasons") if isinstance(shadow, dict) else None
        d["reasons"] = [str(x)[:300] for x in raw][:5] if isinstance(raw, list) else []
        d["agent_id"] = r[12]
        spans.append(d)

        action = d["shadow"] or "ALLOW"
        summary["total"] += 1
        if action == "BLOCK":
            summary["would_block"] += 1
            key = d["tool"] or d["model"] or d["type"]
            by_tool[key] = by_tool.get(key, 0) + 1
        elif action == "REQUIRE_APPROVAL":
            summary["would_require_approval"] += 1
        else:
            summary["allowed"] += 1

    top = sorted(by_tool.items(), key=lambda kv: -kv[1])[:5]
    resp = jsonify(
        {
            "hours": hours,
            "window_start": window_start,
            "since_enabled": since_enabled,
            "mode": mode_info,
            "summary": summary,
            "by_tool": [{"tool": k, "count": v} for k, v in top],
            "spans": spans,
            "truncated": len(rows) >= limit,
        }
    )
    resp.headers["Cache-Control"] = "no-store"
    return resp, 200