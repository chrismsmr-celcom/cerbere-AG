"""GET /api/traces, GET /api/traces/<trace_id>."""

import json
import sqlite3

from flask import jsonify, g

from collector.db import get_db, dict_from_row, is_postgres, _get_db_path, sql_placeholder
from collector.api.helpers import api_bp, _as_json, _sqlite_connect


@api_bp.route("/api/traces")
def list_traces():
    if is_postgres():
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            SELECT trace_id, COUNT(*) as span_count,
                   SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked_count,
                   SUM(cost_usd) as total_cost,
                   MAX(created_at) as last_seen,
                   STRING_AGG(DISTINCT detection_layer, ',') as detection_layers
            FROM spans WHERE org_id = %s
            GROUP BY trace_id
            ORDER BY last_seen DESC LIMIT 100
        """, (g.org_id,))
        rows = [dict_from_row(r, cur) for r in cur.fetchall()]
        conn.close()
    else:
        conn = _sqlite_connect()
        try:
            cur = conn.cursor()
            cur.execute("""
                SELECT trace_id, COUNT(*) as span_count,
                       SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked_count,
                       SUM(cost_usd) as total_cost,
                       MAX(created_at) as last_seen,
                       GROUP_CONCAT(DISTINCT detection_layer) as detection_layers
                FROM spans WHERE org_id = ?
                GROUP BY trace_id
                ORDER BY last_seen DESC LIMIT 100
            """, (g.org_id,))
            rows = [dict_from_row(r, cur) for r in cur.fetchall()]
        finally:
            conn.close()
    return jsonify(rows)


@api_bp.route("/api/traces/<trace_id>")
def get_trace(trace_id):
    if is_postgres():
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM spans WHERE trace_id = %s AND org_id = %s ORDER BY timestamp",
                    (trace_id, g.org_id))
        rows = [dict_from_row(r, cur) for r in cur.fetchall()]
        conn.close()
    else:
        conn = _sqlite_connect()
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM spans WHERE trace_id = ? AND org_id = ? ORDER BY timestamp",
                        (trace_id, g.org_id))
            rows = [dict_from_row(r, cur) for r in cur.fetchall()]
        finally:
            conn.close()

    for r in rows:
        r["input_data"] = _as_json(r["input_data"], {})
        r["output_data"] = _as_json(r["output_data"], {})
        r["security_checks"] = _as_json(r["security_checks"], [])
        r["blocked"] = bool(r["blocked"])
    return jsonify(rows)