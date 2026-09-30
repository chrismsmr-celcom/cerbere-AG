"""Widgets dashboard : heatmap, breakdowns, daily, cost/latency/trends, audit trail."""

import json
import sqlite3

from flask import jsonify, g, request

from collector.db import get_db, is_postgres, _get_db_path, sql_placeholder
from collector.api.helpers import api_bp, _sqlite_connect


@api_bp.route("/api/heatmap")
def api_heatmap():
    """Calendar heatmap (façon GitHub contributions) — une case par jour sur
    ~13 semaines. Groupement par date complète (l'ancien EXTRACT(DAY)
    fusionnait le 5 janvier et le 5 février)."""
    days_back = request.args.get("days", default=91, type=int)
    days_back = max(7, min(days_back, 366))
    if is_postgres():
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            SELECT TO_CHAR(created_at, 'YYYY-MM-DD') as date, COUNT(*) as total,
                   SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked,
                   SUM(CASE WHEN NOT blocked AND security_checks IS NOT NULL
                            AND security_checks::text != '[]' THEN 1 ELSE 0 END) as flagged
            FROM spans WHERE org_id = %s AND created_at > NOW() - (%s || ' days')::interval
            GROUP BY date ORDER BY date
        """, (g.org_id, days_back))
        cells = [{"date": r[0], "total": r[1], "blocked": r[2] or 0, "flagged": r[3] or 0} for r in cur.fetchall()]
        conn.close()
    else:
        conn = _sqlite_connect()
        try:
            cur = conn.cursor()
            cur.execute("""
                SELECT strftime('%Y-%m-%d', created_at) as date, COUNT(*) as total,
                       SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked,
                       SUM(CASE WHEN NOT blocked AND security_checks IS NOT NULL
                                AND security_checks != '[]' THEN 1 ELSE 0 END) as flagged
                FROM spans WHERE org_id = ? AND created_at > datetime('now', '-' || ? || ' days')
                GROUP BY date ORDER BY date
            """, (g.org_id, days_back))
            cells = [{"date": r[0], "total": r[1], "blocked": r[2] or 0, "flagged": r[3] or 0} for r in cur.fetchall()]
        finally:
            conn.close()
    return jsonify({"days": days_back, "cells": cells})


@api_bp.route("/api/checks/breakdown")
def api_checks_breakdown():
    conn = get_db() if is_postgres() else _sqlite_connect()
    cur = conn.cursor()
    try:
        cur.execute("SELECT security_checks FROM spans WHERE org_id = ? AND security_checks IS NOT NULL",
                    (g.org_id,))
        rows = cur.fetchall()
    finally:
        conn.close()

    breakdown = {}
    for row in rows:
        raw = row[0]
        try:
            checks = raw if isinstance(raw, list) else json.loads(raw)
        except Exception:
            continue
        for c in (checks or []):
            name = c.get("check_name", "unknown")
            entry = breakdown.setdefault(name, {"total": 0, "flagged": 0})
            entry["total"] += 1
            if not c.get("passed", True):
                entry["flagged"] += 1

    result = [
        {"check_name": name, "total": v["total"], "flagged": v["flagged"],
         "flag_rate": round(v["flagged"] / v["total"] * 100, 1) if v["total"] else 0}
        for name, v in breakdown.items()
    ]
    return jsonify(sorted(result, key=lambda x: -x["total"]))


@api_bp.route("/api/checks/daily")
def api_checks_daily():
    if is_postgres():
        conn = get_db()
        try:
            cur = conn.cursor()
            cur.execute("""
                SELECT DATE(created_at) as day, c->>'check_name' as name,
                       COUNT(*) as total,
                       SUM(CASE WHEN (c->>'passed')::boolean THEN 0 ELSE 1 END) as flagged
                FROM spans, jsonb_array_elements(security_checks) c
                WHERE org_id = %s AND created_at > NOW() - INTERVAL '14 days'
                GROUP BY day, name ORDER BY day
            """, (g.org_id,))
            rows = [{"day": str(r[0]), "name": r[1], "total": r[2], "flagged": r[3] or 0} for r in cur.fetchall()]
        except Exception:
            rows = []
        conn.close()
    else:
        conn = _sqlite_connect()
        try:
            cur = conn.cursor()
            cur.execute("""
                SELECT DATE(created_at) as day, json_extract(c.value, '$.check_name') as name,
                       COUNT(*) as total,
                       SUM(CASE WHEN json_extract(c.value, '$.passed') = 1 THEN 0 ELSE 1 END) as flagged
                FROM spans, json_each(spans.security_checks) c
                WHERE org_id = ? AND created_at > datetime('now','-14 days')
                GROUP BY day, name ORDER BY day
            """, (g.org_id,))
            rows = [{"day": str(r[0]), "name": r[1], "total": r[2], "flagged": r[3] or 0} for r in cur.fetchall()]
        except Exception:
            rows = []
        finally:
            conn.close()
    return jsonify(rows)


@api_bp.route("/api/models/daily")
def api_models_daily():
    if is_postgres():
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            SELECT DATE(created_at) as day, model, COUNT(*) as n
            FROM spans WHERE org_id = %s AND model IS NOT NULL AND model != ''
              AND created_at > NOW() - INTERVAL '14 days'
            GROUP BY day, model ORDER BY day
        """, (g.org_id,))
        rows = [{"day": str(r[0]), "model": r[1], "n": r[2]} for r in cur.fetchall()]
        conn.close()
    else:
        conn = _sqlite_connect()
        try:
            cur = conn.cursor()
            cur.execute("""
                SELECT DATE(created_at) as day, model, COUNT(*) as n
                FROM spans WHERE org_id = ? AND model IS NOT NULL AND model != ''
                  AND created_at > datetime('now', '-14 days')
                GROUP BY day, model ORDER BY day
            """, (g.org_id,))
            rows = [{"day": str(r[0]), "model": r[1], "n": r[2]} for r in cur.fetchall()]
        finally:
            conn.close()
    return jsonify(rows)


@api_bp.route("/api/spans/expensive")
def api_expensive_spans():
    if is_postgres():
        conn = get_db()
        try:
            cur = conn.cursor()
            cur.execute("""
                SELECT trace_id, span_id, span_type, model, cost_usd,
                       COALESCE(input_data->>'prompt', input_data->>'tool', '') AS prompt,
                       COALESCE(output_data->>'response', '') AS response,
                       input_tokens, output_tokens
                FROM spans WHERE org_id = %s AND cost_usd > 0
                ORDER BY cost_usd DESC LIMIT 10
            """, (g.org_id,))
            rows = [
                {"trace_id": r[0], "span_id": r[1], "span_type": r[2], "model": r[3],
                 "cost_usd": r[4], "prompt": (r[5] or "")[:300], "response": (r[6] or "")[:300],
                 "input_tokens": r[7] or 0, "output_tokens": r[8] or 0}
                for r in cur.fetchall()
            ]
        except Exception:
            rows = []
        conn.close()
    else:
        conn = _sqlite_connect()
        try:
            cur = conn.cursor()
            cur.execute("""
                SELECT trace_id, span_id, span_type, model, cost_usd,
                       COALESCE(json_extract(input_data, '$.prompt'), json_extract(input_data, '$.tool'), '') AS prompt,
                       COALESCE(json_extract(output_data, '$.response'), '') AS response,
                       input_tokens, output_tokens
                FROM spans WHERE org_id = ? AND cost_usd > 0
                ORDER BY cost_usd DESC LIMIT 10
            """, (g.org_id,))
            rows = [
                {"trace_id": r[0], "span_id": r[1], "span_type": r[2], "model": r[3],
                 "cost_usd": r[4], "prompt": (r[5] or "")[:300], "response": (r[6] or "")[:300],
                 "input_tokens": r[7] or 0, "output_tokens": r[8] or 0}
                for r in cur.fetchall()
            ]
        except Exception:
            rows = []
        finally:
            conn.close()
    return jsonify(rows)


def _daily_cost_rows_pg():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT DATE(created_at) as day, SUM(cost_usd) as cost,
               COALESCE(SUM(input_tokens + output_tokens), 0) as tokens
        FROM spans WHERE org_id = %s AND created_at > NOW() - INTERVAL '14 days'
        GROUP BY day ORDER BY day
    """, (g.org_id,))
    rows = [{"day": str(r[0]), "cost": round(float(r[1] or 0), 6), "tokens": int(r[2] or 0)} for r in cur.fetchall()]
    conn.close()
    return rows


@api_bp.route("/api/cost/trend")
def api_cost_trend():
    if is_postgres():
        return jsonify(_daily_cost_rows_pg())
    conn = _sqlite_connect()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT DATE(created_at) as day, SUM(cost_usd) as cost,
                   COALESCE(SUM(input_tokens + output_tokens), 0) as tokens
            FROM spans WHERE org_id = ? AND created_at > datetime('now', '-14 days')
            GROUP BY day ORDER BY day
        """, (g.org_id,))
        rows = [{"day": str(r[0]), "cost": round(float(r[1] or 0), 6), "tokens": int(r[2] or 0)} for r in cur.fetchall()]
    finally:
        conn.close()
    return jsonify(rows)


@api_bp.route("/api/latency/distribution")
def api_latency_distribution():
    conn = get_db() if is_postgres() else _sqlite_connect()
    cur = conn.cursor()
    try:
        cur.execute("SELECT latency_ms FROM spans WHERE org_id = ? AND latency_ms > 0 ORDER BY latency_ms",
                    (g.org_id,))
        values = [r[0] for r in cur.fetchall()]
    finally:
        conn.close()

    def pct(vals, q):
        if not vals:
            return 0
        idx = min(len(vals) - 1, int(len(vals) * q))
        return round(vals[idx], 1)

    return jsonify({
        "count": len(values),
        "p50": pct(values, 0.50), "p90": pct(values, 0.90),
        "p95": pct(values, 0.95), "p99": pct(values, 0.99),
        "min": round(min(values), 1) if values else 0,
        "max": round(max(values), 1) if values else 0,
    })


@api_bp.route("/api/events/recent")
def api_recent_events():
    conn = get_db() if is_postgres() else _sqlite_connect()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT span_type, detection_layer, blocked, block_reason, created_at, security_checks
            FROM spans WHERE org_id = ? ORDER BY created_at DESC LIMIT 8
        """, (g.org_id,))
        events = []
        for r in cur.fetchall():
            try:
                checks = r[5] if isinstance(r[5], list) else json.loads(r[5] or "[]")
            except Exception:
                checks = []
            risk = "low"
            for c in checks:
                if c.get("risk_level") in ("high", "critical"):
                    risk = c.get("risk_level")
                    break
            events.append({
                "span_type": r[0], "layer": r[1] or "regex", "blocked": bool(r[2]),
                "reason": r[3], "created_at": str(r[4]), "risk": risk,
            })
    finally:
        conn.close()
    return jsonify(events)


@api_bp.route("/api/trend/daily")
def api_trend_daily():
    if is_postgres():
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            SELECT DATE(created_at) as day, COUNT(*) as total,
                   SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked
            FROM spans WHERE org_id = %s AND created_at > NOW() - INTERVAL '14 days'
            GROUP BY day ORDER BY day
        """, (g.org_id,))
        rows = [{"day": str(r[0]), "total": r[1], "blocked": r[2] or 0} for r in cur.fetchall()]
        conn.close()
    else:
        conn = _sqlite_connect()
        try:
            cur = conn.cursor()
            cur.execute("""
                SELECT DATE(created_at) as day, COUNT(*) as total,
                       SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked
                FROM spans WHERE org_id = ? AND created_at > datetime('now', '-14 days')
                GROUP BY day ORDER BY day
            """, (g.org_id,))
            rows = [{"day": str(r[0]), "total": r[1], "blocked": r[2] or 0} for r in cur.fetchall()]
        finally:
            conn.close()
    return jsonify(rows)


@api_bp.route("/api/audit/trail")
def api_audit_trail():
    if is_postgres():
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            SELECT created_at, trace_id, span_id, span_type, detection_layer, model, blocked,
                   COALESCE(input_data->>'prompt', input_data->>'tool', '') AS prompt
            FROM spans WHERE org_id = %s ORDER BY created_at DESC LIMIT 50
        """, (g.org_id,))
        rows = [
            {"timestamp": str(r[0]), "trace_id": r[1], "span_id": r[2],
             "span_type": r[3], "layer": r[4] or "regex", "model": r[5] or "—",
             "blocked": bool(r[6]), "prompt": (r[7] or "")[:120]}
            for r in cur.fetchall()
        ]
        conn.close()
    else:
        conn = _sqlite_connect()
        try:
            cur = conn.cursor()
            cur.execute("""
                SELECT created_at, trace_id, span_id, span_type, detection_layer, model, blocked,
                       COALESCE(json_extract(input_data, '$.prompt'), json_extract(input_data, '$.tool'), '') AS prompt
                FROM spans WHERE org_id = ? ORDER BY created_at DESC LIMIT 50
            """, (g.org_id,))
            rows = [
                {"timestamp": str(r[0]), "trace_id": r[1], "span_id": r[2],
                 "span_type": r[3], "layer": r[4] or "regex", "model": r[5] or "—",
                 "blocked": bool(r[6]), "prompt": (r[7] or "")[:120]}
                for r in cur.fetchall()
            ]
        finally:
            conn.close()
    return jsonify(rows)