"""Métriques globales, detection/llm stats, modèles."""

import json
import sqlite3

from flask import jsonify, g, request

from collector.db import get_db, is_postgres, _get_db_path, sql_true, sql_placeholder
from collector.api.helpers import api_bp, logger, _sqlite_connect


@api_bp.route("/api/metrics")
def get_metrics():
    empty_metrics = {
        "total_spans": 0,
        "total_traces": 0,
        "blocked_operations": 0,
        "total_cost_usd": 0.0,
        "total_tokens": 0,
        "avg_latency_ms": 0.0,
        "avg_ml_score": 0.0,
        "avg_llm_score": 0.0,
        "llm_judge_count": 0,
        "risk_distribution": {"low": 0, "medium": 0, "high": 0, "critical": 0},
        "top_threats": [],
        "detection_layers": {},
        "version": "v6.0.0",
    }

    org_id = getattr(g, "org_id", None)
    if not org_id:
        logger.warning("metrics_no_org_id", endpoint=request.endpoint)
        empty_metrics["error"] = "no_org_id"
        return jsonify(empty_metrics), 200

    p = sql_placeholder()

    try:
        conn = get_db() if is_postgres() else _sqlite_connect()
        cur = conn.cursor()
        try:
            cur.execute(f"SELECT COUNT(*) FROM spans WHERE org_id = {p}", (org_id,))
            total_spans = cur.fetchone()[0] or 0

            cur.execute(f"SELECT COUNT(DISTINCT trace_id) FROM spans WHERE org_id = {p}", (org_id,))
            total_traces = cur.fetchone()[0] or 0

            cur.execute(f"SELECT SUM(CASE WHEN blocked THEN 1 ELSE 0 END) FROM spans WHERE org_id = {p}", (org_id,))
            blocked = cur.fetchone()[0] or 0

            cur.execute(f"SELECT SUM(cost_usd) FROM spans WHERE org_id = {p}", (org_id,))
            total_cost = cur.fetchone()[0] or 0

            cur.execute(f"SELECT COALESCE(SUM(input_tokens + output_tokens), 0) FROM spans WHERE org_id = {p}", (org_id,))
            total_tokens = cur.fetchone()[0] or 0

            cur.execute(f"SELECT AVG(latency_ms) FROM spans WHERE latency_ms > 0 AND org_id = {p}", (org_id,))
            avg_latency = cur.fetchone()[0] or 0

            try:
                if is_postgres():
                    cur.execute("""
                        SELECT detection_layer, COUNT(*) as count
                        FROM spans WHERE detection_layer IS NOT NULL AND org_id = %s
                        GROUP BY detection_layer
                    """, (org_id,))
                else:
                    cur.execute("""
                        SELECT detection_layer, COUNT(*) as count
                        FROM spans WHERE detection_layer IS NOT NULL AND org_id = ?
                        GROUP BY detection_layer
                    """, (org_id,))
                detection_stats = {row[0]: row[1] for row in cur.fetchall()}
            except Exception as e:
                logger.warning("metrics_detection_query_failed", error=str(e))
                detection_stats = {}

            try:
                cur.execute(f"SELECT AVG(ml_score) FROM spans WHERE ml_score IS NOT NULL AND org_id = {p}", (org_id,))
                avg_ml_score = cur.fetchone()[0] or 0
                cur.execute(f"SELECT AVG(llm_score) FROM spans WHERE llm_score IS NOT NULL AND org_id = {p}", (org_id,))
                avg_llm_score = cur.fetchone()[0] or 0
                cur.execute(f"SELECT COUNT(*) FROM spans WHERE detection_layer = 'llm_judge' AND org_id = {p}", (org_id,))
                llm_count = cur.fetchone()[0] or 0
            except Exception as e:
                logger.warning("metrics_scores_query_failed", error=str(e))
                avg_ml_score = 0
                avg_llm_score = 0
                llm_count = 0

            risk_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
            try:
                if is_postgres():
                    cur.execute("""
                        SELECT jsonb_array_elements(security_checks) as check
                        FROM spans WHERE created_at > NOW() - INTERVAL '1 day' AND org_id = %s
                    """, (org_id,))
                    for row in cur.fetchall():
                        check = row[0] if isinstance(row[0], dict) else {}
                        level = check.get("risk_level", "low")
                        if level in risk_counts:
                            risk_counts[level] += 1
                else:
                    cur.execute("""
                        SELECT security_checks FROM spans
                        WHERE created_at > datetime('now', '-1 day') AND org_id = ?
                    """, (org_id,))
                    for row in cur.fetchall():
                        try:
                            checks = json.loads(row[0] or "[]")
                            for check in checks:
                                level = check.get("risk_level", "low")
                                if level in risk_counts:
                                    risk_counts[level] += 1
                        except Exception:
                            pass
            except Exception as e:
                logger.warning("metrics_risk_query_failed", error=str(e))

            try:
                cur.execute(f"""
                    SELECT block_reason, COUNT(*) as count
                    FROM spans WHERE blocked = {sql_true()} AND org_id = {p}
                    GROUP BY block_reason ORDER BY count DESC LIMIT 5
                """, (org_id,))
                top_threats = [{"reason": r[0], "count": r[1]} for r in cur.fetchall()]
            except Exception as e:
                logger.warning("metrics_threats_query_failed", error=str(e))
                top_threats = []

        finally:
            conn.close()

        return jsonify({
            "total_spans": total_spans,
            "total_traces": total_traces,
            "blocked_operations": blocked,
            "total_cost_usd": round(float(total_cost or 0), 6),
            "total_tokens": int(total_tokens),
            "avg_latency_ms": round(float(avg_latency or 0), 2),
            "avg_ml_score": round(float(avg_ml_score or 0), 3),
            "avg_llm_score": round(float(avg_llm_score or 0), 3),
            "llm_judge_count": llm_count,
            "risk_distribution": risk_counts,
            "top_threats": top_threats,
            "detection_layers": detection_stats,
            "version": "v6.0.0",
        })

    except Exception as e:
        logger.error("metrics_endpoint_failed", error=str(e), org_id=org_id)
        empty_metrics["error"] = str(e)[:200]
        return jsonify(empty_metrics), 200


@api_bp.route("/api/detection/stats")
def get_detection_stats():
    org_id = getattr(g, "org_id", None)
    if not org_id:
        logger.warning("detection_stats_no_org_id")
        return jsonify({"error": "no_org_id"}), 401

    p = sql_placeholder()
    conn = get_db() if is_postgres() else _sqlite_connect()
    cur = conn.cursor()
    try:
        cur.execute(f"""
            SELECT detection_layer, COUNT(*) as count
            FROM spans WHERE detection_layer IS NOT NULL AND org_id = {p}
            GROUP BY detection_layer ORDER BY count DESC
        """, (org_id,))
        layer_distribution = [{"layer": r[0], "count": r[1]} for r in cur.fetchall()]

        cur.execute(f"""
            SELECT detection_layer, COUNT(*) as total, SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked
            FROM spans WHERE detection_layer IS NOT NULL AND org_id = {p}
            GROUP BY detection_layer
        """, (org_id,))
        layer_accuracy = [
            {"layer": r[0], "total": r[1], "blocked": r[2],
             "block_rate": round((r[2] / r[1] * 100) if r[1] > 0 else 0, 2)}
            for r in cur.fetchall()
        ]

        cur.execute(f"""
            SELECT
                CASE
                    WHEN ml_score >= 0.9 THEN '0.9-1.0'
                    WHEN ml_score >= 0.8 THEN '0.8-0.9'
                    WHEN ml_score >= 0.7 THEN '0.7-0.8'
                    WHEN ml_score >= 0.6 THEN '0.6-0.7'
                    WHEN ml_score >= 0.5 THEN '0.5-0.6'
                    ELSE '0.0-0.5'
                END as score_range, COUNT(*) as count
            FROM spans WHERE ml_score IS NOT NULL AND org_id = {p}
            GROUP BY score_range ORDER BY score_range DESC
        """, (org_id,))
        ml_score_distribution = [{"range": r[0], "count": r[1]} for r in cur.fetchall()]

        cur.execute(f"""
            SELECT
                CASE
                    WHEN llm_score >= 0.9 THEN 'high_risk'
                    WHEN llm_score >= 0.7 THEN 'medium_risk'
                    ELSE 'low_risk'
                END as risk_category, COUNT(*) as count
            FROM spans WHERE llm_score IS NOT NULL AND org_id = {p}
            GROUP BY risk_category
        """, (org_id,))
        llm_score_distribution = [{"category": r[0], "count": r[1]} for r in cur.fetchall()]

    finally:
        conn.close()

    return jsonify({
        "layer_distribution": layer_distribution,
        "layer_accuracy": layer_accuracy,
        "ml_score_distribution": ml_score_distribution,
        "llm_score_distribution": llm_score_distribution,
        "total_analyzed": sum(l["count"] for l in layer_distribution) if layer_distribution else 0,
    })


@api_bp.route("/api/llm/stats")
def get_llm_stats():
    p = sql_placeholder()
    conn = get_db() if is_postgres() else _sqlite_connect()
    cur = conn.cursor()
    try:
        cur.execute(f"SELECT COUNT(*) FROM spans WHERE detection_layer = 'llm_judge' AND org_id = {p}", (g.org_id,))
        total_llm = cur.fetchone()[0] or 0

        cur.execute(f"""
            SELECT COUNT(*), SUM(CASE WHEN blocked THEN 1 ELSE 0 END)
            FROM spans WHERE detection_layer = 'llm_judge' AND org_id = {p}
        """, (g.org_id,))
        total, blocked = cur.fetchone()
        total = total or 0
        blocked = blocked or 0
        block_rate = round((blocked / total * 100), 2) if total else 0

        cur.execute(f"""
            SELECT llm_reason, COUNT(*) as count
            FROM spans WHERE llm_reason IS NOT NULL AND detection_layer = 'llm_judge' AND org_id = {p}
            GROUP BY llm_reason ORDER BY count DESC LIMIT 5
        """, (g.org_id,))
        top_reasons = [{"reason": r[0], "count": r[1]} for r in cur.fetchall()]

    finally:
        conn.close()

    return jsonify({
        "total_analyzed": total_llm,
        "block_rate": block_rate,
        "top_reasons": top_reasons,
        "status": "operational" if total_llm > 0 else "idle",
    })


@api_bp.route("/api/models")
def api_models():
    p = sql_placeholder()
    conn = get_db() if is_postgres() else _sqlite_connect()
    cur = conn.cursor()
    try:
        cur.execute(f"""
            SELECT model, COUNT(*) as requests, AVG(latency_ms) as avg_latency,
                   SUM(cost_usd) as total_cost,
                   SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked_count,
                   COALESCE(SUM(input_tokens), 0) as input_tokens,
                   COALESCE(SUM(output_tokens), 0) as output_tokens
            FROM spans WHERE org_id = {p} AND model IS NOT NULL AND model != ''
            GROUP BY model ORDER BY requests DESC
        """, (g.org_id,))
        models = []
        for r in cur.fetchall():
            row = {"model": r[0], "requests": r[1], "avg_latency": r[2],
                   "total_cost": r[3], "blocked_count": r[4],
                   "input_tokens": r[5], "output_tokens": r[6]}
            models.append({
                "name": row.get("model"),
                "requests": row.get("requests"),
                "avg_latency_ms": round(float(row.get("avg_latency") or 0), 1),
                "total_cost_usd": round(float(row.get("total_cost") or 0), 6),
                "blocked_count": row.get("blocked_count"),
                "input_tokens": int(row.get("input_tokens") or 0),
                "output_tokens": int(row.get("output_tokens") or 0),
            })
    finally:
        conn.close()
    return jsonify(models)