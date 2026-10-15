"""Insights : agrégations pour Data flow (Sankey), Agent graph et Risk vs latency.

  GET /api/insights/flow   : niveau de taint -> tool (volume, bloqués)        [table events]
  GET /api/insights/graph  : agents, tools et données sensibles + liens        [table events]
  GET /api/insights/tools  : latence / risque / volume par tool ou modèle      [table spans]

Toutes les requêtes sont filtrées par org_id (isolation tenant). Les agrégats du
scatter sont calculés en Python sur les 20 000 derniers spans de la période
(`sampled: true` si la limite est atteinte) ; à passer en SQL si le volume l'exige.
"""

from datetime import datetime, timedelta, timezone

from flask import g, jsonify, request

from collector.api.helpers import _as_json, _db_run, api_bp
from collector.auth import require_auth

_RISK_SCORE = {"low": 5, "medium": 35, "high": 70, "critical": 95}
_MAX_SPANS = 20000
_TAINT_ORDER = [
    "PUBLIC",
    "INTERNAL",
    "UNTRUSTED",
    "CONFIDENTIAL",
    "SECRET",
    "MALICIOUS",
]


def _days():
    d = request.args.get("days", default=14, type=int)
    return max(1, min(d, 90))


def _cutoff(days):
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    return (now - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


@api_bp.route("/api/insights/flow")
def api_insights_flow():
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401
    days = _days()
    try:
        rows, _ = _db_run(
            """SELECT taint_level, tool_name, COUNT(*),
                      SUM(CASE WHEN decision = 'BLOCK' THEN 1 ELSE 0 END)
               FROM events
               WHERE org_id = ? AND taint_level IS NOT NULL AND tool_name IS NOT NULL
                 AND "timestamp" > ?
               GROUP BY taint_level, tool_name
               ORDER BY COUNT(*) DESC LIMIT 200""",
            (g.org_id, _cutoff(days)),
            fetch="all",
        )
    except Exception as exc:
        return jsonify({"error": f"Database error: {exc}"}), 500
    links = [
        {
            "source": r[0],
            "target": r[1],
            "value": int(r[2] or 0),
            "blocked": int(r[3] or 0),
        }
        for r in rows
    ]
    sources = sorted(
        {l["source"] for l in links},
        key=lambda s: _TAINT_ORDER.index(s) if s in _TAINT_ORDER else 99,
    )
    return jsonify(
        {
            "days": days,
            "links": links,
            "sources": sources,
            "targets": sorted({l["target"] for l in links}),
            "total": sum(l["value"] for l in links),
        }
    )


@api_bp.route("/api/insights/graph")
def api_insights_graph():
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401
    days = _days()
    cutoff = _cutoff(days)
    try:
        agent_rows, _ = _db_run(
            """SELECT agent_id, tool_name, COUNT(*),
                      SUM(CASE WHEN decision = 'BLOCK' THEN 1 ELSE 0 END), AVG(risk_score)
               FROM events
               WHERE org_id = ? AND tool_name IS NOT NULL AND "timestamp" > ?
               GROUP BY agent_id, tool_name
               ORDER BY COUNT(*) DESC LIMIT 500""",
            (g.org_id, cutoff),
            fetch="all",
        )
        data_rows, _ = _db_run(
            """SELECT taint_level, tool_name, COUNT(*),
                      SUM(CASE WHEN decision = 'BLOCK' THEN 1 ELSE 0 END), AVG(risk_score)
               FROM events
               WHERE org_id = ? AND taint_level IS NOT NULL AND tool_name IS NOT NULL
                 AND "timestamp" > ?
               GROUP BY taint_level, tool_name
               ORDER BY COUNT(*) DESC LIMIT 500""",
            (g.org_id, cutoff),
            fetch="all",
        )
    except Exception as exc:
        return jsonify({"error": f"Database error: {exc}"}), 500

    nodes = {}
    edges = []

    def bump(node_id, kind, label, calls, blocked, risk):
        n = nodes.setdefault(
            node_id,
            {
                "id": node_id,
                "kind": kind,
                "label": label,
                "calls": 0,
                "blocked": 0,
                "_risk": 0.0,
                "_rn": 0,
            },
        )
        n["calls"] += calls
        n["blocked"] += blocked
        if risk is not None:
            n["_risk"] += risk * calls
            n["_rn"] += calls

    for agent, tool, calls, blocked, risk in agent_rows:
        calls, blocked, risk = int(calls or 0), int(blocked or 0), _num(risk)
        a, t = f"agent:{agent}", f"tool:{tool}"
        bump(a, "agent", str(agent), calls, blocked, risk)
        bump(t, "tool", str(tool), calls, blocked, risk)
        edges.append(
            {
                "source": a,
                "target": t,
                "calls": calls,
                "blocked": blocked,
                "risk": round(risk, 1) if risk is not None else None,
            }
        )
    for level, tool, calls, blocked, risk in data_rows:
        calls, blocked, risk = int(calls or 0), int(blocked or 0), _num(risk)
        d, t = f"data:{level}", f"tool:{tool}"
        bump(d, "data", str(level), calls, blocked, risk)
        bump(
            t, "tool", str(tool), 0, 0, None
        )  # le tool existe déjà via les agents ; pas de double comptage
        edges.append(
            {
                "source": d,
                "target": t,
                "calls": calls,
                "blocked": blocked,
                "risk": round(risk, 1) if risk is not None else None,
            }
        )

    out = []
    for n in nodes.values():
        rn = n.pop("_rn")
        total = n.pop("_risk")
        n["risk"] = round(total / rn, 1) if rn else None
        out.append(n)
    return jsonify({"days": days, "nodes": out, "edges": edges})


def _span_risk(blocked, checks, ml, llm):
    level = 0
    for c in checks:
        if isinstance(c, dict) and not c.get("passed", True):
            level = max(
                level, _RISK_SCORE.get(str(c.get("risk_level") or "medium").lower(), 35)
            )
    if blocked:
        level = max(level, 70)
    for sc in (ml, llm):
        v = _num(sc)
        if v is not None:
            level = max(level, min(100.0, v * 100 if v <= 1 else v))
    return float(level)


def _p95(values):
    if not values:
        return 0.0
    s = sorted(values)
    return s[min(len(s) - 1, round(0.95 * (len(s) - 1)))]


@api_bp.route("/api/insights/tools")
def api_insights_tools():
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401
    days = _days()
    try:
        rows, _ = _db_run(
            f"""SELECT span_type, latency_ms, blocked, input_data, security_checks,
                       ml_score, llm_score, trace_id, model
                FROM spans WHERE org_id = ? AND created_at > ?
                ORDER BY created_at DESC LIMIT {_MAX_SPANS}""",
            (g.org_id, _cutoff(days)),
            fetch="all",
        )
    except Exception as exc:
        return jsonify({"error": f"Database error: {exc}"}), 500

    agg = {}
    for (
        span_type,
        latency,
        blocked,
        inp_raw,
        checks_raw,
        ml,
        llm,
        trace_id,
        model,
    ) in rows:
        inp = _as_json(inp_raw, {})
        inp = inp if isinstance(inp, dict) else {}
        tool = inp.get("tool") or inp.get("tool_name")
        label = str(tool or model or span_type or "unknown")
        kind = "tool" if tool else ("llm" if model else "other")
        risk = _span_risk(bool(blocked), _as_json(checks_raw, []), ml, llm)
        a = agg.setdefault(
            (kind, label), {"lat": [], "risk": [], "blocked": 0, "worst": (-1.0, None)}
        )
        lat = _num(latency)
        if lat is not None:
            a["lat"].append(lat)
        a["risk"].append(risk)
        a["blocked"] += 1 if blocked else 0
        if risk > a["worst"][0]:
            a["worst"] = (risk, trace_id)

    tools = []
    for (kind, label), a in agg.items():
        calls = len(a["risk"])
        tools.append(
            {
                "tool": label,
                "kind": kind,
                "calls": calls,
                "avg_latency_ms": round(sum(a["lat"]) / len(a["lat"]), 1)
                if a["lat"]
                else 0.0,
                "p95_latency_ms": round(_p95(a["lat"]), 1),
                "avg_risk": round(sum(a["risk"]) / calls, 1),
                "max_risk": round(max(a["risk"]), 1),
                "blocked": a["blocked"],
                "trace_id": a["worst"][1],
            }
        )
    tools.sort(key=lambda t: -t["calls"])
    return jsonify(
        {"days": days, "tools": tools[:100], "sampled": len(rows) >= _MAX_SPANS}
    )
