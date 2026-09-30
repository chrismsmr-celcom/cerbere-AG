"""Trajectory Timeline + Policy Decision Center (drill-down par event)."""

from flask import jsonify, g

from collector.db import get_db, dict_from_row, is_postgres, _get_db_path, sql_placeholder
from collector.api.helpers import api_bp, _serialize_event, _sqlite_connect


@api_bp.route("/api/trajectory/<session_id>")
def get_trajectory(session_id):
    """Timeline ordonnée d'une session — alimente le widget Trajectory Timeline."""
    cols = """id, trace_id, session_id, agent_id, "timestamp", sequence_no,
              actor, type, tool_name, decision, reason, risk_score, risk_contributors,
              taint_level, prev_event_id, next_event_id"""
    if is_postgres():
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            f"SELECT {cols} FROM events WHERE session_id = %s AND org_id = %s ORDER BY sequence_no",
            (session_id, g.org_id),
        )
        rows = [dict_from_row(r, cur) for r in cur.fetchall()]
        conn.close()
        sess_cur_sql = ("SELECT status, risk_level, current_task, model, environment, agent_id "
                        "FROM agent_sessions WHERE id = %s AND org_id = %s")
        conn = get_db()
        cur = conn.cursor()
        cur.execute(sess_cur_sql, (session_id, g.org_id))
        session_row = dict_from_row(cur.fetchone(), cur)
        conn.close()
    else:
        conn = _sqlite_connect()
        try:
            cur = conn.cursor()
            cur.execute(
                f"SELECT {cols} FROM events WHERE session_id = ? AND org_id = ? ORDER BY sequence_no",
                (session_id, g.org_id),
            )
            rows = [dict_from_row(r, cur) for r in cur.fetchall()]
        finally:
            conn.close()
        sess_cur_sql = ("SELECT status, risk_level, current_task, model, environment, agent_id "
                        "FROM agent_sessions WHERE id = ? AND org_id = ?")
        conn = _sqlite_connect()
        try:
            cur = conn.cursor()
            cur.execute(sess_cur_sql, (session_id, g.org_id))
            session_row = dict_from_row(cur.fetchone(), cur)
        finally:
            conn.close()

    if not rows:
        return jsonify({"error": "Session not found or empty"}), 404

    rows = [_serialize_event(r, full=False) for r in rows]
    return jsonify({"session_id": session_id, "session": session_row, "events": rows})


@api_bp.route("/api/events/<event_id>")
def get_event(event_id):
    """Détail complet d'un event — panneau expand de la timeline."""
    if is_postgres():
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM events WHERE id = %s AND org_id = %s", (event_id, g.org_id))
        row = dict_from_row(cur.fetchone(), cur)
        conn.close()
    else:
        conn = _sqlite_connect()
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM events WHERE id = ? AND org_id = ?", (event_id, g.org_id))
            row = dict_from_row(cur.fetchone(), cur)
        finally:
            conn.close()

    if not row:
        return jsonify({"error": "Event not found"}), 404

    return jsonify(_serialize_event(row, full=True))