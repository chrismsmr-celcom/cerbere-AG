"""Endpoints d'agrégation : Data flow (Sankey), Agent graph, Risk vs latency."""

import copy


def _post(client, headers, base, **over):
    body = copy.deepcopy(base)
    body.update(over)
    r = client.post("/span", json=body, headers=headers)
    assert r.status_code == 201, r.get_json()


def _seed(client, auth_headers, sample_span):
    _post(
        client,
        auth_headers,
        sample_span,
        span_id="s1",
        span_type="tool_call",
        latency_ms=800,
        input_data={"tool": "http_post", "params": {"url": "https://x.example"}},
        taint_level="SECRET",
        risk_score=85,
        blocked=True,
        block_reason="secret to external sink",
    )
    _post(
        client,
        auth_headers,
        sample_span,
        span_id="s2",
        span_type="tool_call",
        latency_ms=100,
        input_data={"tool": "read_file", "params": {"path": "a.txt"}},
        taint_level="CONFIDENTIAL",
        risk_score=20,
        blocked=False,
    )
    _post(
        client,
        auth_headers,
        sample_span,
        span_id="s3",
        span_type="tool_call",
        latency_ms=120,
        input_data={"tool": "read_file", "params": {"path": "b.txt"}},
        taint_level="CONFIDENTIAL",
        risk_score=30,
        blocked=False,
    )


def test_insights_require_auth(client):
    for path in ("flow", "graph", "tools"):
        assert client.get(f"/api/insights/{path}").status_code in (401, 302)


def test_empty_state_is_well_formed(client, auth_headers):
    flow = client.get("/api/insights/flow", headers=auth_headers).get_json()
    assert flow["links"] == [] and flow["total"] == 0
    graph = client.get("/api/insights/graph", headers=auth_headers).get_json()
    assert graph["nodes"] == [] and graph["edges"] == []
    tools = client.get("/api/insights/tools", headers=auth_headers).get_json()
    assert tools["tools"] == [] and tools["sampled"] is False


def test_flow_groups_taint_to_tool(client, auth_headers, sample_span):
    _seed(client, auth_headers, sample_span)
    flow = client.get("/api/insights/flow", headers=auth_headers).get_json()
    by = {(l["source"], l["target"]): l for l in flow["links"]}
    assert by[("SECRET", "http_post")]["blocked"] == 1
    assert by[("CONFIDENTIAL", "read_file")]["value"] == 2
    assert flow["sources"] == ["CONFIDENTIAL", "SECRET"]  # tri par gravité croissante
    assert flow["total"] == 3


def test_graph_has_agents_tools_and_data_nodes(client, auth_headers, sample_span):
    _seed(client, auth_headers, sample_span)
    g = client.get("/api/insights/graph", headers=auth_headers).get_json()
    kinds = {n["kind"] for n in g["nodes"]}
    assert kinds == {"agent", "tool", "data"}
    tool = next(n for n in g["nodes"] if n["id"] == "tool:read_file")
    assert tool["calls"] == 2  # pas de double comptage via les liens de données
    ids = {n["id"] for n in g["nodes"]}
    assert all(e["source"] in ids and e["target"] in ids for e in g["edges"])


def test_tools_scatter_metrics(client, auth_headers, sample_span):
    _seed(client, auth_headers, sample_span)
    data = client.get("/api/insights/tools", headers=auth_headers).get_json()
    by = {t["tool"]: t for t in data["tools"]}
    assert by["read_file"]["calls"] == 2
    assert by["read_file"]["avg_latency_ms"] == 110.0
    assert by["http_post"]["blocked"] == 1
    assert by["http_post"]["avg_risk"] >= 70  # un span bloqué est au moins « high »
    assert by["http_post"]["trace_id"]


def test_days_is_clamped(client, auth_headers):
    for v in ("0", "-5", "9999", "abc"):
        assert (
            client.get(f"/api/insights/flow?days={v}", headers=auth_headers).status_code
            == 200
        )


def test_insights_never_leak_other_orgs(client, auth_headers, sample_span):
    """Isolation tenant : des lignes d'une autre organisation ne doivent jamais apparaître."""
    from collector.api import _db_run

    _seed(client, auth_headers, sample_span)
    _db_run(
        """INSERT INTO events (id, trace_id, session_id, agent_id, org_id, sequence_no, actor, type,
                               tool_name, taint_level, risk_score, decision)
           VALUES ('evt-other', 't-other', 't-other', 'other-agent', 'other-org', 1, 'TOOL', 'tool_call',
                   'leak_tool', 'SECRET', 99, 'BLOCK')""",
        commit=True,
    )
    _db_run(
        """INSERT INTO spans (trace_id, span_id, span_type, timestamp, latency_ms, input_data,
                              security_checks, blocked, org_id, created_at)
           VALUES ('t-other', 'sp-other', 'tool_call', 1700000000, 5, '{"tool": "leak_tool"}',
                   '[]', 1, 'other-org', CURRENT_TIMESTAMP)""",
        commit=True,
    )
    for path in ("flow", "graph", "tools"):
        body = client.get(f"/api/insights/{path}", headers=auth_headers).get_data(
            as_text=True
        )
        assert "leak_tool" not in body and "other-agent" not in body, path
