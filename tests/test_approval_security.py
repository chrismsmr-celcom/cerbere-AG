"""
Regression tests for the human-approval chain (audit findings).

Covered:
1. A session created with an API key can NOT take human decisions
   (self-approval via /api/auth-login must be impossible).
2. An approval is single-use (replay is refused).
3. An approval cannot be used by another organization, nor without an org.
4. An approval does not disable the other controls: tool registration,
   identity and arguments are re-checked on every retry, and a retry blocked
   by those checks does not burn the approval.
5. An approval expires after its use window.

The approval tests run against an in-memory SQLite database injected into
collector.approvals, so they do not depend on the local environment.
"""

import sqlite3

import pytest
from flask import Flask
from itsdangerous import URLSafeTimedSerializer

from agentguard.tool_guard import ToolGuard, ToolPolicy, ToolRequest

ORG_A = "org-a"
ORG_B = "org-b"


# ==============================================================
# Fixtures
# ==============================================================


@pytest.fixture
def approvals(monkeypatch):
    """collector.approvals wired to a throw-away in-memory SQLite DB."""
    from collector import approvals as approvals_module

    conn = sqlite3.connect(":memory:", check_same_thread=False)
    monkeypatch.setattr(approvals_module, "get_db", lambda: conn)
    monkeypatch.setattr(approvals_module, "is_postgres", lambda: False)
    monkeypatch.setattr(approvals_module, "sql_placeholder", lambda: "?")
    yield approvals_module
    conn.close()


def _guard():
    return ToolGuard(
        policies=[
            ToolPolicy(
                name="send_email",
                category="external",
                read_only=False,
                external_side_effect=True,
                require_approval=True,
            )
        ]
    )


def _request(org_id=ORG_A, arguments=None, approval_id=None, **overrides):
    metadata = {"approval_id": approval_id} if approval_id else {}
    params = {
        "tool_name": "send_email",
        "identity": "agent-1",
        "agent_id": "agent-1",
        "session_id": "sess-1",
        "org_id": org_id,
        "arguments": arguments
        if arguments is not None
        else {"to": "cfo@corp.io", "subject": "Q3"},
        "metadata": metadata,
    }
    params.update(overrides)
    return ToolRequest(**params)


def _ask_and_approve(guard, approvals, org_id=ORG_A):
    """Agent asks, a human approves. Returns the approval id."""
    decision = guard.authorize(_request(org_id=org_id))
    assert decision.decision == "require_approval", decision
    approval_id = decision.metadata["approval_id"]
    approvals.approve_approval(approval_id, decided_by="human@corp.io", org_id=org_id)
    return approval_id


# ==============================================================
# 1. Self-approval through an API-key session
# ==============================================================


def test_api_key_session_cannot_take_human_decisions(monkeypatch):
    import collector.auth as auth_pkg
    from collector.auth.config import MAGIC_LINK_COOKIE
    from collector.auth.middleware import require_human_auth
    from collector.auth.sessions import _session_org_id
    from collector.auth.utils import hash_key

    app = Flask(__name__)
    app.config["API_KEY"] = "test-key"
    app.auth_serializer = URLSafeTimedSerializer("test-secret")
    app.auth_session_ttl = 3600

    # The cookie an agent gets from POST /api/auth-login {"api_key": ...}
    token = app.auth_serializer.dumps(
        {"type": "api_key", "org_id": "default", "key_hash": hash_key("test-key")}
    )

    # It is not a human session.
    monkeypatch.setattr(
        auth_pkg, "_resolve_human_session", lambda value: None, raising=False
    )

    with app.test_request_context(
        "/api/approvals/apr_x/approve",
        method="POST",
        headers={"Cookie": f"{MAGIC_LINK_COOKIE}={token}"},
    ):
        # Sanity check: the legacy session itself is valid...
        assert _session_org_id(token) == "default"
        # ...but it must not be accepted for a human decision.
        assert require_human_auth() is False


# ==============================================================
# 2. Single use / replay
# ==============================================================


def test_approved_action_is_allowed_exactly_once(approvals):
    guard = _guard()
    approval_id = _ask_and_approve(guard, approvals)

    first = guard.authorize(_request(approval_id=approval_id))
    assert first.allowed, first
    assert first.metadata["reason_code"] == "human_approval"

    replay = guard.authorize(_request(approval_id=approval_id))
    assert not replay.allowed
    assert replay.metadata["reason_code"] == "approval_already_used"


def test_consume_is_atomic_and_single_use(approvals):
    created = approvals.create_approval(
        tool_name="send_email",
        arguments={"a": 1},
        org_id=ORG_A,
        agent_id="agent-1",
    )
    approval_id = created["approval_id"]

    # Not approved yet: cannot be consumed.
    assert approvals.consume_approval(approval_id, org_id=ORG_A) is False

    approvals.approve_approval(approval_id, decided_by="human", org_id=ORG_A)
    assert approvals.consume_approval(approval_id, org_id=ORG_A) is True
    assert approvals.consume_approval(approval_id, org_id=ORG_A) is False


def test_approval_expires_after_use_window(approvals, monkeypatch):
    created = approvals.create_approval(
        tool_name="send_email", arguments={}, org_id=ORG_A, agent_id="agent-1"
    )
    approval_id = created["approval_id"]
    approvals.approve_approval(approval_id, decided_by="human", org_id=ORG_A)

    monkeypatch.setattr(approvals, "APPROVED_USE_TTL_SECONDS", -1)
    assert approvals.consume_approval(approval_id, org_id=ORG_A) is False


# ==============================================================
# 3. Organization isolation
# ==============================================================


def test_other_organization_cannot_use_an_approval(approvals):
    guard = _guard()
    approval_id = _ask_and_approve(guard, approvals, org_id=ORG_A)

    stolen = guard.authorize(_request(org_id=ORG_B, approval_id=approval_id))
    assert not stolen.allowed
    assert stolen.metadata["reason_code"] == "approval_not_found"

    # The legitimate owner can still use it.
    assert guard.authorize(_request(approval_id=approval_id)).allowed


def test_approval_without_organization_is_refused(approvals):
    guard = _guard()
    approval_id = _ask_and_approve(guard, approvals)

    decision = guard.authorize(_request(org_id="", approval_id=approval_id))
    assert not decision.allowed
    assert decision.metadata["reason_code"] == "approval_org_required"


def test_consume_requires_matching_organization(approvals):
    created = approvals.create_approval(
        tool_name="send_email", arguments={}, org_id=ORG_A, agent_id="agent-1"
    )
    approval_id = created["approval_id"]
    approvals.approve_approval(approval_id, decided_by="human", org_id=ORG_A)

    assert approvals.consume_approval(approval_id, org_id=ORG_B) is False
    assert approvals.consume_approval(approval_id, org_id="") is False
    assert approvals.consume_approval(approval_id, org_id=ORG_A) is True


# ==============================================================
# 4. Approval never disables the other controls
# ==============================================================


def test_changed_arguments_are_refused(approvals):
    guard = _guard()
    approval_id = _ask_and_approve(guard, approvals)

    decision = guard.authorize(
        _request(
            approval_id=approval_id,
            arguments={"to": "attacker@evil.io", "subject": "Q3"},
        )
    )
    assert not decision.allowed
    assert decision.metadata["reason_code"] == "approval_mismatch"


def test_other_agent_or_session_cannot_reuse_the_approval(approvals):
    guard = _guard()
    approval_id = _ask_and_approve(guard, approvals)

    other_agent = guard.authorize(
        _request(approval_id=approval_id, agent_id="agent-2", identity="agent-2")
    )
    assert not other_agent.allowed
    assert other_agent.metadata["reason_code"] == "approval_mismatch"

    other_session = guard.authorize(
        _request(approval_id=approval_id, session_id="sess-2")
    )
    assert not other_session.allowed
    assert other_session.metadata["reason_code"] == "approval_mismatch"


def test_unregistered_tool_is_blocked_even_with_an_approval(approvals):
    guard = _guard()
    approval_id = _ask_and_approve(guard, approvals)

    del guard.policies["send_email"]

    decision = guard.authorize(_request(approval_id=approval_id))
    assert not decision.allowed
    assert decision.metadata["reason_code"] == "tool"


def test_revoked_identity_is_blocked_and_does_not_burn_the_approval(approvals):
    guard = _guard()
    guard.policies["send_email"].allowed_identities = {"agent-1"}
    approval_id = _ask_and_approve(guard, approvals)

    # Identity revoked after the human approved.
    guard.policies["send_email"].allowed_identities = {"someone-else"}
    blocked = guard.authorize(_request(approval_id=approval_id))
    assert not blocked.allowed
    assert blocked.metadata["reason_code"] == "identity"

    # The blocked retry did not spend the approval: once the identity is
    # valid again, the approved action goes through (once).
    guard.policies["send_email"].allowed_identities = {"agent-1"}
    assert guard.authorize(_request(approval_id=approval_id)).allowed
