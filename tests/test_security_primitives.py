"""Focused regression tests for the security primitives used by Cerbere AG.

These tests validate primitive behavior in isolation. They do not replace
self-hosted integration tests for persistence, API enforcement, or dashboard UX.
"""

import pytest

from agentguard.attestation import (
    build_attestation,
    sign_attestation,
    verify_attestation,
)
from agentguard.delegation import DelegationRegistry
from agentguard.egress import evaluate_egress, normalize_destination
from agentguard.tool_contracts import (
    DataClass,
    DataOrigin,
    ToolContract,
    ToolContractRegistry,
)


def test_delegation_is_scoped_to_tenant_parent_child_and_scope():
    registry = DelegationRegistry()
    registry.grant(
        "del-1",
        "tenant-a",
        "parent",
        "child",
        {"crm.read", "files.*"},
        ttl_seconds=60,
    )

    assert registry.authorize(
        "del-1",
        tenant_id="tenant-a",
        parent_agent_id="parent",
        child_agent_id="child",
        scope="crm.read",
    )
    assert registry.authorize(
        "del-1",
        tenant_id="tenant-a",
        parent_agent_id="parent",
        child_agent_id="child",
        scope="files.write",
    )
    assert not registry.authorize(
        "del-1",
        tenant_id="tenant-b",
        parent_agent_id="parent",
        child_agent_id="child",
        scope="crm.read",
    )
    assert not registry.authorize(
        "del-1",
        tenant_id="tenant-a",
        parent_agent_id="other",
        child_agent_id="child",
        scope="crm.read",
    )
    assert not registry.authorize(
        "del-1",
        tenant_id="tenant-a",
        parent_agent_id="parent",
        child_agent_id="child",
        scope="crm.delete",
    )


def test_delegation_expiry_and_revocation_are_enforced():
    registry = DelegationRegistry()
    item = registry.grant(
        "del-2",
        "tenant-a",
        "parent",
        "child",
        {"tool.call"},
        ttl_seconds=10,
    )
    kwargs = {
        "tenant_id": "tenant-a",
        "parent_agent_id": "parent",
        "child_agent_id": "child",
        "scope": "tool.call",
    }
    assert registry.authorize("del-2", **kwargs, now=item.created_at + 1)
    assert not registry.authorize("del-2", **kwargs, now=item.expires_at + 1)
    assert registry.revoke("del-2")
    assert not registry.revoke("del-2")
    assert not registry.authorize("del-2", **kwargs)


@pytest.mark.parametrize(
    "args",
    [
        ("", "tenant", "parent", "child", {"x"}, 10),
        ("id", "", "parent", "child", {"x"}, 10),
        ("id", "tenant", "same", "same", {"x"}, 10),
        ("id", "tenant", "parent", "child", set(), 10),
        ("id", "tenant", "parent", "child", {"x"}, 0),
    ],
)
def test_delegation_rejects_invalid_grants(args):
    registry = DelegationRegistry()
    with pytest.raises(ValueError):
        registry.grant(*args)


def test_egress_defaults_to_deny_without_allowlist():
    decision = evaluate_egress("https://api.example.com/path")
    assert not decision.allowed
    assert decision.normalized_host == "api.example.com"


def test_egress_allowlist_and_denylist_precedence():
    allowed = evaluate_egress(
        "https://api.example.com/v1",
        allowlist=("*.example.com",),
    )
    denied = evaluate_egress(
        "https://blocked.example.com",
        allowlist=("*.example.com",),
        denylist=("blocked.example.com",),
    )
    assert allowed.allowed
    assert not denied.allowed
    assert denied.reason == "Destination matches denylist"


@pytest.mark.parametrize(
    "destination",
    [
        "http://localhost:8080",
        "http://127.0.0.1",
        "http://10.0.0.2",
        "http://169.254.1.1",
        "http://service.internal",
        "http://db.local",
        "http://user:pass@example.com",
        "singlelabel",
    ],
)
def test_egress_rejects_local_private_or_ambiguous_destinations(destination):
    with pytest.raises(ValueError):
        normalize_destination(destination)


def test_contract_registry_fails_closed_for_unknown_tools():
    registry = ToolContractRegistry(strict=True)
    result = registry.authorize(
        "unknown.tool",
        [],
        tenant_id="tenant-a",
        org_id="org-a",
    )
    assert not result.allowed


def test_contract_requires_provenance_and_rejects_cross_tenant_data():
    registry = ToolContractRegistry(strict=True)
    registry.register(ToolContract(tool_pattern="crm.*"))
    missing = registry.authorize(
        "crm.lookup",
        [],
        tenant_id="tenant-a",
        org_id="org-a",
    )
    foreign = registry.authorize(
        "crm.lookup",
        [DataOrigin("d1", "agent", "db", DataClass.INTERNAL, "tenant-b", "org-a")],
        tenant_id="tenant-a",
        org_id="org-a",
    )
    assert not missing.allowed
    assert not foreign.allowed


def test_contract_rejects_secret_and_malicious_data():
    registry = ToolContractRegistry()
    registry.register(ToolContract(tool_pattern="external.*"))
    for classification in (DataClass.SECRET, DataClass.MALICIOUS):
        origin = DataOrigin(
            "d1",
            "agent",
            "vault",
            classification,
            "tenant-a",
            "org-a",
        )
        result = registry.authorize(
            "external.send",
            [origin],
            tenant_id="tenant-a",
            org_id="org-a",
        )
        assert not result.allowed


def test_contract_returns_approval_requirement_for_confidential_data():
    registry = ToolContractRegistry()
    registry.register(
        ToolContract(
            tool_pattern="external.*",
            accepts=(DataClass.PUBLIC, DataClass.INTERNAL),
        )
    )
    origin = DataOrigin(
        "d1",
        "agent",
        "crm",
        DataClass.CONFIDENTIAL,
        "tenant-a",
        "org-a",
    )
    result = registry.authorize(
        "external.send",
        [origin],
        tenant_id="tenant-a",
        org_id="org-a",
    )
    assert not result.allowed
    assert result.requires_approval


def test_contract_checks_destination_allowlist():
    registry = ToolContractRegistry()
    registry.register(
        ToolContract(
            tool_pattern="http.post",
            allowed_destinations=("api.example.com",),
        )
    )
    origin = DataOrigin(
        "d1",
        "agent",
        "crm",
        DataClass.INTERNAL,
        "tenant-a",
        "org-a",
    )
    assert registry.authorize(
        "http.post",
        [origin],
        tenant_id="tenant-a",
        org_id="org-a",
        destination="api.example.com",
    ).allowed
    assert not registry.authorize(
        "http.post",
        [origin],
        tenant_id="tenant-a",
        org_id="org-a",
        destination="evil.example",
    ).allowed


def test_attestation_detects_payload_tampering():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    bundle = build_attestation(
        [{"event_id": "evt-1", "decision": "block"}],
        subject="tenant-a",
        created_at=1_700_000_000,
    )
    signed = sign_attestation(bundle, private_bytes)
    assert verify_attestation(signed, public_bytes)

    tampered = {**signed, "payload": {**signed["payload"], "subject": "tenant-b"}}
    assert not verify_attestation(tampered, public_bytes)
