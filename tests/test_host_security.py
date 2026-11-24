from agentguard.egress import evaluate_egress
from agentguard.event_contract import AgentEvent, EventKind
from agentguard.host_security import HostSecurityPolicy
from agentguard.integrations.registry import list_integrations


def test_registry_distinguishes_business_workflow_and_framework_coverage():
    items = {item["id"]: item for item in list_integrations()}
    assert items["business-agent"]["status"] == "planned"
    assert items["workflow-agent"]["status"] == "planned"
    assert items["langchain"]["status"] == "planned"


def test_event_timestamp_is_generated():
    event = AgentEvent(
        kind=EventKind.TOOL_PRE,
        tenant_id="t",
        org_id="o",
        agent_id="a",
        integration_id="sdk",
        surface="python",
    )
    assert event.timestamp > 0


def test_egress_blocks_private_ip_and_local_names_even_with_wildcard():
    assert not evaluate_egress("http://10.0.0.1", ("*",)).allowed
    assert not evaluate_egress("http://localhost", ("*",)).allowed
    assert not evaluate_egress("http://db.internal", ("*",)).allowed


def test_host_policy_blocks_dangerous_commands_and_requires_artifact_hash(tmp_path):
    policy = HostSecurityPolicy(allowed_executables=("/usr/bin/python",))
    assert not policy.evaluate_command("rm -rf /").allowed
    assert not policy.evaluate_command("/bin/sh run.sh").allowed
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"package")
    assert not policy.evaluate_artifact(str(artifact)).allowed
