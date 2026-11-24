from agentguard.integrations import (
    get_integration,
    list_integrations,
)


def test_registry_reports_native_coding_agent_coverage():
    integrations = {
        item["id"]: item for item in list_integrations(kind="coding_agent")
    }

    assert integrations["claude-code"]["status"] == "experimental"
    assert integrations["claude-code"]["enforcement"] == ("tool.pre",)
    assert integrations["cursor"]["status"] == "experimental"
    assert "shell.pre" in integrations["cursor"]["enforcement"]
    assert integrations["codex"]["status"] == "planned"


def test_registry_reports_mcp_gateway_separately():
    gateway = get_integration("mcp-gateway")

    assert gateway is not None
    assert gateway.status == "available"
    assert "mcp.tool.pre" in gateway.enforcement
    assert "mcp.tool.result" in gateway.events


def test_registry_returns_none_for_unknown_integration():
    assert get_integration("unknown-agent") is None
