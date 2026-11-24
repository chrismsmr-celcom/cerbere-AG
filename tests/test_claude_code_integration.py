from agentguard.integrations import claude_code


class FakeVerifier:
    def __init__(self, valid=True):
        self.valid = valid
        self.calls = []

    def verify_for(self, signed, *, tool_name, params, nonce):
        self.calls.append((tool_name, params, nonce))
        return self.valid


class FakeResponse:
    def __init__(self, body):
        self.body = body

    def raise_for_status(self):
        return None

    def json(self):
        return self.body


def test_pre_tool_use_allows_only_verified_allow(monkeypatch):
    verifier = FakeVerifier()
    monkeypatch.setenv("AGENTGUARD_AGENT_ID", "claude-agent")
    monkeypatch.setattr(
        claude_code,
        "_decision_client",
        lambda: ("https://collector.test", {}, ("claude-agent", verifier)),
    )
    monkeypatch.setattr(
        claude_code.requests,
        "post",
        lambda *args, **kwargs: FakeResponse(
            {"action": "ALLOW", "agent_id": "claude-agent", "reason": "policy"}
        ),
    )

    allowed, reason = claude_code.evaluate_pre_tool_use(
        {"tool_name": "Bash", "tool_input": {"command": "pwd"}}
    )

    assert allowed is True
    assert reason == "policy"
    assert verifier.calls[0][0] == "Bash"
    assert verifier.calls[0][1] == {"command": "pwd"}
    assert verifier.calls[0][2]


def test_pre_tool_use_denies_non_allow_decision(monkeypatch):
    verifier = FakeVerifier()
    monkeypatch.setattr(
        claude_code,
        "_decision_client",
        lambda: ("https://collector.test", {}, ("claude-agent", verifier)),
    )
    monkeypatch.setattr(
        claude_code.requests,
        "post",
        lambda *args, **kwargs: FakeResponse(
            {"action": "BLOCK", "agent_id": "claude-agent", "reason": "not allowed"}
        ),
    )

    allowed, reason = claude_code.evaluate_pre_tool_use(
        {"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}}
    )

    assert allowed is False
    assert reason == "not allowed"


def test_pre_tool_use_denies_invalid_signature(monkeypatch):
    verifier = FakeVerifier(valid=False)
    monkeypatch.setattr(
        claude_code,
        "_decision_client",
        lambda: ("https://collector.test", {}, ("claude-agent", verifier)),
    )
    monkeypatch.setattr(
        claude_code.requests,
        "post",
        lambda *args, **kwargs: FakeResponse(
            {"action": "ALLOW", "agent_id": "claude-agent"}
        ),
    )

    allowed, reason = claude_code.evaluate_pre_tool_use(
        {"tool_name": "Read", "tool_input": {"file_path": "README.md"}}
    )

    assert allowed is False
    assert "verify" in reason.lower()


def test_pre_tool_use_rejects_malformed_payload():
    allowed, reason = claude_code.evaluate_pre_tool_use(
        {"tool_name": "Bash", "tool_input": "not-an-object"}
    )
    assert allowed is False
    assert "Malformed" in reason
