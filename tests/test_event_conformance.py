import pytest

from agentguard.event_contract import assert_decision_conformance


class Decision:
    def __init__(self, action, reason, rules):
        self.action = action
        self.reason = reason
        self.matched_rules = rules


def test_cross_surface_conformance_accepts_identical_decisions():
    result = assert_decision_conformance(
        [
            Decision("ALLOW", "same policy", ["rule-a"]),
            Decision("ALLOW", "same policy", ["rule-a"]),
        ]
    )
    assert result == ("allow", "same policy", ("rule-a",))


def test_cross_surface_conformance_rejects_divergent_decisions():
    with pytest.raises(AssertionError):
        assert_decision_conformance(
            [
                Decision("ALLOW", "policy", ["rule-a"]),
                Decision("BLOCK", "policy", ["rule-a"]),
            ]
        )
