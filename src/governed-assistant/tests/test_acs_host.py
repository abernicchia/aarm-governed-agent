"""Unit tests for the ACS host seam (approval routing without OPA)."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

from agent_control_specification import (
    AgentControlBlocked,
    AgentControlSuspended,
    Decision,
    InterventionPoint,
)

from acs_host import AcsHost, HostContext


def _result(decision: Decision, *, approval: Any = None, reason: str = "") -> Any:
    return SimpleNamespace(
        verdict=SimpleNamespace(
            decision=decision,
            reason=reason,
            message="",
            transform=None,
            approval=approval,
        ),
        transformed_policy_target=None,
        transformed_policy_target_applied=False,
        input_identity="sha256:in",
        enforced_identity="sha256:in",
    )


class _FakeControl:
    def __init__(self, result: Any, enforce: Any = None) -> None:
        self.result = result
        self._enforce = enforce
        self.enforce_calls = 0

    async def evaluate_intervention_point(self, point: Any, snapshot: Any, mode: Any) -> Any:
        return self.result

    async def enforce(self, point: Any, result: Any, mode: Any, *, approval_resolver: Any) -> None:
        self.enforce_calls += 1
        if self._enforce is not None:
            await self._enforce(point, result)


def _resolver(*_: Any) -> Any:
    return None


def test_plain_allow_skips_approval() -> None:
    control = _FakeControl(_result(Decision.ALLOW))
    result = AcsHost(control, approval_resolver=_resolver).evaluate_intervention_point("input", {})
    assert result.verdict == "allow"
    assert result.approval is None
    assert control.enforce_calls == 0


def test_final_deny_is_not_routed_to_resolver() -> None:
    control = _FakeControl(_result(Decision.DENY, reason="tool_not_allowed"))
    result = AcsHost(control, approval_resolver=_resolver).evaluate_intervention_point("pre_tool_call", {})
    assert result.verdict == "deny"
    assert result.reason == "tool_not_allowed"
    assert control.enforce_calls == 0


def test_escalate_approved_becomes_allow() -> None:
    control = _FakeControl(_result(Decision.ESCALATE))
    result = AcsHost(control, approval_resolver=_resolver).evaluate_intervention_point("pre_tool_call", {})
    assert result.verdict == "allow"
    assert result.allowed
    assert result.approval == "approved"


def test_deny_with_approval_block_is_routed_to_resolver() -> None:
    control = _FakeControl(_result(Decision.DENY, approval={"approvers": ["human"]}))
    result = AcsHost(control, approval_resolver=_resolver).evaluate_intervention_point("pre_tool_call", {})
    assert control.enforce_calls == 1
    assert result.verdict == "allow"


def test_escalate_without_resolver_fails_closed() -> None:
    control = _FakeControl(_result(Decision.ESCALATE))
    result = AcsHost(control).evaluate_intervention_point("pre_tool_call", {})
    assert result.verdict == "deny"
    assert control.enforce_calls == 0


def test_escalate_blocked_by_resolver_is_deny() -> None:
    async def block(point: Any, result: Any) -> None:
        raise AgentControlBlocked(InterventionPoint.PRE_TOOL_CALL, _result(Decision.ESCALATE, reason="human"))

    control = _FakeControl(_result(Decision.ESCALATE), enforce=block)
    result = AcsHost(control, approval_resolver=_resolver).evaluate_intervention_point("pre_tool_call", {})
    assert result.verdict == "deny"
    assert result.approval == "denied"
    assert result.reason == "human"


def test_escalate_suspended_is_not_allowed() -> None:
    async def suspend(point: Any, result: Any) -> None:
        raise AgentControlSuspended(InterventionPoint.PRE_TOOL_CALL, result, handle="ticket-1")

    control = _FakeControl(_result(Decision.ESCALATE), enforce=suspend)
    result = AcsHost(control, approval_resolver=_resolver).evaluate_intervention_point("pre_tool_call", {})
    assert result.verdict == "escalate"
    assert not result.allowed


def test_approval_timeout_denies() -> None:
    async def hang(point: Any, result: Any) -> None:
        await asyncio.sleep(5)

    control = _FakeControl(_result(Decision.ESCALATE), enforce=hang)
    host = AcsHost(control, approval_resolver=_resolver, approval_timeout_seconds=0.05)
    result = host.evaluate_intervention_point("pre_tool_call", {})
    assert result.verdict == "deny"
    assert result.approval == "timeout"


def test_sync_evaluate_works_inside_running_loop() -> None:
    control = _FakeControl(_result(Decision.ALLOW))
    host = AcsHost(control)

    async def run() -> str:
        return host.evaluate_intervention_point("input", {}).verdict

    assert asyncio.run(run()) == "allow"


def test_builder_mirrors_host_budgets_into_envelope() -> None:
    host = AcsHost(_FakeControl(_result(Decision.ALLOW)))
    ctx = HostContext(agent_id="governed-assistant", session_id="sess-1", call_count=3)
    snapshot = host.builder_for(ctx).pre_tool_call(tool_name="calculator", args={}, call_id="c-1")
    assert snapshot["envelope"]["budgets"]["tool_call_count"] == 3
    assert snapshot["envelope"]["session"]["id"] == "sess-1"
    assert snapshot["tool_call"] == {"name": "calculator", "args": {}, "id": "c-1"}
