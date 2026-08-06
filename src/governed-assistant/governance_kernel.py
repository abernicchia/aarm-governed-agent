"""Governance-aware MAF kernel — injects session context into ACS snapshots."""

from __future__ import annotations

from typing import Any, Callable, Optional

from agent_os.integrations.base import ExecutionContext, GovernancePolicy
from agent_os.integrations.maf_adapter import MAFKernel

from governance_session import get_session_state, inject_governance_snapshot


def _host_human_approval_deny() -> Any:
    from agent_os.integrations._v5_runtime_bridge import BridgeResult

    from agent_os.policies.decision import PolicyCheckResult

    check = PolicyCheckResult(
        allowed=False,
        action="deny",
        reason="human_approval_required",
        matched_rule="require_human_approval",
    )
    evaluation = type("E", (), {
        "is_allowed": lambda self: False,
        "verdict": "deny",
        "reason": "human_approval_required",
        "audit_entry": {},
    })()
    return BridgeResult(evaluation=evaluation, check_result=check)


class GovernanceMAFKernel(MAFKernel):
    """MAFKernel that attaches session governance context to every snapshot."""

    def evaluate_input(self, ctx: ExecutionContext, input_data: Any) -> Any:
        body: Any
        if isinstance(input_data, (str, dict)):
            body = input_data
        elif hasattr(input_data, "content"):
            body = str(getattr(input_data, "content"))
        else:
            body = str(input_data)

        state = get_session_state(ctx.session_id)
        state.ingest_user_message(body if isinstance(body, str) else str(body))

        builder = self.bridge.builder_for(ctx)
        snapshot = builder.input(
            body=body if isinstance(body, (str, dict)) else str(body),
        )
        snapshot = inject_governance_snapshot(snapshot, ctx.session_id)
        result = self.bridge._evaluate("input", snapshot)

        if (
            result.verdict == "allow"
            and self.policy.require_human_approval
            and self._approval_resolver is None
        ):
            return _host_human_approval_deny()
        return result

    def evaluate_pre_tool_call(
        self,
        ctx: ExecutionContext,
        *,
        tool_name: str,
        args: dict[str, Any],
        call_id: str = "call-1",
    ) -> Any:
        builder = self.bridge.builder_for(ctx)
        snapshot = builder.pre_tool_call(
            tool_name=tool_name,
            args=dict(args),
            call_id=call_id,
        )
        snapshot = inject_governance_snapshot(snapshot, ctx.session_id)
        result = self.bridge._evaluate("pre_tool_call", snapshot)
        fallback = result.evaluation.audit_entry.get("v5_fallback")
        if result.verdict == "allow" and fallback == "unbound_intervention_point":
            from agent_os.integrations._v5_runtime_bridge import _host_budget_check

            host_check = _host_budget_check(self.policy, ctx)
            if host_check is not None:
                return host_check
        return result


def build_governance_kernel(
    policy: GovernancePolicy,
    *,
    approval_resolver: Optional[Callable[..., Any]] = None,
    _runtime: Optional[Any] = None,
    _runtime_factory: Optional[Callable[[GovernancePolicy], Any]] = None,
) -> GovernanceMAFKernel:
    return GovernanceMAFKernel(
        policy,
        approval_resolver=approval_resolver,
        _runtime=_runtime,
        _runtime_factory=_runtime_factory,
    )


def patch_middleware_kernel(middleware: Any) -> Any:
    kernel = getattr(middleware, "kernel", None)
    if kernel is None or isinstance(kernel, GovernanceMAFKernel):
        return middleware

    wrapper = GovernanceMAFKernel.__new__(GovernanceMAFKernel)
    wrapper.policy = kernel.policy
    wrapper._approval_resolver = getattr(kernel, "_approval_resolver", None)
    wrapper._bridge = kernel._bridge
    wrapper._start_time = getattr(kernel, "_start_time", 0.0)
    wrapper._last_error = getattr(kernel, "_last_error", None)
    middleware.kernel = wrapper
    return middleware
