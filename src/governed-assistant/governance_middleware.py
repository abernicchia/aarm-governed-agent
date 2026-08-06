"""Project middleware wrappers that bind Foundry session context to audit entries."""

from __future__ import annotations

import time
from typing import Any, Awaitable, Callable

from agent_framework import MiddlewareTermination
from agent_os.integrations.maf_adapter import AuditTrailMiddleware, CapabilityGuardMiddleware

from governance_audit import (
    enrich_audit_data,
    resolve_session_id,
    reset_governance_audit_context,
    set_governance_audit_context,
)
from governance_session import get_session_state, parse_delegated_from


class GovernedAuditTrailMiddleware(AuditTrailMiddleware):
    """AuditTrailMiddleware that binds session_id for all nested audit entries."""

    async def process(
        self,
        context: Any,
        call_next: Callable[[], Awaitable[None]],
    ) -> None:
        agent_name = getattr(context.agent, "name", "unknown")
        agent_did = self.agent_did or agent_name
        session_id = resolve_session_id(context)
        token = set_governance_audit_context(
            session_id=session_id,
            agent_did=agent_did,
            agent_name=agent_name,
        )
        metadata: dict[str, Any] = getattr(context, "metadata", {})
        if session_id:
            metadata["session_id"] = session_id
        messages: list[Any] = getattr(context, "messages", None) or []
        if messages:
            last_text = getattr(messages[-1], "text", "") or str(messages[-1])
            delegated = parse_delegated_from(last_text)
            if delegated:
                metadata["delegated_from"] = delegated
                state = get_session_state(session_id)
                state.delegated_from = delegated
        try:
            await super().process(context, call_next)
        finally:
            reset_governance_audit_context(token)


def _resolved_v5_session_id(fallback_prefix: str) -> str:
    return resolve_session_id() or f"{fallback_prefix}-{int(time.time())}"


class GovernedCapabilityGuardMiddleware(CapabilityGuardMiddleware):
    """Capability guard with session context, delegation audit, and tool tracking."""

    def _ensure_v5_context(self) -> Any:
        assert self.kernel is not None
        if self._v5_ctx is None:
            from agent_os.integrations.base import ExecutionContext

            self._v5_ctx = ExecutionContext(
                agent_id=self._agent_id,
                session_id=_resolved_v5_session_id("maf-cap"),
                policy=self.kernel.policy,
            )
        return self._v5_ctx

    async def _process_v5(
        self,
        context: Any,
        call_next: Callable[[], Awaitable[None]],
    ) -> None:
        assert self.kernel is not None
        func_name = getattr(
            getattr(context, "function", None), "name", "unknown"
        )

        raw_args = getattr(context, "arguments", None)
        if isinstance(raw_args, dict):
            args_dict = dict(raw_args)
        elif raw_args is None:
            args_dict = {}
        else:
            args_dict = {"_value": raw_args}

        ctx = self._ensure_v5_context()
        bridge_result = self.kernel.evaluate_pre_tool_call(
            ctx,
            tool_name=func_name,
            args=args_dict,
            call_id=f"maf-cap-{ctx.call_count + 1}",
        )

        if not bridge_result.allowed:
            reason = bridge_result.reason or "tool_blocked"
            context.result = (
                f"⛔ Tool '{func_name}' is not permitted by governance policy"
            )

            if self.audit_log:
                self.audit_log.log(
                    event_type="tool_blocked",
                    agent_did="capability-guard",
                    action="deny",
                    resource=func_name,
                    data=enrich_audit_data(
                        {
                            "tool": func_name,
                            "reason": reason,
                            "verdict": bridge_result.verdict,
                        },
                        decision=bridge_result.verdict,
                        threat_class=_threat_class_for_reason(reason),
                    ),
                    outcome="denied",
                    policy_decision=bridge_result.verdict,
                )

            raise MiddlewareTermination(
                f"Tool '{func_name}' is not permitted by governance policy"
            )

        if bridge_result.transform is not None and isinstance(
            bridge_result.transform.value, dict
        ):
            try:
                context.arguments = bridge_result.transform.value
            except Exception:  # noqa: BLE001
                pass

        if self.audit_log:
            self.audit_log.log(
                event_type="tool_invocation",
                agent_did="capability-guard",
                action="start",
                resource=func_name,
                data=enrich_audit_data({"tool": func_name}, decision="allow"),
                outcome="success",
                policy_decision="allow",
            )

        await call_next()

        ctx.call_count += 1
        result_summary = str(getattr(context, "result", ""))[:500]
        state = get_session_state(ctx.session_id)
        state.record_tool_completion(func_name, getattr(context, "result", ""))

        if self.audit_log:
            self.audit_log.log(
                event_type="tool_invocation",
                agent_did="capability-guard",
                action="complete",
                resource=func_name,
                data=enrich_audit_data(
                    {
                        "tool": func_name,
                        "result_preview": result_summary,
                        "read_file_count": state.read_file_count,
                        "poisoned_context": state.poisoned_context,
                    },
                    decision="allow",
                ),
                outcome="success",
                policy_decision="allow",
            )


def _threat_class_for_reason(reason: str) -> str:
    mapping = {
        "tool_unknown": "T8",
        "tool_not_allowed": "T1",
        "intent_mismatch": "T4",
        "credential_scope_insufficient": "T8",
        "poisoned_context_blocked": "T5",
        "enumeration_limit_exceeded": "T9",
        "write_path_not_allowed": "T10",
        "egress_destination_not_allowed": "T3",
        "blocked_pattern_input": "T1",
    }
    return mapping.get(reason, "")
