"""Project middleware wrappers that bind Foundry session context to audit entries."""

from __future__ import annotations

import json
import uuid
from typing import Any, Awaitable, Callable

from agent_framework import Content, FunctionMiddleware, MiddlewareTermination
from agent_os.integrations.maf_adapter import AuditTrailMiddleware

from acs_host import HostContext, SessionHostContexts
from governance_audit import (
    enrich_audit_data,
    resolve_session_id,
    reset_governance_audit_context,
    set_governance_audit_context,
)
from governance_kernel import GovernanceKernel
from governance_phase2 import resolve_runtime_agent_id
from governance_session import get_session_state, parse_delegated_from


class GovernedAuditTrailMiddleware(AuditTrailMiddleware):
    """AuditTrailMiddleware that binds session_id for all nested audit entries."""

    async def process(
        self,
        context: Any,
        call_next: Callable[[], Awaitable[None]],
    ) -> None:
        agent_name = getattr(context.agent, "name", "unknown")
        agent_did = resolve_runtime_agent_id(fallback=self.agent_did or agent_name)
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


def tool_result_text(result: Any) -> str:
    """Plain text of a tool result.

    The agent framework hands the guard a ``list[Content]`` (not a ``str``) for tool output,
    and ``str()`` of that list is an object repr, not the text. Policy and audit need the text:
    the Rego poisoning rule only inspects string values, and the receipt's ``result_preview``
    should be readable.
    """
    if result is None:
        return ""
    if isinstance(result, str):
        return result
    if isinstance(result, Content):
        return str(result)
    if isinstance(result, (list, tuple)):
        return "\n".join(tool_result_text(item) for item in result)
    if isinstance(result, dict):
        try:
            return json.dumps(result, default=str, sort_keys=True)
        except (TypeError, ValueError):
            return str(result)
    return str(result)


class GovernedCapabilityGuardMiddleware(FunctionMiddleware):
    """ACS `pre_tool_call` / `post_tool_call` guard with session context and tool tracking."""

    def __init__(
        self,
        *,
        kernel: GovernanceKernel,
        audit_log: Any | None = None,
        agent_id: str = "maf-agent",
    ) -> None:
        self.kernel = kernel
        self.audit_log = audit_log
        self._agent_id = agent_id
        # Offline tests and drivers pin one context here to share a session across middleware.
        self._host_ctx: HostContext | None = None
        self._contexts = SessionHostContexts(agent_id=agent_id, fallback_prefix="maf-cap")

    def _host_context(self) -> HostContext:
        """The context for this request's own session; a pinned context wins."""
        if self._host_ctx is not None:
            return self._host_ctx
        return self._contexts.for_session(resolve_session_id())

    async def process(
        self,
        context: Any,
        call_next: Callable[[], Awaitable[None]],
    ) -> None:
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

        ctx = self._host_context()
        action_id = uuid.uuid4().hex[:12]
        pre_result = await self.kernel.evaluate_pre_tool_call(
            ctx,
            tool_name=func_name,
            args=args_dict,
            call_id=f"maf-cap-{ctx.call_count + 1}",
        )

        if not pre_result.allowed:
            reason = pre_result.reason or "tool_blocked"
            context.result = (
                f"⛔ Tool '{func_name}' is not permitted by governance policy"
            )

            if self.audit_log:
                self.audit_log.log(
                    event_type="tool_blocked",
                    agent_did=self._agent_id,
                    action="deny",
                    resource=func_name,
                    data=enrich_audit_data(
                        {
                            "tool": func_name,
                            "reason": reason,
                            "verdict": pre_result.verdict,
                            "approval": pre_result.approval,
                        },
                        decision=pre_result.decision,
                        threat_class=_threat_class_for_reason(reason),
                        session_id=ctx.session_id,
                        action_id=action_id,
                        intervention_point="pre_tool_call",
                    ),
                    outcome="denied",
                    policy_decision=pre_result.decision,
                )

            raise MiddlewareTermination(
                f"Tool '{func_name}' is not permitted by governance policy"
            )

        if pre_result.transform is not None and isinstance(pre_result.transformed_value, dict):
            try:
                context.arguments = pre_result.transformed_value
            except Exception:  # noqa: BLE001
                pass

        if self.audit_log:
            self.audit_log.log(
                event_type="tool_invocation",
                agent_did=self._agent_id,
                action="start",
                resource=func_name,
                data=enrich_audit_data(
                    {"tool": func_name, "approval": pre_result.approval},
                    decision=pre_result.decision,
                    session_id=ctx.session_id,
                    action_id=action_id,
                    intervention_point="pre_tool_call",
                ),
                outcome="success",
                policy_decision=pre_result.decision,
            )

        await call_next()

        ctx.call_count += 1
        result_text = tool_result_text(getattr(context, "result", ""))
        result_summary = result_text[:500]
        state = get_session_state(ctx.session_id)

        post_result = await self.kernel.evaluate_post_tool_call(
            ctx,
            tool_name=func_name,
            args=args_dict,
            result=result_text,
            call_id=f"maf-cap-{ctx.call_count}",
        )
        if not post_result.allowed:
            reason = post_result.reason or "tool_output_blocked"
            context.result = (
                f"⛔ Tool output from '{func_name}' blocked by governance policy"
            )
            state.poisoned_context = reason in {
                "tool_output_poisoned",
                "poisoned_context_blocked",
            }
            result_summary = str(context.result)[:500]
        elif post_result.transform is not None:
            transformed = post_result.transformed_value
            if transformed is not None:
                context.result = transformed
                result_summary = str(transformed)[:500]

        if self.audit_log:
            self.audit_log.log(
                event_type="tool_invocation",
                agent_did=self._agent_id,
                action="complete",
                resource=func_name,
                data=enrich_audit_data(
                    {
                        "tool": func_name,
                        "result_preview": result_summary,
                        "read_file_count": state.read_file_count,
                        "poisoned_context": state.poisoned_context,
                        "reason": post_result.reason,
                    },
                    decision=post_result.decision,
                    threat_class=(
                        _threat_class_for_reason(post_result.reason)
                        if not post_result.allowed
                        else None
                    ),
                    session_id=ctx.session_id,
                    action_id=action_id,
                    intervention_point="post_tool_call",
                ),
                outcome="success" if post_result.allowed else "denied",
                policy_decision=post_result.decision,
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
        "semantic_drift_blocked": "T4",
        "intent_drift_blocked": "T4",
        "delegation_unsigned": "T7",
        "delegation_scope_insufficient": "T2",
        "tool_output_poisoned": "T11",
        "tool_output_blocked": "T10",
        "context_thread_poisoned": "T5",
    }
    return mapping.get(reason, "")
