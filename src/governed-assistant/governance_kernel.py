"""Governance kernel — injects session context into ACS snapshots and evaluates them."""

from __future__ import annotations

from typing import Any

from acs_host import AcsHost, HostContext, PolicyResult
from governance_session import get_session_state, inject_governance_snapshot
from tools import ALLOWED_TOOLS


class GovernanceKernel:
    """Evaluates the `input`, `pre_tool_call`, and `post_tool_call` points on the ACS runtime."""

    def __init__(self, host: AcsHost) -> None:
        self.host = host

    def _enrich_state(self, ctx: HostContext) -> None:
        state = get_session_state(ctx.session_id)
        try:
            from governance_phase2 import enrich_session_for_input, phase2_enabled

            if phase2_enabled():
                enrich_session_for_input(state, allowed_tools=ALLOWED_TOOLS)
                if not state.agent_did:
                    from governance_phase2 import resolve_runtime_agent_id

                    state.agent_did = resolve_runtime_agent_id(fallback=ctx.agent_id)
        except Exception:
            pass

    async def evaluate_input(self, ctx: HostContext, input_data: Any) -> PolicyResult:
        body: Any
        if isinstance(input_data, (str, dict)):
            body = input_data
        elif hasattr(input_data, "content"):
            body = str(getattr(input_data, "content"))
        else:
            body = str(input_data)

        state = get_session_state(ctx.session_id)
        state.ingest_user_message(body if isinstance(body, str) else str(body))
        self._enrich_state(ctx)

        snapshot = self.host.builder_for(ctx).input(body=body)
        snapshot = inject_governance_snapshot(snapshot, ctx.session_id)
        return await self.host.aevaluate("input", snapshot)

    async def evaluate_pre_tool_call(
        self,
        ctx: HostContext,
        *,
        tool_name: str,
        args: dict[str, Any],
        call_id: str = "call-1",
    ) -> PolicyResult:
        state = get_session_state(ctx.session_id)
        try:
            from governance_phase2 import enrich_session_for_tool, phase2_enabled

            if phase2_enabled():
                enrich_session_for_tool(
                    state,
                    tool_name=tool_name,
                    args=dict(args),
                    request_id=call_id,
                    allowed_tools=ALLOWED_TOOLS,
                )
        except Exception:
            pass

        snapshot = self.host.builder_for(ctx).pre_tool_call(
            tool_name=tool_name,
            args=dict(args),
            call_id=call_id,
        )
        snapshot = inject_governance_snapshot(snapshot, ctx.session_id)
        return await self.host.aevaluate("pre_tool_call", snapshot)

    async def evaluate_post_tool_call(
        self,
        ctx: HostContext,
        *,
        tool_name: str,
        args: dict[str, Any],
        result: Any,
        error: Any = None,
        duration_ms: float = 0.0,
        call_id: str = "call-1",
    ) -> PolicyResult:
        state = get_session_state(ctx.session_id)
        state.record_tool_completion(tool_name, result, args=dict(args))

        snapshot = self.host.builder_for(ctx).post_tool_call(
            tool_name=tool_name,
            args=dict(args),
            result=result,
            error=error,
            duration_ms=duration_ms,
            call_id=call_id,
        )
        snapshot["policy_target"] = {"value": result, "kind": "tool_output"}
        snapshot = inject_governance_snapshot(snapshot, ctx.session_id)
        return await self.host.aevaluate("post_tool_call", snapshot)
