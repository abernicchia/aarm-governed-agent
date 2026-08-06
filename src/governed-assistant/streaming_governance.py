"""Streaming-compatible policy denial for the Foundry Responses host."""

from __future__ import annotations

import time
from typing import Any, Awaitable, Callable

from agent_framework import (
    AgentResponse,
    AgentResponseUpdate,
    Content,
    Message,
    MiddlewareTermination,
    ResponseStream,
)
from agent_os.integrations.maf_adapter import GovernancePolicyMiddleware, logger

from governance_audit import enrich_audit_data, resolve_session_id


def _message_text(message: Any) -> str:
    text = getattr(message, "text", None)
    return text if isinstance(text, str) else ""


def _apply_input_text_transform(message: Any, transformed_text: str) -> None:
    """Rewrite the last user message after a Rego transform verdict."""
    if isinstance(message, Message):
        message.contents = [Content.from_text(text=transformed_text)]
        message.raw_representation = None
        return

    contents = getattr(message, "contents", None)
    if isinstance(contents, list):
        message.contents = [Content.from_text(text=transformed_text)]
        return

    if hasattr(message, "content"):
        setattr(message, "content", transformed_text)


def _apply_redaction_transform(
    kernel: Any,
    ctx: Any,
    message: Any,
) -> bool:
    """Apply a Rego transform verdict to one message, when redaction applies."""
    text = _message_text(message)
    if not text:
        return False

    bridge_result = kernel.evaluate_input(ctx, text)
    if (
        bridge_result.transform is not None
        and isinstance(bridge_result.transform.value, str)
        and bridge_result.transform.value != text
    ):
        _apply_input_text_transform(message, bridge_result.transform.value)
        return True
    return False


def _set_stream_aware_denial(context: Any, reason: str) -> None:
    """Return a user-visible denial that works for both streaming and non-streaming runs."""
    message = f"⛔ Policy violation: {reason}"
    if getattr(context, "stream", False):

        async def _denial_updates() -> Any:
            yield AgentResponseUpdate(
                contents=[Content.from_text(text=message)],
                role="assistant",
            )

        context.result = ResponseStream(
            _denial_updates(),
            finalizer=AgentResponse.from_updates,
        )
        return

    context.result = AgentResponse(
        messages=[Message("assistant", [message])],
    )


class StreamingGovernancePolicyMiddleware(GovernancePolicyMiddleware):
    """GovernancePolicyMiddleware that surfaces denials over streaming Responses API."""

    def _ensure_v5_context(self) -> Any:
        assert self.kernel is not None
        if self._v5_ctx is None:
            from agent_os.integrations.base import ExecutionContext

            self._v5_ctx = ExecutionContext(
                agent_id=self._agent_id,
                session_id=resolve_session_id() or f"maf-mw-{int(time.time())}",
                policy=self.kernel.policy,
            )
        return self._v5_ctx

    async def _process_v4(
        self,
        context: Any,
        call_next: Callable[[], Awaitable[None]],
    ) -> None:
        agent_name = getattr(context.agent, "name", "unknown")

        last_message_text = ""
        messages: list[Any] = getattr(context, "messages", None) or []
        if messages:
            last_msg = messages[-1]
            last_message_text = getattr(last_msg, "text", None) or str(last_msg)

        eval_context: dict[str, Any] = {
            "agent": agent_name,
            "message": last_message_text,
            "timestamp": time.time(),
            "stream": getattr(context, "stream", False),
            "message_count": len(messages),
        }

        decision = self.evaluator.evaluate(eval_context)

        metadata: dict[str, Any] = getattr(context, "metadata", {})
        metadata["governance_decision"] = decision

        if not decision.allowed:
            logger.info(
                "Policy DENY for agent '%s': %s (rule=%s)",
                agent_name,
                decision.reason,
                decision.matched_rule,
            )
            _set_stream_aware_denial(context, decision.reason)

            if self.audit_log:
                self.audit_log.log(
                    event_type="policy_violation",
                    agent_did=self._agent_id,
                    action="deny",
                    data={
                        "reason": decision.reason,
                        "matched_rule": decision.matched_rule,
                        "message_preview": last_message_text[:200],
                    },
                    outcome="denied",
                    policy_decision=decision.action,
                )

            raise MiddlewareTermination(decision.reason)

        logger.debug(
            "Policy ALLOW for agent '%s' (rule=%s)",
            agent_name,
            decision.matched_rule,
        )

        if self.audit_log:
            self.audit_log.log(
                event_type="policy_evaluation",
                agent_did=self._agent_id,
                action="allow",
                data={
                    "matched_rule": decision.matched_rule,
                    "message_preview": last_message_text[:200],
                },
                outcome="success",
                policy_decision=decision.action,
            )

        await call_next()

    async def _process_v5(
        self,
        context: Any,
        call_next: Callable[[], Awaitable[None]],
    ) -> None:
        assert self.kernel is not None
        agent_name = getattr(context.agent, "name", "unknown")

        last_message_text = ""
        last_msg = None
        messages: list[Any] = getattr(context, "messages", None) or []
        if messages:
            last_msg = messages[-1]
            last_message_text = _message_text(last_msg) or str(last_msg)

        ctx = self._ensure_v5_context()

        # Foundry passes prior turns plus the new user message. Redact secrets
        # in the full context so stale session history cannot leak credentials.
        redacted_count = 0
        for message in messages:
            if message is last_msg:
                continue
            if _apply_redaction_transform(self.kernel, ctx, message):
                redacted_count += 1

        bridge_result = self.kernel.evaluate_input(ctx, last_message_text)

        metadata: dict[str, Any] = getattr(context, "metadata", {})
        metadata["governance_decision"] = bridge_result

        if not bridge_result.allowed:
            reason = bridge_result.reason or "policy_violation"
            logger.info(
                "Policy DENY (AGT input) for agent '%s': %s",
                agent_name,
                reason,
            )
            _set_stream_aware_denial(context, reason)

            if self.audit_log:
                self.audit_log.log(
                    event_type="policy_violation",
                    agent_did=self._agent_id,
                    action="deny",
                    data=enrich_audit_data(
                        {
                            "reason": reason,
                            "verdict": bridge_result.verdict,
                            "message_preview": last_message_text[:200],
                        },
                        decision=bridge_result.verdict,
                        threat_class="T1",
                    ),
                    outcome="denied",
                    policy_decision=bridge_result.verdict,
                )

            raise MiddlewareTermination(reason)

        if (
            bridge_result.transform is not None
            and isinstance(bridge_result.transform.value, str)
            and last_msg is not None
        ):
            _apply_input_text_transform(last_msg, bridge_result.transform.value)

        policy_decision = "modify" if bridge_result.transform is not None else bridge_result.verdict
        if redacted_count or bridge_result.transform is not None:
            policy_decision = "modify"
        logger.debug(
            "Policy %s (AGT input) for agent '%s'%s",
            policy_decision.upper(),
            agent_name,
            f" ({redacted_count} history message(s) redacted)" if redacted_count else "",
        )

        if self.audit_log:
            self.audit_log.log(
                event_type="policy_evaluation",
                agent_did=self._agent_id,
                action="allow",
                data=enrich_audit_data(
                    {
                        "message_preview": last_message_text[:200],
                        "verdict": bridge_result.verdict,
                        "transformed": bridge_result.transform is not None or redacted_count > 0,
                        "history_messages_redacted": redacted_count,
                    },
                    decision=policy_decision,
                ),
                outcome="success",
                policy_decision=policy_decision,
            )

        await call_next()
