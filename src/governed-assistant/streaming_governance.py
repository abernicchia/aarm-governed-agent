"""ACS `input` policy middleware with streaming-compatible denials for the Foundry host."""

from __future__ import annotations

import logging
import time
from typing import Any, Awaitable, Callable

from agent_framework import (
    AgentMiddleware,
    AgentResponse,
    AgentResponseUpdate,
    Content,
    Message,
    MiddlewareTermination,
    ResponseStream,
)

from acs_host import HostContext
from governance_audit import enrich_audit_data, resolve_session_id
from governance_kernel import GovernanceKernel

logger = logging.getLogger(__name__)


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


async def _apply_redaction_transform(
    kernel: GovernanceKernel,
    ctx: HostContext,
    message: Any,
) -> bool:
    """Apply a Rego transform verdict to one message, when redaction applies."""
    text = _message_text(message)
    if not text:
        return False

    result = await kernel.evaluate_input(ctx, text)
    transformed = result.transformed_value
    if result.transform is not None and isinstance(transformed, str) and transformed != text:
        _apply_input_text_transform(message, transformed)
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


class StreamingGovernancePolicyMiddleware(AgentMiddleware):
    """Evaluates the ACS `input` point and surfaces denials over the streaming Responses API."""

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
        self._host_ctx: HostContext | None = None

    def _host_context(self) -> HostContext:
        if self._host_ctx is None:
            self._host_ctx = HostContext(
                agent_id=self._agent_id,
                session_id=resolve_session_id() or f"maf-mw-{int(time.time())}",
            )
        return self._host_ctx

    async def process(
        self,
        context: Any,
        call_next: Callable[[], Awaitable[None]],
    ) -> None:
        agent_name = getattr(context.agent, "name", "unknown")

        last_message_text = ""
        last_msg = None
        messages: list[Any] = getattr(context, "messages", None) or []
        if messages:
            last_msg = messages[-1]
            last_message_text = _message_text(last_msg) or str(last_msg)

        ctx = self._host_context()

        # Foundry passes prior turns plus the new user message. Redact secrets
        # in the full context so stale session history cannot leak credentials.
        redacted_count = 0
        for message in messages:
            if message is last_msg:
                continue
            if await _apply_redaction_transform(self.kernel, ctx, message):
                redacted_count += 1

        result = await self.kernel.evaluate_input(ctx, last_message_text)

        metadata: dict[str, Any] = getattr(context, "metadata", {})
        metadata["governance_decision"] = result

        if not result.allowed:
            reason = result.reason or "policy_violation"
            logger.info(
                "Policy DENY (ACS input) for agent '%s': %s",
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
                            "verdict": result.verdict,
                            "message_preview": last_message_text[:200],
                        },
                        decision=result.verdict,
                        threat_class="T1",
                    ),
                    outcome="denied",
                    policy_decision=result.verdict,
                )

            raise MiddlewareTermination(reason)

        transformed = result.transformed_value
        if result.transform is not None and isinstance(transformed, str) and last_msg is not None:
            _apply_input_text_transform(last_msg, transformed)

        policy_decision = result.verdict
        if redacted_count or result.transform is not None:
            policy_decision = "modify"
        logger.debug(
            "Policy %s (ACS input) for agent '%s'%s",
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
                        "verdict": result.verdict,
                        "transformed": result.transform is not None or redacted_count > 0,
                        "history_messages_redacted": redacted_count,
                    },
                    decision=policy_decision,
                ),
                outcome="success",
                policy_decision=policy_decision,
            )

        await call_next()
