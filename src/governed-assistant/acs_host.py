"""Host seam over the ACS runtime (`agent_control_specification.AgentControl`).

AGT removed `agt.policies` (`AgtRuntime`, `ApprovalDecision`, `SnapshotBuilder`,
...); hosts now call the ACS runtime directly. This module is the only place
that talks to `AgentControl`: it builds AGT snapshots, evaluates intervention
points, and routes approvals through the host resolver.
"""

from __future__ import annotations

import asyncio
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Mapping

from agent_control_specification import (
    AgentControl,
    AgentControlBlocked,
    AgentControlSuspended,
    ApprovalResolver,
    Decision,
    EnforcementMode,
    InterventionPoint,
    InterventionPointResult,
    Verdict,
)

DEFAULT_APPROVAL_TIMEOUT_SECONDS = 300.0
DEFER_REASON_PREFIX = "defer_missing_"


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class HostContext:
    """Per-session host counters mirrored into the snapshot envelope budgets."""

    agent_id: str
    session_id: str
    call_count: int = 0
    total_tokens: int = 0


class SessionHostContexts:
    """One `HostContext` per session id, resolved on every request.

    A middleware lives as long as the host process, but sessions come and go. If it kept a
    single `HostContext` built on its first request, every later session would reuse that
    session's id, and with it the governance state keyed on it (intent, read counts, poison
    flags, pending DEFER) and the tool-call budget. Resolving the id per request keeps those
    separate. When no session id is available, one fixed fallback id is used for the life of
    the instance, which is the single-session behaviour the offline tests rely on.
    """

    def __init__(self, *, agent_id: str, fallback_prefix: str) -> None:
        self._agent_id = agent_id
        self._fallback_session_id = f"{fallback_prefix}-{int(time.time())}"
        self._contexts: dict[str, HostContext] = {}
        self._lock = threading.Lock()

    def for_session(self, session_id: str | None) -> HostContext:
        key = session_id or self._fallback_session_id
        with self._lock:
            ctx = self._contexts.get(key)
            if ctx is None:
                ctx = HostContext(agent_id=self._agent_id, session_id=key)
                self._contexts[key] = ctx
            return ctx


@dataclass
class SnapshotBuilder:
    """Builds AGT-SNAPSHOT-1.0 snapshots (common envelope + per-point body)."""

    agent_id: str
    session_id: str
    agent_version: str = "1.0.0"
    session_started_at: str = field(default_factory=_utcnow_iso)
    tool_call_count: int = 0
    token_count: int = 0

    def envelope(self, intervention_point: str) -> dict[str, Any]:
        return {
            "agent": {"id": self.agent_id, "version": self.agent_version, "name": self.agent_id},
            "session": {"id": self.session_id, "started_at": self.session_started_at},
            "intervention_point": intervention_point,
            "timestamp": _utcnow_iso(),
            "budgets": {
                "tool_call_count": self.tool_call_count,
                "token_count": self.token_count,
                "elapsed_seconds": 0.0,
                "cost_usd": 0.0,
            },
        }

    def input(self, *, body: str | dict[str, Any], source: str = "user") -> dict[str, Any]:
        return {
            "envelope": self.envelope("input"),
            "input": {"body": body, "source": source, "headers": {}, "ifc": {"source_labels": []}},
        }

    def pre_tool_call(self, *, tool_name: str, args: dict[str, Any], call_id: str) -> dict[str, Any]:
        return {
            "envelope": self.envelope("pre_tool_call"),
            "tool_call": {"name": tool_name, "args": args, "id": call_id},
        }

    def post_tool_call(
        self,
        *,
        tool_name: str,
        args: dict[str, Any],
        result: Any,
        error: Any = None,
        duration_ms: float = 0.0,
        call_id: str,
    ) -> dict[str, Any]:
        return {
            "envelope": self.envelope("post_tool_call"),
            "tool_call": {"name": tool_name, "args": args, "id": call_id},
            "tool_result": {"value": result, "error": error, "duration_ms": duration_ms},
        }


@dataclass(frozen=True)
class PolicyResult:
    """One evaluated intervention point plus the host approval outcome.

    ``approval`` is ``None`` when no approval was needed, otherwise one of
    ``approved``, ``denied``, ``suspended``, or ``timeout``.
    """

    evaluation: InterventionPointResult
    approval: str | None = None

    @property
    def verdict(self) -> str:
        if self.approval == "approved":
            return "allow"
        if self.approval in ("denied", "timeout"):
            return "deny"
        if self.approval == "suspended":
            return "escalate"
        return str(self.evaluation.verdict.decision.value)

    @property
    def allowed(self) -> bool:
        return self.verdict in ("allow", "warn", "transform")

    @property
    def reason(self) -> str:
        return str(self.evaluation.verdict.reason or "")

    @property
    def decision(self) -> str:
        """The AARM decision: one of ``allow``, ``deny``, ``modify``, ``step_up``, ``defer``.

        ACS has no DEFER verdict, so Rego signals it with a deny whose reason starts
        with ``defer_missing_``; the host surfaces it as its own decision (S31).
        """
        if self.missing_context:
            return "defer"
        if self.approval is not None:
            return "step_up"
        verdict = self.verdict
        if verdict == "transform":
            return "modify"
        if verdict == "escalate":
            return "step_up"
        if verdict == "warn":
            return "allow"
        return verdict

    @property
    def missing_context(self) -> list[str]:
        """Fields a DEFER is waiting for, e.g. ``["invoice_id"]``; empty when not deferred."""
        reason = self.reason
        if self.evaluation.verdict.decision == Decision.DENY and reason.startswith(DEFER_REASON_PREFIX):
            return [reason[len(DEFER_REASON_PREFIX):]]
        return []

    @property
    def message(self) -> str:
        return str(self.evaluation.verdict.message or "")

    @property
    def transform(self) -> Any | None:
        return self.evaluation.verdict.transform

    @property
    def transformed_value(self) -> Any:
        if self.evaluation.transformed_policy_target_applied:
            return self.evaluation.transformed_policy_target
        transform = self.transform
        return None if transform is None else transform.value

    @property
    def input_identity(self) -> str | None:
        return self.evaluation.input_identity

    @property
    def enforced_identity(self) -> str | None:
        return self.evaluation.enforced_identity

    def audit_record(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "decision": self.decision,
            "reason_code": self.reason,
            "approval": self.approval,
            "input_identity": self.input_identity,
            "enforced_identity": self.enforced_identity,
        }


def _requires_approval(verdict: Verdict) -> bool:
    # ACS <0.4 emits ``escalate``; ACS >=0.4 emits ``deny`` with an ``approval`` block.
    if verdict.decision == Decision.ESCALATE:
        return True
    return verdict.decision == Decision.DENY and getattr(verdict, "approval", None) is not None


def _run_sync(coro: Awaitable[Any]) -> Any:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)  # type: ignore[arg-type]

    holder: dict[str, Any] = {}

    def _runner() -> None:
        try:
            holder["value"] = asyncio.run(coro)  # type: ignore[arg-type]
        except BaseException as exc:  # noqa: BLE001 - re-raised in caller thread
            holder["error"] = exc

    thread = threading.Thread(target=_runner, daemon=True)
    thread.start()
    thread.join()
    if "error" in holder:
        raise holder["error"]
    return holder["value"]


class AcsHost:
    """Evaluates intervention points on an `AgentControl` and resolves approvals."""

    def __init__(
        self,
        control: AgentControl,
        *,
        approval_resolver: ApprovalResolver | None = None,
        approval_timeout_seconds: float = DEFAULT_APPROVAL_TIMEOUT_SECONDS,
    ) -> None:
        self._control = control
        self._approval_resolver = approval_resolver
        self._approval_timeout_seconds = approval_timeout_seconds
        self._builders: dict[str, SnapshotBuilder] = {}

    @property
    def control(self) -> AgentControl:
        return self._control

    def builder_for(self, ctx: HostContext) -> SnapshotBuilder:
        key = ctx.session_id or ctx.agent_id
        builder = self._builders.get(key)
        if builder is None:
            builder = SnapshotBuilder(agent_id=ctx.agent_id, session_id=key)
            self._builders[key] = builder
        builder.tool_call_count = max(builder.tool_call_count, int(ctx.call_count))
        builder.token_count = max(builder.token_count, int(ctx.total_tokens))
        return builder

    async def aevaluate(
        self,
        intervention_point: str,
        snapshot: Mapping[str, Any],
        mode: str = "enforce",
    ) -> PolicyResult:
        point = InterventionPoint(intervention_point)
        enforcement_mode = EnforcementMode(mode)
        result = await self._control.evaluate_intervention_point(point, dict(snapshot), enforcement_mode)
        if enforcement_mode != EnforcementMode.ENFORCE or not _requires_approval(result.verdict):
            return PolicyResult(result)
        if self._approval_resolver is None:
            return PolicyResult(result, approval="denied")

        try:
            await asyncio.wait_for(
                self._control.enforce(
                    point,
                    result,
                    enforcement_mode,
                    approval_resolver=self._approval_resolver,
                ),
                timeout=self._approval_timeout_seconds,
            )
        except TimeoutError:
            return PolicyResult(result, approval="timeout")
        except AgentControlSuspended:
            return PolicyResult(result, approval="suspended")
        except AgentControlBlocked as blocked:
            return PolicyResult(blocked.result, approval="denied")
        return PolicyResult(result, approval="approved")

    def evaluate_intervention_point(
        self,
        intervention_point: str,
        snapshot: Mapping[str, Any],
        mode: str = "enforce",
    ) -> PolicyResult:
        """Synchronous wrapper around :meth:`aevaluate` for scripts and tests."""
        return _run_sync(self.aevaluate(intervention_point, snapshot, mode))
