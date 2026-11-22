"""Audit helpers: session_id, consistent agent_did, Foundry request context, OTEL fields."""

from __future__ import annotations

import logging
import os
from contextvars import ContextVar, Token
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from agentmesh.governance import AuditEntry, AuditLog

_logger = logging.getLogger(__name__)

_BAGGAGE_SESSION_ID = "azure.ai.agentserver.session_id"
_ALTERNATE_AGENT_DIDS = frozenset({"capability-guard"})


@dataclass(frozen=True)
class GovernanceAuditContext:
    session_id: str | None
    agent_did: str
    agent_name: str | None = None
    delegated_from: str | None = None


_audit_context: ContextVar[GovernanceAuditContext | None] = ContextVar(
    "governance_audit_context",
    default=None,
)


def set_governance_audit_context(
    *,
    session_id: str | None,
    agent_did: str,
    agent_name: str | None = None,
    delegated_from: str | None = None,
) -> Token:
    """Bind session/agent identity for the current async task (one agent invoke)."""
    return _audit_context.set(
        GovernanceAuditContext(
            session_id=session_id,
            agent_did=agent_did,
            agent_name=agent_name,
            delegated_from=delegated_from,
        )
    )


def reset_governance_audit_context(token: Token) -> None:
    _audit_context.reset(token)


def resolve_session_id(context: Any | None = None) -> str | None:
    """Resolve Foundry session ID from request context, OTEL baggage, or metadata."""
    try:
        from azure.ai.agentserver.core import get_request_context

        session_id = get_request_context().session_id
        if isinstance(session_id, str) and session_id.strip():
            return session_id.strip()
    except Exception:
        pass

    try:
        from opentelemetry import baggage as otel_baggage
        from opentelemetry import context as otel_context

        bag_session = otel_baggage.get_baggage(
            _BAGGAGE_SESSION_ID,
            context=otel_context.get_current(),
        )
        if isinstance(bag_session, str) and bag_session.strip():
            return bag_session.strip()
    except Exception:
        pass

    if context is not None:
        metadata = getattr(context, "metadata", None) or {}
        for key in ("session_id", "agent_session_id"):
            value = metadata.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()

    bound = _audit_context.get()
    if bound is not None and bound.session_id:
        return bound.session_id

    return None


def resolve_trace_id() -> str | None:
    """Return the active OTEL trace ID as a 32-char hex string, if any."""
    try:
        from opentelemetry import trace

        span = trace.get_current_span()
        span_context = span.get_span_context()
        if span_context is not None and span_context.is_valid:
            return format(span_context.trace_id, "032x")
    except Exception:
        pass
    return None


def normalize_agent_did(agent_did: str) -> str:
    """Map middleware-specific aliases to the canonical agent DID."""
    bound = _audit_context.get()
    if bound is None:
        return agent_did
    if agent_did in _ALTERNATE_AGENT_DIDS:
        return bound.agent_did
    if bound.agent_name and agent_did == bound.agent_name:
        return bound.agent_did
    return agent_did


def enrich_audit_data(
    data: dict[str, Any] | None,
    *,
    decision: str | None = None,
    threat_class: str | None = None,
    session_id: str | None = None,
    action_id: str | None = None,
    intervention_point: str | None = None,
) -> dict[str, Any]:
    """Add AARM-interoperable telemetry fields (S11) and policy-context evidence (S29/S30).

    ``aarm.decision`` is set once: a decision already stamped by the middleware
    (``modify``, ``step_up``, ``defer``) is not overwritten by the audit log's
    generic enrichment. ``aarm.action_id`` + ``aarm.intervention_point`` mark a
    decision record, so a batch export can prove one decision per action (S31).
    """
    payload = dict(data or {})
    if decision and "aarm.decision" not in payload:
        payload["aarm.decision"] = decision
    if threat_class:
        payload["aarm.threat_class"] = threat_class
    if action_id:
        payload["aarm.action_id"] = action_id
    if intervention_point:
        payload["aarm.intervention_point"] = intervention_point
    payload["agent.id"] = payload.get("agent.id") or _current_agent_id()
    bound = _audit_context.get()
    if bound and bound.delegated_from:
        payload["delegated_from"] = bound.delegated_from
        payload["executed_by"] = bound.agent_did
    _attach_policy_context(payload, session_id)
    return payload


def _attach_policy_context(payload: dict[str, Any], session_id: str | None) -> None:
    """Embed what policy saw (intent, prior actions, drift) so receipts are self-evidencing."""
    if "policy_context" in payload:
        return
    try:
        from governance_session import peek_policy_context

        bound = _audit_context.get()
        sid = session_id or (bound.session_id if bound else None) or resolve_session_id()
        context = peek_policy_context(sid)
    except Exception:
        return
    if context is None:
        return
    payload["policy_context"] = context
    # Flat copies stay queryable in OTEL / Log Analytics, where nested values become strings.
    payload["aarm.drift_score"] = context["drift_score"]
    payload["aarm.message_count"] = context["message_count"]


def stamp_agent_id(payload: dict[str, Any], agent_did: str) -> dict[str, Any]:
    payload["agent.id"] = agent_did
    return payload


def _current_agent_id() -> str:
    bound = _audit_context.get()
    if bound is not None:
        return bound.agent_did
    try:
        from governance_phase2 import phase2_enabled, resolve_runtime_agent_id

        if phase2_enabled():
            return resolve_runtime_agent_id(fallback="governed-assistant")
    except Exception:
        pass
    return "governed-assistant"


def _to_otel_audit_entry(entry: AuditEntry) -> Any:
    """Adapt an ``agentmesh`` AuditEntry to the shape ``OTelLogsBackend`` expects.

    ``agent_os.otel_audit_backend.OTelLogsBackend`` reads ``agent_id``,
    ``decision``, ``reason``, ``latency_ms`` and ``metadata`` from
    ``agent_os.audit_logger.AuditEntry``, while the governance middleware
    produces ``agentmesh.governance.AuditEntry`` (``agent_did``,
    ``policy_decision``, ``data``, ...). Passing the latter directly raises
    ``AttributeError: 'AuditEntry' object has no attribute 'agent_id'``.
    """
    from agent_os.audit_logger import AuditEntry as OtelAuditEntry

    data = dict(getattr(entry, "data", None) or {})
    metadata: dict[str, Any] = dict(data)
    for key in ("entry_id", "session_id", "trace_id", "resource", "outcome"):
        value = getattr(entry, key, None)
        if value is not None:
            metadata[key] = value

    latency_ms = 0.0
    issued_at = getattr(entry, "issued_at", None)
    completed_at = getattr(entry, "completed_at", None)
    if issued_at is not None and completed_at is not None:
        try:
            latency_ms = (completed_at - issued_at).total_seconds() * 1000.0
        except Exception:
            latency_ms = 0.0

    timestamp = getattr(entry, "timestamp", None)
    return OtelAuditEntry(
        timestamp=(
            timestamp.isoformat() if hasattr(timestamp, "isoformat") else str(timestamp)
        ),
        event_type=entry.event_type,
        agent_id=entry.agent_did,
        action=entry.action,
        decision=(
            getattr(entry, "policy_decision", None)
            or data.get("aarm.decision")
            or getattr(entry, "outcome", "")
            or ""
        ),
        reason=str(data.get("reason") or ""),
        latency_ms=latency_ms,
        metadata=metadata,
    )


class _OtelEnrichedSink:
    """Wraps an audit sink and mirrors entries to OTEL logs when available."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self._otel: Any | None = None
        try:
            from agent_os.otel_audit_backend import OTelLogsBackend

            backend = OTelLogsBackend()
            if backend.enabled:
                self._otel = backend
        except Exception:
            self._otel = None

    def write(self, entry: AuditEntry) -> None:
        self._inner.write(entry)
        if self._otel is not None:
            # Telemetry mirroring must never break the governed invocation.
            try:
                self._otel.write(_to_otel_audit_entry(entry))
            except Exception:
                _logger.debug("OTEL audit mirror failed", exc_info=True)

    def flush(self) -> None:
        self._inner.flush()
        if self._otel is not None:
            self._otel.flush()


class GovernedAuditLog(AuditLog):
    """AuditLog that stamps session_id, delegation, and normalizes agent_did."""

    @staticmethod
    def _attach_mesh_signature_fields(
        enriched: dict[str, Any],
        *,
        agent_did: str,
        event_type: str,
    ) -> None:
        try:
            from governance_phase2 import phase2_enabled
            from governance_identity import sign_audit_fields

            if not phase2_enabled():
                return
            if not str(agent_did).startswith("did:mesh:"):
                return
            enriched.update(
                sign_audit_fields(
                    enriched.get("entry_id") or event_type,
                    event_type,
                    agent_did,
                )
            )
        except Exception:
            return

    def log(
        self,
        event_type: str,
        agent_did: str,
        action: str,
        resource: Optional[str] = None,
        data: Optional[dict] = None,
        outcome: str = "success",
        policy_decision: Optional[str] = None,
        trace_id: Optional[str] = None,
        *,
        session_id: Optional[str] = None,
        arguments_hash: str | None = None,
        approver_did: str | None = None,
        policy_version: str | None = None,
        issued_at: datetime | None = None,
        completed_at: datetime | None = None,
    ) -> AuditEntry:
        resolved_session_id = session_id or resolve_session_id()
        resolved_trace_id = trace_id or resolve_trace_id()
        resolved_agent_did = normalize_agent_did(agent_did)
        enriched = enrich_audit_data(
            data,
            decision=policy_decision or action,
            threat_class=(data or {}).get("aarm.threat_class"),
        )
        self._attach_mesh_signature_fields(
            enriched,
            agent_did=resolved_agent_did,
            event_type=event_type,
        )
        stamp_agent_id(enriched, resolved_agent_did)

        entry = AuditEntry(
            event_type=event_type,
            agent_did=resolved_agent_did,
            action=action,
            resource=resource,
            data=enriched,
            outcome=outcome,
            policy_decision=policy_decision,
            trace_id=resolved_trace_id,
            session_id=resolved_session_id,
            sandbox_id=self._env_context.sandbox_id,
            environment=self._env_context.environment,
            compute_driver=self._env_context.compute_driver,
            arguments_hash=arguments_hash,
            approver_did=approver_did,
            policy_version=policy_version,
            issued_at=issued_at,
            completed_at=completed_at,
        )

        self._chain.add_entry(entry)

        if self._sink is not None:
            self._sink.write(entry)

        if resolved_agent_did not in self._by_agent:
            self._by_agent[resolved_agent_did] = []
        self._by_agent[resolved_agent_did].append(entry.entry_id)

        if event_type not in self._by_type:
            self._by_type[event_type] = []
        self._by_type[event_type].append(entry.entry_id)

        return entry


def build_audit_sink() -> Any:
    """Return stdout, signed file, or OTEL-enriched audit sink."""
    from agentmesh.governance import StdoutAuditSink

    signed = os.getenv("GOVERNANCE_SIGNED_AUDIT", "").lower() in ("1", "true", "yes")
    otel_mirror = os.getenv("GOVERNANCE_OTEL_AUDIT", "1").lower() not in ("0", "false", "no")

    if signed:
        from agentmesh.governance.audit_backends import FileAuditSink

        audit_path = Path(
            os.getenv("GOVERNANCE_AUDIT_FILE", ".governance-audit.jsonl")
        ).resolve()
        secret = os.getenv("GOVERNANCE_AUDIT_SECRET", "governed-assistant-demo-key").encode()
        inner: Any = FileAuditSink(audit_path, secret)
    elif os.getenv("GOVERNANCE_AUDIT_STDOUT", "1").lower() in ("0", "false", "no"):
        inner = None
    else:
        inner = StdoutAuditSink()

    if inner is None:
        return None
    if otel_mirror:
        return _OtelEnrichedSink(inner)
    return inner
