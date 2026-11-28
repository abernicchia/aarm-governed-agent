"""Phase 2 bootstrap — native AGT subsystems (R2–R9, T7, T10)."""

from __future__ import annotations

import os
from typing import Any

from governance_credentials import bootstrap_credential_vault, resolve_credential_scope
from governance_drift import combined_drift_score, compute_semantic_drift
from governance_identity import (
    bootstrap_identities,
    delegation_scope,
    delegation_token,
    extract_delegation_token,
    get_agent_did,
    verify_delegation_token,
)
from governance_intent import check_tool_intent, ensure_session_intent
from governance_session import SessionState

_bootstrapped = False


def phase2_enabled() -> bool:
    return os.getenv("GOVERNANCE_PHASE2", "1").lower() not in ("0", "false", "no")


def bootstrap_phase2(*, allowed_tools: list[str]) -> None:
    global _bootstrapped
    if _bootstrapped or not phase2_enabled():
        return
    main, _research = bootstrap_identities(allowed_tools=allowed_tools)
    bootstrap_credential_vault(agent_did=str(main.did))
    _bootstrapped = True


def resolve_runtime_agent_id(*, fallback: str) -> str:
    if not phase2_enabled() or not _bootstrapped:
        return fallback
    return get_agent_did()


def enrich_session_for_tool(
    state: SessionState,
    *,
    tool_name: str,
    args: dict[str, Any],
    request_id: str,
    allowed_tools: list[str],
) -> None:
    if not phase2_enabled():
        return

    if state.session_intent:
        if not state.intent_id:
            state.intent_id = ensure_session_intent(
                session_id=state.session_id,
                intent_text=state.session_intent,
                allowed_tools=allowed_tools,
            )
        if state.intent_id:
            intent_fields = check_tool_intent(
                intent_id=state.intent_id,
                tool_name=tool_name,
                args=args,
                request_id=request_id,
            )
            state.intent_allowed = bool(intent_fields["intent_allowed"])
            state.intent_was_planned = bool(intent_fields["intent_was_planned"])
            state.intent_drift_score = float(intent_fields["intent_drift_score"])

    semantic = compute_semantic_drift(
        session_intent=state.session_intent,
        tool_name=tool_name,
        args=args,
    )
    state.semantic_drift_score = combined_drift_score(
        semantic=semantic,
        intent_drift=state.intent_drift_score,
    )
    state.drift_score = state.semantic_drift_score

    state.credential_scope = resolve_credential_scope(
        tool_name=tool_name,
        args=args,
        agent_did=get_agent_did(),
        fallback_scope=state.credential_scope,
    )


def enrich_session_for_input(state: SessionState, *, allowed_tools: list[str]) -> None:
    if not phase2_enabled():
        return

    state.agent_did = get_agent_did()
    if state.session_intent and not state.intent_id:
        state.intent_id = ensure_session_intent(
            session_id=state.session_id,
            intent_text=state.session_intent,
            allowed_tools=allowed_tools,
        )

    if state.delegated_from and not state.delegation_verified:
        token = state.delegation_token
        auto = os.getenv("GOVERNANCE_DELEGATION_AUTO", "1").lower() not in ("0", "false", "no")
        verified = _accept_delegation_token(state, token) if token else False
        if not verified and auto and state.delegated_from in {"research-agent", "research agent"}:
            # Demo token (default mode only): it authorizes every catalog tool, so default mode
            # does not restrict a delegated session. Strict mode (AUTO=0) never reaches this branch.
            _accept_delegation_token(state, delegation_token(",".join(allowed_tools)), store=True)


def _accept_delegation_token(state: SessionState, token: str, *, store: bool = False) -> bool:
    """Verify ``token`` and record the result and the tools it authorizes on the session."""
    if store:
        state.delegation_token = token
    verified = verify_delegation_token(token)
    state.delegation_verified = verified
    state.delegation_scope = delegation_scope(token) if verified else []
    return verified


def ingest_delegation_from_message(state: SessionState, text: str) -> None:
    token = extract_delegation_token(text)
    if token:
        state.delegation_token = token
        _accept_delegation_token(state, token)
