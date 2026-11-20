"""Per-session governance context for AARM scenarios 12–20 and Phase 2 (21–28)."""

from __future__ import annotations

import os
import re
import threading
from dataclasses import dataclass, field
from typing import Any

from governance_identity import hash_action

_INTENT_PREFIX = re.compile(r"^\s*INTENT:\s*(.+?)(?:\s*$|\s+(?=\S))", re.IGNORECASE | re.DOTALL)
_DELEGATION_PATTERNS = (
    re.compile(r"research agent", re.IGNORECASE),
    re.compile(r"planner agent", re.IGNORECASE),
    re.compile(r"delegated from\s+([a-z0-9_-]+)", re.IGNORECASE),
)
_POISON_MARKERS = (
    "always approve shell_execute",
    "ignore all policies",
    "disable governance",
)

_LOCK = threading.Lock()
_SESSIONS: dict[str, SessionState] = {}


@dataclass
class SessionState:
    session_id: str
    session_intent: str | None = None
    credential_scope: str = "read"
    read_file_count: int = 0
    delegated_from: str | None = None
    poisoned_context: bool = False
    prior_tools: list[str] = field(default_factory=list)
    conversation_thread: list[dict[str, str]] = field(default_factory=list)
    action_history: list[dict[str, str]] = field(default_factory=list)
    agent_did: str = ""
    intent_id: str | None = None
    intent_allowed: bool = True
    intent_was_planned: bool = True
    intent_drift_score: float = 0.0
    semantic_drift_score: float = 0.0
    drift_score: float = 0.0
    delegation_token: str | None = None
    delegation_verified: bool = False

    def apply_env_defaults(self) -> None:
        if self.session_intent is None:
            env_intent = os.getenv("GOVERNANCE_SESSION_INTENT", "").strip()
            if env_intent:
                self.session_intent = env_intent
        if not os.getenv("GOVERNANCE_PHASE2", "1").lower() in ("0", "false", "no"):
            return
        env_scope = os.getenv("GOVERNANCE_CREDENTIAL_SCOPE", "").strip().lower()
        if env_scope:
            self.credential_scope = env_scope

    def ingest_user_message(self, text: str) -> None:
        if not text:
            return
        match = _INTENT_PREFIX.match(text.strip())
        if match:
            self.session_intent = match.group(1).strip()
        delegated = parse_delegated_from(text)
        if delegated:
            self.delegated_from = delegated
        self.append_conversation_turn("user", text)
        try:
            from governance_phase2 import ingest_delegation_from_message

            ingest_delegation_from_message(self, text)
        except Exception:
            pass

    def append_conversation_turn(self, role: str, text: str) -> None:
        if not text:
            return
        self.conversation_thread.append({"role": role, "text": str(text)[:500]})
        if len(self.conversation_thread) > 20:
            self.conversation_thread = self.conversation_thread[-20:]

    def record_tool_completion(self, tool_name: str, result: Any, *, args: dict | None = None) -> None:
        self.prior_tools.append(tool_name)
        if tool_name == "read_file":
            self.read_file_count += 1
        result_text = str(result or "")
        if any(marker in result_text.lower() for marker in _POISON_MARKERS):
            self.poisoned_context = True
        self.action_history.append(
            {
                "tool": tool_name,
                "args_hash": hash_action(tool_name, args or {}),
                "outcome": "complete",
            }
        )
        if len(self.action_history) > 30:
            self.action_history = self.action_history[-30:]
        self.append_conversation_turn("tool", f"{tool_name}: {result_text[:400]}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_intent": self.session_intent or "",
            "credential_scope": self.credential_scope,
            "read_file_count": self.read_file_count,
            "delegated_from": self.delegated_from or "",
            "poisoned_context": self.poisoned_context,
            "prior_tools": list(self.prior_tools),
            "conversation_thread": list(self.conversation_thread),
            "action_history": list(self.action_history),
            "agent_did": self.agent_did or "",
            "intent_id": self.intent_id or "",
            "intent_allowed": self.intent_allowed,
            "intent_was_planned": self.intent_was_planned,
            "intent_drift_score": self.intent_drift_score,
            "semantic_drift_score": self.semantic_drift_score,
            "drift_score": self.drift_score,
            "delegation_verified": self.delegation_verified,
            "delegation_token_present": bool(self.delegation_token),
        }


def get_session_state(session_id: str | None) -> SessionState:
    key = session_id or "default-session"
    with _LOCK:
        state = _SESSIONS.get(key)
        if state is None:
            state = SessionState(session_id=key)
            _SESSIONS[key] = state
        state.apply_env_defaults()
        return state


def reset_session_state(session_id: str | None = None) -> None:
    with _LOCK:
        if session_id is None:
            _SESSIONS.clear()
        else:
            _SESSIONS.pop(session_id, None)


def parse_delegated_from(text: str) -> str | None:
    if not text:
        return None
    for pattern in _DELEGATION_PATTERNS:
        match = pattern.search(text)
        if match:
            if match.lastindex:
                return match.group(1).strip()
            return "research-agent"
    return None


def inject_governance_snapshot(snapshot: dict[str, Any], session_id: str | None) -> dict[str, Any]:
    enriched = dict(snapshot)
    governance = get_session_state(session_id).to_dict()
    enriched["governance"] = governance
    envelope = dict(enriched.get("envelope", {}))
    envelope["governance"] = governance
    enriched["envelope"] = envelope
    return enriched
