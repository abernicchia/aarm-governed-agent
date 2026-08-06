"""Per-session governance context for AARM scenarios 12–20 (R2, R3, R9, T5)."""

from __future__ import annotations

import os
import re
import threading
from dataclasses import dataclass, field
from typing import Any

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

    def apply_env_defaults(self) -> None:
        if self.session_intent is None:
            env_intent = os.getenv("GOVERNANCE_SESSION_INTENT", "").strip()
            if env_intent:
                self.session_intent = env_intent
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

    def record_tool_completion(self, tool_name: str, result: Any) -> None:
        self.prior_tools.append(tool_name)
        if tool_name == "read_file":
            self.read_file_count += 1
        result_text = str(result or "")
        if any(marker in result_text.lower() for marker in _POISON_MARKERS):
            self.poisoned_context = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_intent": self.session_intent or "",
            "credential_scope": self.credential_scope,
            "read_file_count": self.read_file_count,
            "delegated_from": self.delegated_from or "",
            "poisoned_context": self.poisoned_context,
            "prior_tools": list(self.prior_tools),
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
