"""IntentManager integration for Phase 2 (R2, R3, R7)."""

from __future__ import annotations

import asyncio
import os
import re
from typing import Any

from agent_os.intent import DriftPolicy, IntentAction, IntentManager

from governance_identity import get_agent_did

_READ_ONLY_MARKERS = {"read-only", "readonly", "calculator", "time only", "math/time"}
_READ_ONLY_TOOLS = ("calculator", "get_current_time")

_manager: IntentManager | None = None


def get_intent_manager() -> IntentManager:
    global _manager
    if _manager is None:
        from agent_os.stateless import MemoryBackend

        _manager = IntentManager(backend=MemoryBackend())
    return _manager


def _run_async(coro: Any) -> Any:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


def intent_is_read_only(intent_text: str) -> bool:
    lower = intent_text.lower()
    return any(marker in lower for marker in _READ_ONLY_MARKERS)


def planned_actions_from_intent(intent_text: str, *, allowed_tools: list[str]) -> list[IntentAction]:
    if intent_is_read_only(intent_text):
        return [IntentAction(action=name) for name in _READ_ONLY_TOOLS]
    return [
        IntentAction(action=name)
        for name in allowed_tools
        if name != "shell_execute"
    ]


def drift_policy_for_intent(intent_text: str) -> DriftPolicy:
    override = os.getenv("GOVERNANCE_INTENT_DRIFT_POLICY", "").strip().lower()
    if override in {p.value for p in DriftPolicy}:
        return DriftPolicy(override)
    if intent_is_read_only(intent_text):
        return DriftPolicy.HARD_BLOCK
    return DriftPolicy.SOFT_BLOCK


async def _ensure_intent_async(
    *,
    session_id: str,
    intent_text: str,
    allowed_tools: list[str],
) -> str:
    manager = get_intent_manager()
    agent_id = get_agent_did()
    key = f"session-intent:{session_id}"
    existing = await manager._backend.get(f"agt:{key}")  # noqa: SLF001
    if existing and isinstance(existing, dict) and existing.get("intent_id"):
        return str(existing["intent_id"])

    planned = planned_actions_from_intent(intent_text, allowed_tools=allowed_tools)
    intent = await manager.declare_intent(
        agent_id=agent_id,
        planned_actions=planned,
        drift_policy=drift_policy_for_intent(intent_text),
        ttl_seconds=3600,
    )
    if os.getenv("GOVERNANCE_INTENT_AUTO_APPROVE", "1").lower() not in ("0", "false", "no"):
        intent = await manager.approve_intent(intent.intent_id)
    await manager._backend.set(  # noqa: SLF001
        f"agt:{key}",
        {"intent_id": intent.intent_id, "intent_text": intent_text},
        ttl=7200,
    )
    return intent.intent_id


def ensure_session_intent(
    *,
    session_id: str,
    intent_text: str,
    allowed_tools: list[str],
) -> str | None:
    if not intent_text.strip():
        return None
    return _run_async(
        _ensure_intent_async(
            session_id=session_id,
            intent_text=intent_text,
            allowed_tools=allowed_tools,
        )
    )


async def _check_tool_async(
    *,
    intent_id: str,
    tool_name: str,
    args: dict[str, Any],
    request_id: str,
) -> dict[str, Any]:
    manager = get_intent_manager()
    check = await manager.check_action(
        intent_id,
        tool_name,
        args,
        get_agent_did(),
        request_id,
    )
    drift_score = 0.0
    if not check.was_planned and check.trust_penalty:
        drift_score = min(1.0, check.trust_penalty / 100.0)
    elif not check.was_planned and not check.allowed:
        drift_score = 1.0
    return {
        "intent_allowed": check.allowed,
        "intent_was_planned": check.was_planned,
        "intent_drift_score": drift_score,
        "intent_check_reason": check.reason or "",
    }


def check_tool_intent(
    *,
    intent_id: str | None,
    tool_name: str,
    args: dict[str, Any],
    request_id: str,
) -> dict[str, Any]:
    if not intent_id:
        return {
            "intent_allowed": True,
            "intent_was_planned": True,
            "intent_drift_score": 0.0,
            "intent_check_reason": "",
        }
    return _run_async(
        _check_tool_async(
            intent_id=intent_id,
            tool_name=tool_name,
            args=args,
            request_id=request_id,
        )
    )


def extract_intent_summary(intent_text: str) -> str:
    cleaned = re.sub(r"\s+", " ", intent_text.strip())
    return cleaned[:240]
