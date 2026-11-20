"""Semantic drift scoring for Phase 2 (R7)."""

from __future__ import annotations

import os
from typing import Any

from agent_os.semantic_policy import IntentCategory, SemanticPolicyEngine

from governance_intent import intent_is_read_only

_engine: SemanticPolicyEngine | None = None


def get_semantic_engine() -> SemanticPolicyEngine:
    global _engine
    if _engine is None:
        _engine = SemanticPolicyEngine(
            deny=[
                IntentCategory.DESTRUCTIVE_DATA,
                IntentCategory.DATA_EXFILTRATION,
                IntentCategory.PRIVILEGE_ESCALATION,
                IntentCategory.SYSTEM_MODIFICATION,
                IntentCategory.CODE_EXECUTION,
            ],
            confidence_threshold=0.5,
        )
    return _engine


def drift_threshold() -> float:
    raw = os.getenv("GOVERNANCE_DRIFT_THRESHOLD", "0.7").strip()
    try:
        return float(raw)
    except ValueError:
        return 0.7


def compute_semantic_drift(
    *,
    session_intent: str | None,
    tool_name: str,
    args: dict[str, Any],
) -> float:
    if not session_intent:
        return 0.0

    engine = get_semantic_engine()
    classification = engine.classify(tool_name, args)

    if intent_is_read_only(session_intent) and classification.is_dangerous:
        return classification.confidence

    if classification.category in {
        IntentCategory.DATA_EXFILTRATION,
        IntentCategory.CODE_EXECUTION,
    }:
        return classification.confidence * 0.5

    return 0.0


def combined_drift_score(*, semantic: float, intent_drift: float) -> float:
    return max(semantic, intent_drift)
