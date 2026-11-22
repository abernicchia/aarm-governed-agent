"""Rogue-detection tuning for AARM Scenario 7 demos."""

from __future__ import annotations

import os
from typing import Any

from agent_os.integrations.maf_adapter import RogueDetectionMiddleware

from tools import ALLOWED_TOOLS

# The capability profile must match the policy's allow-list (tools.ALLOWED_TOOLS).
# A narrower profile made any allowed-but-unlisted tool (write_file, send_email, ...)
# a capability violation: as the first call after a restart it scored 1.00 and was
# quarantined at MEDIUM risk, even though the policy allowed it.
AGENT_BASELINE_TOOLS = list(ALLOWED_TOOLS)


def rogue_demo_mode_enabled() -> bool:
    """Use demo-friendly rogue thresholds (default on for this sample project)."""
    return os.getenv("GOVERNANCE_ROGUE_DEMO", "1").lower() not in ("0", "false", "no")


def build_demo_rogue_detector() -> Any:
    """Detector tuned for the multi-turn Scenario 7 script."""
    from agent_sre.anomaly.rogue_detector import (
        RiskLevel,
        RogueAgentDetector,
        RogueDetectorConfig,
    )

    return RogueAgentDetector(
        config=RogueDetectorConfig(
            # Stock thresholds need long sessions (5+ minute windows, entropy >3.5).
            # Tuned for run-scenario-7.sh: forced calculator warmup + first spam turn.
            frequency_window_seconds=30.0,
            frequency_z_threshold=1.0,
            frequency_min_windows=2,
            entropy_min_actions=10,
            entropy_high_threshold=0.45,
            quarantine_risk_level=RiskLevel.MEDIUM,
        )
    )


def build_rogue_detection_middleware(*, agent_id: str, audit_log: Any | None) -> RogueDetectionMiddleware:
    """Rogue-detection middleware; demo thresholds when GOVERNANCE_ROGUE_DEMO is enabled."""
    if not rogue_demo_mode_enabled():
        from agent_sre.anomaly.rogue_detector import RogueAgentDetector, RogueDetectorConfig

        return RogueDetectionMiddleware(
            detector=RogueAgentDetector(config=RogueDetectorConfig()),
            agent_id=agent_id,
            audit_log=audit_log,
        )

    return RogueDetectionMiddleware(
        detector=build_demo_rogue_detector(),
        agent_id=agent_id,
        capability_profile={"allowed_tools": AGENT_BASELINE_TOOLS},
        audit_log=audit_log,
    )
