"""AGT 5.0 governance policy configuration (OPA/Rego-backed runtime)."""

from __future__ import annotations

import os
from typing import Any

from agent_os.integrations.base import GovernancePolicy

from tools import ALLOWED_TOOLS

from rego_runtime import configure_rego_runtime


def build_governance_policy() -> GovernancePolicy:
    """Build runtime configuration consumed by AgtRuntime."""
    return GovernancePolicy(
        name="governed-assistant-safety",
        version="2.1.0",
        max_tokens=4096,
        max_tool_calls=50,
        allowed_tools=list(ALLOWED_TOOLS),
        blocked_patterns=[],
        require_human_approval=True,
        drift_threshold=0.15,
        log_all_calls=True,
    )


def build_approval_resolver(*, auto_approve: bool | None = None) -> Any:
    """Return an approval callback for STEP_UP (escalate) verdicts."""
    from agt.policies.runtime import ApprovalDecision

    if auto_approve is None:
        auto_approve = os.getenv("GOVERNANCE_AUTO_APPROVE", "").lower() in ("1", "true", "yes")

    def resolver(_intervention_point: str, result: Any) -> ApprovalDecision:
        if auto_approve:
            identity = getattr(result, "enforced_identity", None) or "governed-assistant:approved"
            return ApprovalDecision("allow", enforced_identity=identity)
        return ApprovalDecision("deny")

    return resolver


def bootstrap_governance_runtime() -> None:
    """Validate ACS manifest and Rego bundle are present."""
    configure_rego_runtime()
