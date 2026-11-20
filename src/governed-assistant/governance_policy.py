"""Governance runtime configuration (approval resolver, manifest bootstrap)."""

from __future__ import annotations

import os

from agent_control_specification import (
    ApprovalResolution,
    ApprovalResolver,
    InterventionPoint,
    InterventionPointResult,
)

from rego_runtime import configure_rego_runtime


def build_approval_resolver(*, auto_approve: bool | None = None) -> ApprovalResolver:
    """Return the ACS approval resolver for STEP_UP verdicts."""
    if auto_approve is None:
        auto_approve = os.getenv("GOVERNANCE_AUTO_APPROVE", "").lower() in ("1", "true", "yes")

    def resolver(
        _intervention_point: InterventionPoint,
        result: InterventionPointResult,
    ) -> ApprovalResolution:
        # ACS binds the approval to the evaluated action; an identity that
        # differs from `result.enforced_identity` fails closed.
        if auto_approve and result.enforced_identity:
            return ApprovalResolution.allow(result.enforced_identity)
        return ApprovalResolution.deny()

    return resolver


def bootstrap_governance_runtime() -> None:
    """Validate ACS manifest and Rego bundle are present."""
    configure_rego_runtime()
