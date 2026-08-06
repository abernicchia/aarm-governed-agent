"""Patch agent_framework_openai content-filter handling for Azure Foundry.

Foundry can return innererror.code="ContentFiltered" on jailbreak detection.
The stock SDK enum only defines ResponsibleAIPolicyViolation, which raises
ValueError and surfaces as a server_error instead of a content-filter response.
"""

from __future__ import annotations

from enum import Enum

_applied = False


def apply_content_filter_patch() -> None:
    """Register Foundry's ContentFiltered code on the SDK enum (idempotent)."""
    global _applied
    if _applied:
        return

    import agent_framework_openai._exceptions as openai_exceptions

    existing = openai_exceptions.ContentFilterCodes

    members = {member.name: member.value for member in existing}
    members.setdefault("CONTENT_FILTERED", "ContentFiltered")

    patched = Enum("ContentFilterCodes", members, type=str)
    openai_exceptions.ContentFilterCodes = patched  # type: ignore[misc, assignment]

    _applied = True
