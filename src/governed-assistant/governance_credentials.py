"""CredentialVault integration for Phase 2 (R9)."""

from __future__ import annotations

import os
from typing import Any

from agent_os.credential_vault import CredentialProfile, CredentialVault

from governance_identity import get_agent_did

_vault: CredentialVault | None = None


def get_credential_vault() -> CredentialVault:
    global _vault
    if _vault is None:
        _vault = CredentialVault()
    return _vault


def bootstrap_credential_vault(*, agent_did: str) -> CredentialVault:
    """Bind database capabilities for the agent (S24, least privilege).

    ``database:read`` is always bound. ``database:write`` is bound only when
    ``GOVERNANCE_DB_WRITE_TOKEN`` is set, so write scope is an explicit grant
    and not the default.
    """
    vault = get_credential_vault()
    vault.put("db-read", os.getenv("GOVERNANCE_DB_READ_TOKEN", "readonly-db-token"))
    bindings = {"database:read": "db-read"}

    write_token = os.getenv("GOVERNANCE_DB_WRITE_TOKEN", "").strip()
    if write_token:
        vault.put("db-write", write_token)
        bindings["database:write"] = "db-write"

    vault.register_profile(CredentialProfile(agent_did=agent_did, bindings=bindings))
    return vault


def _write_sql(statement: str) -> bool:
    lower = statement.lower().strip()
    return lower.startswith(("update", "delete", "insert", "drop"))


def resolve_credential_scope(
    *,
    tool_name: str,
    args: dict[str, Any],
    agent_did: str,
    fallback_scope: str = "read",
) -> str:
    if tool_name != "query_database":
        return fallback_scope

    statement = str(args.get("statement", ""))
    if _write_sql(statement):
        handle = "db-write"
        action_class = "database:write"
        resolved = "write"
    else:
        handle = "db-read"
        action_class = "database:read"
        resolved = "read"

    vault = get_credential_vault()
    if vault.check_access(agent_did, handle, action_class):
        return resolved
    return fallback_scope if resolved == "read" else "read"
