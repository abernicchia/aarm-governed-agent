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
    vault = get_credential_vault()
    vault.put("db-read", os.getenv("GOVERNANCE_DB_READ_TOKEN", "readonly-db-token"))
    vault.put("db-write", os.getenv("GOVERNANCE_DB_WRITE_TOKEN", "write-db-token"))
    vault.register_profile(
        CredentialProfile(
            agent_did=agent_did,
            bindings={
                "database:read": "db-read",
                "database:write": "db-write",
            },
        )
    )
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
