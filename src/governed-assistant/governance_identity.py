"""Agent Mesh cryptographic identity for Phase 2 (R5, R6)."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from agentmesh.identity.agent_id import AgentDID, AgentIdentity
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

_REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_IDENTITY_DIR = _REPO_ROOT / ".governance" / "identities"

_MAIN_IDENTITY_FILE = "governed-assistant.json"
_RESEARCH_IDENTITY_FILE = "research-agent.json"

_MAIN: AgentIdentity | None = None
_RESEARCH: AgentIdentity | None = None


def identity_dir() -> Path:
    override = os.getenv("GOVERNANCE_IDENTITY_DIR", "").strip()
    if override:
        return Path(override).resolve()
    return DEFAULT_IDENTITY_DIR


def _private_key_to_b64(private_key: ed25519.Ed25519PrivateKey) -> str:
    raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return base64.b64encode(raw).decode()


def _private_key_from_b64(value: str) -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.from_private_bytes(base64.b64decode(value))


def save_identity(path: Path, identity: AgentIdentity) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = identity.model_dump(mode="json")
    if identity._private_key is not None:
        payload["_private_key_b64"] = _private_key_to_b64(identity._private_key)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def load_identity(path: Path) -> AgentIdentity:
    raw = json.loads(path.read_text(encoding="utf-8"))
    private_b64 = raw.pop("_private_key_b64", None)
    did = AgentDID.from_string(raw["did"]) if isinstance(raw.get("did"), str) else raw["did"]
    raw["did"] = did
    identity = AgentIdentity(**raw)
    if private_b64:
        identity._private_key = _private_key_from_b64(private_b64)
    return identity


def load_or_create_identity(
    *,
    file_name: str,
    name: str,
    sponsor: str,
    capabilities: list[str],
    factory: Any | None = None,
) -> AgentIdentity:
    path = identity_dir() / file_name
    if path.is_file():
        return load_identity(path)

    if factory is not None:
        identity = factory()
    else:
        identity = AgentIdentity.create(
            name=name,
            sponsor=sponsor,
            capabilities=capabilities,
        )
    save_identity(path, identity)
    return identity


def bootstrap_identities(*, allowed_tools: list[str]) -> tuple[AgentIdentity, AgentIdentity]:
    global _MAIN, _RESEARCH
    if _MAIN is not None and _RESEARCH is not None:
        return _MAIN, _RESEARCH

    sponsor = os.getenv("GOVERNANCE_SPONSOR_EMAIL", "demo@sailpoint.com")
    caps = list(allowed_tools) + ["database:read", "database:write"]
    main = load_or_create_identity(
        file_name=_MAIN_IDENTITY_FILE,
        name="Governed Assistant",
        sponsor=sponsor,
        capabilities=caps,
    )

    research_path = identity_dir() / _RESEARCH_IDENTITY_FILE
    if research_path.is_file():
        research = load_identity(research_path)
    else:
        research = main.delegate(
            "Research Agent",
            capabilities=["read_file", "http_request"],
            description="Delegated research sub-agent for multi-agent demos",
        )
        save_identity(research_path, research)

    _MAIN = main
    _RESEARCH = research
    return main, research


def get_main_identity() -> AgentIdentity:
    if _MAIN is None:
        raise RuntimeError("Phase 2 identities not bootstrapped")
    return _MAIN


def get_research_identity() -> AgentIdentity:
    if _RESEARCH is None:
        raise RuntimeError("Phase 2 identities not bootstrapped")
    return _RESEARCH


def get_agent_did() -> str:
    return str(get_main_identity().did)


def sign_payload(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return get_main_identity().sign(canonical)


def sign_audit_fields(entry_id: str, event_type: str, agent_did: str) -> dict[str, str]:
    payload = {
        "entry_id": entry_id,
        "event_type": event_type,
        "agent_did": agent_did,
    }
    return {
        "mesh.did": agent_did,
        "mesh.signature": sign_payload(payload),
        "mesh.key_id": get_main_identity().verification_key_id,
    }


def verify_identity_signature(identity: AgentIdentity, payload: dict[str, Any], signature: str) -> bool:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return identity.verify_signature(canonical, signature)


def delegation_token(scope: str, *, executor_did: str | None = None) -> str:
    """Issue a signed delegation authorizing ``scope`` for the main agent."""
    research = get_research_identity()
    target = executor_did or get_agent_did()
    payload = {
        "delegator": str(research.did),
        "executor": target,
        "scope": scope,
    }
    signature = research.sign(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    )
    return base64.urlsafe_b64encode(
        json.dumps({"payload": payload, "signature": signature}).encode()
    ).decode()


def parse_delegation_token(token: str) -> tuple[dict[str, Any], str] | None:
    try:
        decoded = base64.urlsafe_b64decode(token.encode())
        envelope = json.loads(decoded.decode())
        payload = envelope.get("payload")
        signature = envelope.get("signature")
        if not isinstance(payload, dict) or not isinstance(signature, str):
            return None
        return payload, signature
    except Exception:
        return None


def verify_delegation_token(token: str, *, executor_did: str | None = None) -> bool:
    parsed = parse_delegation_token(token)
    if parsed is None:
        return False
    payload, signature = parsed
    research = get_research_identity()
    if str(research.did) != payload.get("delegator"):
        return False
    target = executor_did or get_agent_did()
    if payload.get("executor") != target:
        return False
    return verify_identity_signature(research, payload, signature)


def extract_delegation_token(text: str) -> str | None:
    if not text:
        return None
    marker = "DELEGATION:"
    idx = text.upper().find(marker)
    if idx < 0:
        return None
    remainder = text[idx + len(marker) :].strip()
    token = remainder.split()[0].strip() if remainder else ""
    return token or None


def hash_action(tool_name: str, args: dict[str, Any]) -> str:
    blob = json.dumps({"tool": tool_name, "args": args}, sort_keys=True).encode()
    return hashlib.sha256(blob).hexdigest()[:16]
