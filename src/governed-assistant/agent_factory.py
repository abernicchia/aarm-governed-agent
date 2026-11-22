"""Build a Microsoft Agent Framework agent with AGT governance middleware."""

from __future__ import annotations

import os
from typing import Any

from agent_framework import Agent

from rego_runtime import build_acs_host
from governance_policy import bootstrap_governance_runtime, build_approval_resolver
from governance_audit import GovernedAuditLog, build_audit_sink
from governance_kernel import GovernanceKernel
from governance_middleware import GovernedAuditTrailMiddleware, GovernedCapabilityGuardMiddleware
from streaming_governance import StreamingGovernancePolicyMiddleware
from rogue_detection_config import build_rogue_detection_middleware
from governance_phase2 import bootstrap_phase2, phase2_enabled, resolve_runtime_agent_id
from tools import ALLOWED_TOOLS, TOOLS

AGENT_ID = "governed-assistant"
AGENT_NAME = "Governed Assistant"


def resolve_agent_id() -> str:
    return resolve_runtime_agent_id(fallback=AGENT_ID)


def build_audit_log() -> GovernedAuditLog:
    """Shared audit log with optional signed file sink and OTEL mirroring."""
    return GovernedAuditLog(sink=build_audit_sink())


def build_governance_stack() -> list[Any]:
    """Four-layer middleware stack (outer → inner) over the ACS runtime."""
    bootstrap_governance_runtime()
    if phase2_enabled():
        bootstrap_phase2(allowed_tools=ALLOWED_TOOLS)
    kernel = GovernanceKernel(build_acs_host(approval_resolver=build_approval_resolver()))
    audit_log = build_audit_log()
    # Resolve after bootstrap_phase2: with Phase 2 on this is the Mesh DID, so every receipt
    # carries ``did:mesh:…`` plus ``mesh.did`` / ``mesh.signature`` (AARM R6). It falls back to
    # the static AGENT_ID when Phase 2 is off.
    agent_id = resolve_agent_id()
    return [
        GovernedAuditTrailMiddleware(audit_log=audit_log, agent_did=agent_id),
        StreamingGovernancePolicyMiddleware(kernel=kernel, audit_log=audit_log, agent_id=agent_id),
        GovernedCapabilityGuardMiddleware(kernel=kernel, audit_log=audit_log, agent_id=agent_id),
        build_rogue_detection_middleware(agent_id=agent_id, audit_log=audit_log),
    ]


def create_agent(client: Any) -> Agent[Any]:
    return Agent(
        client=client,
        name=AGENT_NAME,
        instructions=(
            "You are a helpful assistant with calculator, time, file read/write, "
            "email, database query, HTTP, and customer update tools. Use tools when "
            "they help answer the user. "
            "When the user asks to update a customer record, call "
            "update_customer_record with the requested parameters — do not "
            "refuse or ask the user for governance approval yourself; the "
            "governance middleware enforces approval automatically at execution "
            "time. When the user asks to run a shell command, call shell_execute "
            "with the requested command — do not refuse on your own; governance "
            "policy blocks it automatically at execution time. When the user asks "
            "to read a file and upload or send it via http_request, call read_file "
            "then http_request with the requested URL — do not refuse on your own; "
            "governance policy blocks external hosts automatically at execution "
            "time. Do not bypass "
            "governance rules. When a destructive or ambiguous request is denied, "
            "ask the user for the missing details instead of guessing."
        ),
        tools=TOOLS,
        middleware=build_governance_stack(),
        default_options={"store": False},
    )


def create_foundry_client() -> Any:
    from agent_framework.foundry import FoundryChatClient
    from azure.identity import DefaultAzureCredential

    model_name = os.getenv("AZURE_AI_MODEL_DEPLOYMENT_NAME") or os.getenv("FOUNDRY_MODEL_NAME")
    if not model_name:
        raise RuntimeError(
            "Model deployment name is not configured. Set "
            "AZURE_AI_MODEL_DEPLOYMENT_NAME or FOUNDRY_MODEL_NAME."
        )

    project_endpoint = os.environ["FOUNDRY_PROJECT_ENDPOINT"]
    credential = DefaultAzureCredential(exclude_cli_credential=True)
    return FoundryChatClient(
        project_endpoint=project_endpoint,
        model=model_name,
        credential=credential,
    )
