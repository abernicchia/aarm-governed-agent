"""Build a Microsoft Agent Framework agent with AGT governance middleware."""

from __future__ import annotations

import os
from typing import Any

from agent_framework import Agent
from agent_os.integrations.maf_adapter import (
    AuditTrailMiddleware,
    CapabilityGuardMiddleware,
    GovernancePolicyMiddleware,
    create_governance_middleware,
)

from rego_runtime import build_rego_runtime_factory
from governance_policy import (
    bootstrap_governance_runtime,
    build_approval_resolver,
    build_governance_policy,
)
from governance_audit import GovernedAuditLog, build_audit_sink
from governance_kernel import patch_middleware_kernel
from governance_middleware import GovernedAuditTrailMiddleware, GovernedCapabilityGuardMiddleware
from streaming_governance import StreamingGovernancePolicyMiddleware
from rogue_detection_config import apply_rogue_demo_config
from tools import ALLOWED_TOOLS, TOOLS

AGENT_ID = "governed-assistant"
AGENT_NAME = "Governed Assistant"


def build_audit_log() -> GovernedAuditLog:
    """Shared audit log with optional signed file sink and OTEL mirroring."""
    return GovernedAuditLog(sink=build_audit_sink())


def build_governance_stack() -> list[Any]:
    bootstrap_governance_runtime()
    approval_resolver = build_approval_resolver()
    stack = create_governance_middleware(
        policy=build_governance_policy(),
        allowed_tools=ALLOWED_TOOLS,
        agent_id=AGENT_ID,
        enable_rogue_detection=True,
        approval_resolver=approval_resolver,
        audit_log=build_audit_log(),
        _runtime_factory=build_rego_runtime_factory(approval_resolver=approval_resolver),
    )
    stack = apply_rogue_demo_config(stack, agent_id=AGENT_ID)
    upgraded = [_upgrade_middleware(middleware) for middleware in stack]
    return [patch_middleware_kernel(middleware) for middleware in upgraded]


def _upgrade_middleware(middleware: Any) -> Any:
    if isinstance(middleware, GovernedAuditTrailMiddleware):
        return middleware
    if isinstance(middleware, AuditTrailMiddleware):
        return GovernedAuditTrailMiddleware(
            audit_log=middleware.audit_log,
            agent_did=middleware.agent_did,
        )
    if isinstance(middleware, GovernedCapabilityGuardMiddleware):
        return middleware
    if isinstance(middleware, CapabilityGuardMiddleware):
        return GovernedCapabilityGuardMiddleware(
            allowed_tools=middleware.allowed_tools,
            denied_tools=middleware.denied_tools,
            audit_log=middleware.audit_log,
            kernel=middleware.kernel,
            agent_id=middleware._agent_id,
        )
    if isinstance(middleware, GovernancePolicyMiddleware):
        return _upgrade_policy_middleware(middleware)
    return middleware


def _upgrade_policy_middleware(middleware: Any) -> Any:
    """Use streaming-aware policy denial for the Foundry Responses host."""
    if not isinstance(middleware, GovernancePolicyMiddleware):
        return middleware
    return StreamingGovernancePolicyMiddleware(
        evaluator=middleware.evaluator,
        audit_log=middleware.audit_log,
        kernel=middleware.kernel,
        agent_id=middleware._agent_id,
    )


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
