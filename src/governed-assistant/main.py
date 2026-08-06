# Copyright (c) Microsoft. All rights reserved.

"""Hosted agent entry point for Azure AI Foundry (Responses protocol)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from agent_factory import create_agent, create_foundry_client
from agent_framework_foundry_hosting import ResponsesHostServer
from content_filter_patch import apply_content_filter_patch
from dotenv import load_dotenv
from opentelemetry.environment_variables import (
    OTEL_LOGS_EXPORTER,
    OTEL_METRICS_EXPORTER,
    OTEL_TRACES_EXPORTER,
)


def _otel_exporter_disabled(env_var: str) -> bool:
    return os.environ.get(env_var, "").lower().strip() == "none"


def _local_observability_disabled() -> bool:
    """True when local .env disables all OTEL exporters (no App Insights)."""
    return (
        _otel_exporter_disabled(OTEL_TRACES_EXPORTER)
        and _otel_exporter_disabled(OTEL_METRICS_EXPORTER)
        and _otel_exporter_disabled(OTEL_LOGS_EXPORTER)
    )


def _configure_console_logging_only(*, log_level: str | None = None) -> None:
    """Attach console logging without initializing the OTEL distro."""
    import logging

    import azure.ai.agentserver.core._config as agent_config

    resolved_level = agent_config.resolve_log_level(log_level)
    root = logging.getLogger()
    root.setLevel(resolved_level)

    console_handler_attr = "_agentserver_console"
    has_console = any(
        getattr(handler, console_handler_attr, False)
        or (
            isinstance(handler, logging.StreamHandler)
            and not isinstance(handler, logging.FileHandler)
        )
        for handler in root.handlers
    )
    if not has_console:
        console = logging.StreamHandler()
        console.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
        )
        setattr(console, console_handler_attr, True)
        root.addHandler(console)

    if logging.getLevelName(resolved_level) > logging.DEBUG:
        for noisy in (
            "azure.monitor.opentelemetry.exporter",
            "azure.core.pipeline.policies.http_logging_policy",
        ):
            logging.getLogger(noisy).setLevel(logging.WARNING)


def configure_observability(**kwargs: Any) -> None:
    """Configure logging/tracing; suppress noisy console OTEL export locally."""
    import azure.ai.agentserver.core._tracing as tracing

    connection_string = kwargs.get("connection_string")
    if connection_string:
        tracing.configure_observability(**kwargs)
        return

    if _local_observability_disabled():
        # OTEL_TRACES_EXPORTER=none leaves a ProxyTracerProvider with no
        # add_span_processor; skip the distro entirely for quiet local runs.
        _configure_console_logging_only(log_level=kwargs.get("log_level"))
        return

    import microsoft.opentelemetry as ms_otel

    original_use = ms_otel.use_microsoft_opentelemetry

    def _local_use_microsoft_opentelemetry(**otel_kwargs: Any) -> None:
        # Without App Insights locally, the distro auto-enables console export
        # and prints large JSON trace/metric blobs (including harmless IMDS errors).
        otel_kwargs.setdefault("enable_console", False)
        if _otel_exporter_disabled(OTEL_METRICS_EXPORTER):
            otel_kwargs.setdefault("disable_metrics", True)
        if _otel_exporter_disabled(OTEL_TRACES_EXPORTER):
            otel_kwargs.setdefault("disable_tracing", True)
        if _otel_exporter_disabled(OTEL_LOGS_EXPORTER):
            otel_kwargs.setdefault("disable_logging", True)
        if otel_kwargs.get("disable_tracing"):
            inst_opts = dict(otel_kwargs.get("instrumentation_options") or {})
            for lib in (
                "agent_framework",
                "semantic_kernel",
                "langchain",
                "openai_agents",
            ):
                inst_opts.setdefault(lib, {}).setdefault("enabled", False)
            otel_kwargs["instrumentation_options"] = inst_opts
        original_use(**otel_kwargs)

    ms_otel.use_microsoft_opentelemetry = _local_use_microsoft_opentelemetry
    try:
        tracing.configure_observability(**kwargs)
    finally:
        ms_otel.use_microsoft_opentelemetry = original_use


def main() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    load_dotenv(repo_root / ".env")
    apply_content_filter_patch()
    agent = create_agent(create_foundry_client())
    server = ResponsesHostServer(agent, configure_observability=configure_observability)
    server.run()


if __name__ == "__main__":
    main()
