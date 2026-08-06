"""OPA/Rego-backed governance runtime for AGT 5.0 middleware."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any, Callable

from agent_os.integrations.base import GovernancePolicy

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = REPO_ROOT / "policies" / "manifest.yaml"
DEFAULT_BUNDLE = REPO_ROOT / "policies" / "rego"
STOCK_REGO_ROOT = REPO_ROOT / "policy-engine" / "policy" / "lib"


def ensure_rego_bundle(*, bundle_dir: Path | None = None) -> Path:
    """Ensure the Rego bundle contains the policy module and AGT stock library."""
    bundle = Path(bundle_dir or DEFAULT_BUNDLE).resolve()
    bundle.mkdir(parents=True, exist_ok=True)

    if not STOCK_REGO_ROOT.is_dir():
        raise RuntimeError(
            f"AGT stock Rego library not found at {STOCK_REGO_ROOT}. "
            "Ensure policy-engine/policy/lib exists in the repository."
        )

    for rego_file in STOCK_REGO_ROOT.glob("*.rego"):
        if rego_file.name.endswith("_test.rego"):
            continue
        dest = bundle / rego_file.name
        if not dest.exists() or rego_file.read_bytes() != dest.read_bytes():
            shutil.copy2(rego_file, dest)

    policy_file = bundle / "governed-assistant.rego"
    if not policy_file.is_file():
        raise RuntimeError(
            f"Rego policy not found at {policy_file}. "
            "Ensure policies/rego/governed-assistant.rego exists."
        )

    return bundle


def configure_rego_runtime() -> Path:
    """Validate manifest and Rego bundle; return manifest path."""
    import os

    env_manifest = os.environ.get("GOVERNANCE_MANIFEST")
    if env_manifest:
        manifest_path = Path(env_manifest).resolve()
        # azd injects the container path (/app/policies/...) for local runs.
        if not manifest_path.is_file() and DEFAULT_MANIFEST.is_file():
            manifest_path = DEFAULT_MANIFEST.resolve()
    else:
        manifest_path = DEFAULT_MANIFEST.resolve()

    if not manifest_path.is_file():
        raise RuntimeError(
            f"ACS manifest not found at {manifest_path}. "
            "Set GOVERNANCE_MANIFEST or ensure policies/manifest.yaml exists."
        )
    ensure_rego_bundle()
    return manifest_path


def build_rego_runtime_factory(
    *,
    manifest_path: Path | str | None = None,
    approval_resolver: Callable[..., Any] | None = None,
) -> Callable[[GovernancePolicy], Any]:
    """Return a runtime factory for MAFKernel / create_governance_middleware."""

    def factory(_governance_policy: GovernancePolicy) -> Any:
        from agt.policies.runtime import AgtRuntime

        ensure_rego_bundle()
        path = configure_rego_runtime() if manifest_path is None else Path(manifest_path).resolve()
        return AgtRuntime(str(path), approval_resolver=approval_resolver)

    return factory
