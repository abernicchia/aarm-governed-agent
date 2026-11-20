"""OPA/Rego-backed ACS runtime (`AgentControl`) for the governance middleware."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import yaml
from agent_control_specification import AgentControl, ApprovalResolver

from acs_host import DEFAULT_APPROVAL_TIMEOUT_SECONDS, AcsHost

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


def approval_timeout_from_manifest(manifest_path: Path) -> float:
    """Read `approval.timeout_seconds`; invalid or missing values use the ACS default."""
    manifest: Any = yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
    approval = manifest.get("approval") if isinstance(manifest, dict) else None
    raw = approval.get("timeout_seconds") if isinstance(approval, dict) else None
    if isinstance(raw, (int, float)) and not isinstance(raw, bool) and raw > 0:
        return float(raw)
    return DEFAULT_APPROVAL_TIMEOUT_SECONDS


def build_acs_host(
    *,
    manifest_path: Path | str | None = None,
    approval_resolver: ApprovalResolver | None = None,
) -> AcsHost:
    """Load the ACS manifest into `AgentControl` and wrap it in the host seam."""
    ensure_rego_bundle()
    path = configure_rego_runtime() if manifest_path is None else Path(manifest_path).resolve()
    control = AgentControl.from_path(str(path), approval_resolver=approval_resolver)
    return AcsHost(
        control,
        approval_resolver=approval_resolver,
        approval_timeout_seconds=approval_timeout_from_manifest(path),
    )
