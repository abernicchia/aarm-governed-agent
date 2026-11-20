#!/usr/bin/env bash
# Phase 2 conformance gate — Mesh identity, IntentManager, vault, post_tool_call.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}/src/governed-assistant"

export GOVERNANCE_PHASE2=1
export GOVERNANCE_AUDIT_STDOUT=0
export GOVERNANCE_OTEL_AUDIT=0
export GOVERNANCE_INTENT_AUTO_APPROVE=1

echo "== Phase 2: OPA bundle check =="
opa check "${ROOT}/policies/rego/"

echo "== Phase 2: pytest suite =="
python -m pytest tests/test_phase2_governance.py -v

echo "== Phase 2: optional agt verify =="
if command -v agt >/dev/null 2>&1; then
  agt verify || true
fi

echo "Phase 2 conformance checks completed."
