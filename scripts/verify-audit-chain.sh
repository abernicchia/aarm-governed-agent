#!/usr/bin/env bash
# Scenario 19 — verify tamper-evident audit chain (R5).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AUDIT_FILE="${GOVERNANCE_AUDIT_FILE:-$REPO_ROOT/.governance-audit.jsonl}"
SECRET="${GOVERNANCE_AUDIT_SECRET:-governed-assistant-demo-key}"

cd "$REPO_ROOT/src/governed-assistant"

export GOVERNANCE_SIGNED_AUDIT=1
export GOVERNANCE_AUDIT_STDOUT=0
export GOVERNANCE_AUDIT_FILE="$AUDIT_FILE"
export GOVERNANCE_AUDIT_SECRET="$SECRET"
export GOVERNANCE_AUTO_APPROVE=1

rm -f "$AUDIT_FILE"

python - <<'PY'
import asyncio
import os
from types import SimpleNamespace

from agent_factory import build_governance_stack
from governance_middleware import GovernedCapabilityGuardMiddleware

stack = build_governance_stack()
capability = next(m for m in stack if isinstance(m, GovernedCapabilityGuardMiddleware))

async def run() -> None:
    context = SimpleNamespace(
        function=SimpleNamespace(name="shell_execute"),
        arguments={"command": "id"},
        result=None,
    )

    async def call_next() -> None:
        context.result = "executed"

    try:
        await capability.process(context, call_next)
    except Exception:
        pass

asyncio.run(run())
print(f"Wrote signed audit entries to {os.environ['GOVERNANCE_AUDIT_FILE']}")
PY

python - <<PY
from pathlib import Path
from agentmesh.governance.audit_backends import FileAuditSink

path = Path("$AUDIT_FILE")
secret = "$SECRET".encode()
sink = FileAuditSink(path, secret)
ok, err = sink.verify_integrity()
if not ok:
    raise SystemExit(f"Integrity check failed before tamper: {err}")
print("Integrity OK before tamper")

lines = path.read_text(encoding="utf-8").splitlines()
if not lines:
    raise SystemExit("Audit file is empty")
# The first receipt is the denied shell_execute call: flip its decision to "allow".
tampered = lines[0].replace('"deny"', '"allow"')
if tampered == lines[0]:
    raise SystemExit("Nothing to tamper with in the first audit entry")
path.write_text(tampered + "\n" + "\n".join(lines[1:]), encoding="utf-8")

sink2 = FileAuditSink(path, secret)
ok2, err2 = sink2.verify_integrity()
if ok2:
    raise SystemExit("Tamper was not detected")
print(f"Tamper detected as expected: {err2}")
PY

echo "Scenario 19 audit-chain verification passed."
