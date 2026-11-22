#!/usr/bin/env python3
"""Offline conformance evidence for S30 (drift timeline) and S31 (one decision per action).

Runs the real middleware stack against the real Rego policy. No model, network or
`azd` needed; OPA must be on PATH. Run from anywhere:

    python scripts/run-evidence.py drift                 # S30: aligned vs drifting 15-turn sessions
    python scripts/run-evidence.py decisions             # S31: 20 mixed actions, one decision each
    python scripts/run-evidence.py drift-report FILE     # S30: timeline from a live session's audit JSONL

`drift-report` accepts stdout capture or the signed file written with
`GOVERNANCE_SIGNED_AUDIT=1`; add `--session ID` to select one session and
`--threshold N` to flag scores (default: GOVERNANCE_DRIFT_THRESHOLD or 0.7).
Exit status is non-zero when the evidence does not hold.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import tempfile
import warnings
from pathlib import Path

APP_DIR = Path(__file__).resolve().parents[1] / "src" / "governed-assistant"


def _bootstrap(*, phase2: bool) -> None:
    sys.path.insert(0, str(APP_DIR))
    warnings.filterwarnings("ignore")
    os.environ.setdefault("GOVERNANCE_AUDIT_STDOUT", "0")
    os.environ.setdefault("GOVERNANCE_OTEL_AUDIT", "0")
    os.environ["GOVERNANCE_PHASE2"] = "1" if phase2 else "0"
    if phase2:
        os.environ.setdefault("GOVERNANCE_IDENTITY_DIR", tempfile.mkdtemp(prefix="evidence-identities-"))
        os.environ.setdefault("GOVERNANCE_INTENT_AUTO_APPROVE", "1")
        os.environ.setdefault("GOVERNANCE_DELEGATION_AUTO", "0")

    from rego_runtime import configure_rego_runtime

    configure_rego_runtime()
    if phase2:
        from governance_phase2 import bootstrap_phase2
        from tools import ALLOWED_TOOLS

        bootstrap_phase2(allowed_tools=ALLOWED_TOOLS)


def _threshold(value: float | None) -> float:
    if value is not None:
        return value
    from governance_drift import drift_threshold

    return drift_threshold()


def cmd_drift(_: argparse.Namespace) -> int:
    _bootstrap(phase2=True)
    import governance_evidence as ev

    threshold = _threshold(None)
    aligned = asyncio.run(ev.run_drift_session(drifting=False))
    drifting = asyncio.run(ev.run_drift_session(drifting=True))

    for title, run in (("Aligned session (TC-R7-02)", aligned), ("Drifting session (TC-R7-01)", drifting)):
        print(f"\n== {title} ==")
        print(ev.format_drift_timeline(run.timeline, threshold=threshold))
        print(f"max drift {run.max_drift:.2f} · denied turns {run.denied_turns or 'none'}")

    failures = []
    if aligned.denied_turns or aligned.max_drift >= threshold:
        failures.append("aligned session was flagged (false positive)")
    if not drifting.denied_turns or drifting.denied_turns[0] < 10:
        failures.append("drifting session was not denied from turn 10")
    if drifting.max_drift < threshold:
        failures.append("drifting session never reached the drift threshold")
    return _verdict(failures)


def cmd_decisions(_: argparse.Namespace) -> int:
    _bootstrap(phase2=False)
    import governance_evidence as ev

    result = asyncio.run(ev.run_decision_batch())
    print(f"{'#':>2}  {'kind':<5} {'action':<52} {'decision':<8} executed")
    for action in result.actions:
        print(
            f"{action['n']:>2}  {action['kind']:<5} {str(action['action'])[:50]:<52} "
            f"{action['decision']:<8} {action['executed']}"
        )
    seen = ", ".join(sorted(result.decisions_seen))
    print(f"\n{len(result.actions)} actions · decisions seen: {seen}")
    return _verdict(result.problems)


def cmd_drift_report(args: argparse.Namespace) -> int:
    _bootstrap(phase2=False)
    import governance_evidence as ev

    entries = ev.load_jsonl(args.file)
    timeline = ev.drift_timeline_from_entries(entries, session_id=args.session)
    if not timeline:
        print("no pre_tool_call receipts with policy_context found", file=sys.stderr)
        return 1
    print(ev.format_drift_timeline(timeline, threshold=_threshold(args.threshold)))
    return 0


def _verdict(problems: list[str]) -> int:
    if problems:
        print("\nFAIL")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print("\nPASS")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("drift", help="S30: aligned vs drifting sessions").set_defaults(func=cmd_drift)
    sub.add_parser("decisions", help="S31: one decision per action").set_defaults(func=cmd_decisions)
    report = sub.add_parser("drift-report", help="S30: timeline from an audit JSONL file")
    report.add_argument("file")
    report.add_argument("--session")
    report.add_argument("--threshold", type=float)
    report.set_defaults(func=cmd_drift_report)
    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
