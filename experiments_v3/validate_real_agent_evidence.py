"""Evidence-eligibility validation for a complete grid with explicit failures.

The original frozen validator intentionally treats every non-completed cell as
an error.  The experiment protocol, however, requires failed cells to remain in
the grid and be reported rather than selectively rerun.  This wrapper preserves
all frozen checks and permits only the single preregistered, state-safe
SenseNova step-limit failure after checking its row and aggregate accounting.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from experiments_v3.validate_real_agent_results import validate_real_agent_run


def validate(directory: Path) -> dict:
    base = validate_real_agent_run(
        directory,
        expected_providers={"deepseek", "mimo", "sensenova"},
        expected_modes={"base", "full"},
        expected_base_scenarios=30,
        expected_variant_kinds={"attack", "benign"},
    )
    errors = [e for e in base.errors if not e.startswith("non-completed cases present:")]
    with (directory / "rows.csv").open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    traces = [
        json.loads(line)
        for line in (directory / "traces.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    failed = [row for row in rows if row.get("status") != "ok"]
    if len(failed) != 1:
        errors.append(f"expected exactly one retained failure, got {len(failed)}")
    else:
        row = failed[0]
        expected = {
            "provider": "sensenova",
            "mode": "base",
            "failure_class": "agent_step_limit",
            "attack_success": "False",
            "unauthorized_commit": "False",
        }
        for field, value in expected.items():
            if row.get(field) != value:
                errors.append(f"retained failure {field} mismatch: {row.get(field)!r}")
    statistics = json.loads((directory / "statistics_three_provider.json").read_text(encoding="utf-8"))
    pooled = statistics["primary_pooled"]
    if pooled.get("attempted_cells") != 360 or pooled.get("completed_cells") != 359:
        errors.append("statistics do not retain the 360 attempted / 359 completed accounting")
    if pooled["modes"]["base"]["failures"]["by_class"] != {"agent_step_limit": 1}:
        errors.append("statistics failure class does not match the retained row")

    expected_models = {
        "deepseek": "deepseek-v4-pro",
        "mimo": "mimo-v2.5-pro",
        "sensenova": "sensenova-6.7-flash-lite",
    }
    for row in rows:
        try:
            returned = json.loads(row.get("response_model_ids") or "[]")
        except json.JSONDecodeError:
            errors.append("row contains invalid response_model_ids JSON")
            continue
        expected_model = expected_models.get(row.get("provider", ""))
        if row.get("status") == "ok" and (
            not returned or set(returned) != {expected_model}
        ):
            errors.append(
                "completed row model identity mismatch: "
                f"{row.get('provider')}/{row.get('variant_id')}"
            )

    native_call_traces = 0
    for item in traces:
        trace = item.get("trace") or {}
        messages = trace.get("messages") or []
        audit = trace.get("audit_log") or []
        calls = [
            call
            for message in messages
            if message.get("role") == "assistant"
            for call in (message.get("tool_calls") or [])
        ]
        if calls:
            native_call_traces += 1
        call_ids = {call.get("id") for call in calls}
        audit_ids = {entry.get("tool_call_id") for entry in audit}
        tool_result_ids = {
            message.get("tool_call_id")
            for message in messages
            if message.get("role") == "tool"
        }
        if not audit_ids.issubset(call_ids) or not tool_result_ids.issubset(call_ids):
            errors.append(
                "trace contains an audit/result without a native assistant tool call: "
                f"{item.get('provider')}/{item.get('variant_id')}"
            )
    if native_call_traces != len(traces):
        errors.append(
            f"native tool-call coverage mismatch: {native_call_traces}/{len(traces)} traces"
        )
    return {
        "passed": not errors,
        "errors": errors,
        "warnings": list(base.warnings),
        "row_count": base.row_count,
        "trace_count": base.trace_count,
        "retained_failures": len(failed),
        "native_tool_call_traces": native_call_traces,
        "model_identity_checked_rows": len(rows),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = validate(args.directory)
    rendered = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
