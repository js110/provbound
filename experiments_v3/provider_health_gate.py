from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from experiments_v3.provider_smoke import run_provider_smoke
from experiments_v3.providers import create_provider, provider_catalog


def evaluate_provider_health(
    attempts: list[dict[str, Any]],
    *,
    configured_model: str,
    required_attempts: int,
) -> dict[str, Any]:
    reasons: list[str] = []
    if len(attempts) != required_attempts:
        reasons.append("attempt_count_mismatch")
    if any(
        row.get("status") != "ok" or row.get("native_tool_call") is not True
        for row in attempts
    ):
        reasons.append("native_tool_probe_failure")
    returned = {
        model_id
        for row in attempts
        for model_id in (row.get("response_model_ids") or [])
    }
    if returned != {configured_model}:
        reasons.append("returned_model_mismatch")
    return {
        "status": "pass" if not reasons else "fail",
        "reasons": reasons,
        "required_attempts": required_attempts,
        "configured_model": configured_model,
        "returned_model_ids": sorted(returned),
    }


def run_health_gate(
    *,
    provider_name: str,
    configured_model: str,
    provider: Any,
    attempts: int = 3,
) -> dict[str, Any]:
    if attempts <= 0:
        raise ValueError("attempts must be positive")
    rows: list[dict[str, Any]] = []
    for index in range(1, attempts + 1):
        try:
            row = run_provider_smoke(
                provider_name=provider_name,
                configured_model=configured_model,
                provider=provider,
            )
        except Exception as error:  # Availability failures are evidence, not safety wins.
            row = {
                "provider": provider_name,
                "configured_model": configured_model,
                "response_model_ids": [],
                "status": "unavailable",
                "native_tool_call": False,
                "tool_calls": 0,
                "error_type": type(error).__name__,
            }
        row["attempt"] = index
        rows.append(row)
    decision = evaluate_provider_health(
        rows,
        configured_model=configured_model,
        required_attempts=attempts,
    )
    return {
        "provider": provider_name,
        **decision,
        "attempts": rows,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--providers",
        nargs="+",
        choices=sorted(provider_catalog()),
        default=sorted(provider_catalog()),
    )
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    results = []
    for name in args.providers:
        spec = provider_catalog()[name]
        try:
            provider = create_provider(name)
        except Exception as error:
            results.append(
                {
                    "provider": name,
                    "configured_model": spec.model,
                    "status": "fail",
                    "reasons": ["provider_initialization_failure"],
                    "required_attempts": args.attempts,
                    "returned_model_ids": [],
                    "attempts": [],
                    "error_type": type(error).__name__,
                }
            )
            continue
        results.append(
            run_health_gate(
                provider_name=name,
                configured_model=spec.model,
                provider=provider,
                attempts=args.attempts,
            )
        )
    payload = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "kind": "provider_consecutive_native_tool_health_gate",
        "attempts_per_provider": args.attempts,
        "status": "pass" if all(row["status"] == "pass" for row in results) else "fail",
        "paper_evidence_eligible": False,
        "results": results,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    raise SystemExit(payload["status"] != "pass")


if __name__ == "__main__":
    main()
