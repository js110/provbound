import argparse
import json
from pathlib import Path
from typing import Any

from causalguard.guard.authorization import Decision
from causalguard.integrations.core_guard import CoreGuard
from experiments_v3.runtime_capabilities import (
    build_scenario_capabilities,
    build_scenario_contract,
    compile_runtime_tool_call,
)
from experiments_v3.validate_dataset import load_jsonl


def run_provenance_benchmark(
    scenarios: list[dict[str, Any]],
    *,
    split: str,
) -> dict[str, Any]:
    rows = []
    true_positive = false_positive = false_negative = 0
    forged_reviews = 0
    selected = [scenario for scenario in scenarios if scenario["split"] == split]
    for scenario in selected:
        benign = next(
            variant
            for variant in scenario["variants"]
            if variant["kind"] == "benign"
        )
        state = scenario["initial_state"]
        payload_field = state["payload_field"]
        registry = build_scenario_capabilities(scenario, benign)
        call = compile_runtime_tool_call(
            scenario["tool"],
            {
                "target_ref": "user_goal:target",
                "payload_ref": f"{state['resource']}:{payload_field}",
            },
            scenario,
            registry,
        )
        for argument, expected_values in scenario["provenance_gold"].items():
            expected = frozenset(expected_values)
            predicted = call.argument_provenance.get(argument, frozenset())
            true_positive += len(expected & predicted)
            false_positive += len(predicted - expected)
            false_negative += len(expected - predicted)
            rows.append(
                {
                    "base_scenario_id": scenario["base_scenario_id"],
                    "domain": scenario["domain"],
                    "argument": argument,
                    "expected_origins": sorted(expected),
                    "predicted_origins": sorted(predicted),
                    "exact_match": expected == predicted,
                }
            )
        forged = compile_runtime_tool_call(
            scenario["tool"],
            {
                "target_ref": "forged:target",
                "payload_ref": "forged:payload",
            },
            scenario,
            registry,
        )
        decision = CoreGuard().evaluate(
            forged,
            contracts=[build_scenario_contract(scenario)],
        ).decision
        forged_reviews += decision == Decision.REVIEW

    precision = _rate(true_positive, true_positive + false_positive)
    recall = _rate(true_positive, true_positive + false_negative)
    summary = {
        "split": split,
        "base_scenarios": len(selected),
        "arguments": len(rows),
        "origin_precision": precision,
        "origin_recall": recall,
        "origin_f1": _rate(2 * precision * recall, precision + recall),
        "exact_argument_rate": _rate(
            sum(row["exact_match"] for row in rows), len(rows)
        ),
        "forged_reference_review_rate": _rate(forged_reviews, len(selected)),
        "evidence_boundary": (
            "Measures runtime-bound structured argument provenance against independent "
            "field-origin gold. It does not evaluate free-text semantic provenance inference."
        ),
    }
    return {"summary": summary, "rows": rows}


def _rate(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--split", choices=("dev", "test"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run_provenance_benchmark(
        load_jsonl(args.dataset),
        split=args.split,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result["summary"], ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
