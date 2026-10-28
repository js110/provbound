from dataclasses import dataclass
from datetime import datetime, timezone
import argparse
import csv
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

from causalguard.guard.authorization import (
    AuthorizationContract,
    DataCategory,
    Decision,
)
from causalguard.guard.certificate import verify_decision_certificate
from causalguard.guard.trace_schema import SourceTrust, ToolCall
from causalguard.integrations.core_guard import CoreGuard


@dataclass(frozen=True)
class DatasetRunRow:
    mode: str
    split: str
    base_scenario_id: str
    variant_id: str
    domain: str
    attack_family: str
    expected: Decision
    predicted: Decision
    certificate_valid: bool | None


def run_dataset(
    scenarios: list[dict[str, Any]],
    *,
    split: str,
    modes: Iterable[str] = ("base", "action_target", "full"),
) -> list[DatasetRunRow]:
    requested_modes = tuple(modes)
    unsupported = set(requested_modes) - {"base", "action_target", "full"}
    if unsupported:
        raise ValueError(f"unsupported modes: {sorted(unsupported)}")
    rows: list[DatasetRunRow] = []
    guard = CoreGuard()
    for scenario in scenarios:
        if scenario["split"] != split:
            continue
        for variant in scenario["variants"]:
            call, contract = compile_variant(scenario, variant)
            for mode in requested_modes:
                certificate_valid: bool | None = None
                if mode == "base":
                    predicted = Decision.ALLOW
                elif mode == "action_target":
                    predicted = _action_target_decision(call, contract)
                else:
                    result = guard.evaluate(call, contracts=[contract])
                    predicted = result.decision
                    if result.certificate is not None:
                        certificate_valid = verify_decision_certificate(
                            result.certificate
                        ).valid
                rows.append(
                    DatasetRunRow(
                        mode=mode,
                        split=split,
                        base_scenario_id=scenario["base_scenario_id"],
                        variant_id=variant["variant_id"],
                        domain=scenario["domain"],
                        attack_family=scenario["attack_family"],
                        expected=Decision(variant["expected_decision"]),
                        predicted=predicted,
                        certificate_valid=certificate_valid,
                    )
                )
    return rows


def summarize_dataset_rows(
    rows: list[DatasetRunRow],
) -> dict[str, dict[str, float | int]]:
    summary: dict[str, dict[str, float | int]] = {}
    for mode in sorted({row.mode for row in rows}):
        selected = [row for row in rows if row.mode == mode]
        allows = [row for row in selected if row.expected == Decision.ALLOW]
        blocks = [row for row in selected if row.expected == Decision.BLOCK]
        reviews = [row for row in selected if row.expected == Decision.REVIEW]
        nonallow_predictions = [
            row for row in selected if row.predicted != Decision.ALLOW
        ]
        summary[mode] = {
            "cases": len(selected),
            "exact_accuracy": _rate(
                sum(row.predicted == row.expected for row in selected),
                len(selected),
            ),
            "attack_success_rate": _rate(
                sum(row.predicted == Decision.ALLOW for row in blocks),
                len(blocks),
            ),
            "false_positive_rate": _rate(
                sum(row.predicted != Decision.ALLOW for row in allows),
                len(allows),
            ),
            "utility": _rate(
                sum(row.predicted == Decision.ALLOW for row in allows),
                len(allows),
            ),
            "block_recall": _rate(
                sum(row.predicted == Decision.BLOCK for row in blocks),
                len(blocks),
            ),
            "review_recall": _rate(
                sum(row.predicted == Decision.REVIEW for row in reviews),
                len(reviews),
            ),
            "certificate_validity": _rate(
                sum(row.certificate_valid is True for row in nonallow_predictions),
                len(nonallow_predictions),
            ),
        }
    return summary


def write_dataset_run(
    scenarios: list[dict[str, Any]],
    *,
    split: str,
    output_directory: Path,
    modes: Iterable[str] = ("base", "action_target", "full"),
) -> dict[str, Any]:
    rows = run_dataset(scenarios, split=split, modes=modes)
    summary = summarize_dataset_rows(rows)
    output_directory.mkdir(parents=True, exist_ok=True)
    with (output_directory / "rows.csv").open(
        "w", encoding="utf-8", newline=""
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "mode",
                "split",
                "base_scenario_id",
                "variant_id",
                "domain",
                "attack_family",
                "expected",
                "predicted",
                "correct",
                "certificate_valid",
            ],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    "mode": row.mode,
                    "split": row.split,
                    "base_scenario_id": row.base_scenario_id,
                    "variant_id": row.variant_id,
                    "domain": row.domain,
                    "attack_family": row.attack_family,
                    "expected": row.expected.value,
                    "predicted": row.predicted.value,
                    "correct": row.expected == row.predicted,
                    "certificate_valid": row.certificate_valid,
                }
            )
    (output_directory / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    canonical_dataset = json.dumps(
        scenarios,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    manifest = {
        "run_id": f"offline-frozen-{split}-v1",
        "kind": "frozen_custom_authorization_benchmark",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "split": split,
        "base_scenario_count": len(
            {row.base_scenario_id for row in rows}
        ),
        "variant_count": len(
            {(row.base_scenario_id, row.variant_id) for row in rows}
        ),
        "modes": sorted({row.mode for row in rows}),
        "canonical_dataset_sha256": hashlib.sha256(canonical_dataset).hexdigest(),
        "outputs": ["rows.csv", "summary.json"],
        "paper_evidence_eligible": split == "test",
        "evidence_boundary": (
            "This run evaluates the deterministic policy against structured gold. "
            "It does not measure whether a language model produced the correct tool call."
        ),
    }
    (output_directory / "run_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def compile_variant(
    scenario: dict[str, Any],
    variant: dict[str, Any],
) -> tuple[ToolCall, AuthorizationContract]:
    state = scenario["initial_state"]
    auth = scenario["authorization_gold"]
    payload_field = state["payload_field"]
    arguments: dict[str, Any] = {
        "target": state["authorized_target"],
        payload_field: state["payload"],
    }
    provenance = {
        name: frozenset(origins)
        for name, origins in scenario["provenance_gold"].items()
    }
    categories = {
        name: frozenset(values)
        for name, values in scenario["data_category_gold"].items()
    }
    tool_name = scenario["tool"]
    purpose = auth["purpose"]
    timestamp = datetime.fromisoformat("2026-07-18T12:00:00+00:00")
    session_id = auth["session_id"]
    mutation = variant["mutation"]

    if "action" in mutation:
        tool_name = mutation["action"]
    if "target" in mutation:
        arguments["target"] = mutation["target"]
    if "payload" in mutation:
        arguments[payload_field] = mutation["payload"]
        provenance[payload_field] = frozenset({"untrusted:parameter-pollution"})
    if "source" in mutation:
        affected = "target" if "target" in mutation else payload_field
        provenance[affected] = frozenset({mutation["source"]})
    if "purpose" in mutation:
        purpose = mutation["purpose"]
    if "extra_data_categories" in mutation:
        categories[payload_field] = frozenset(
            set(categories.get(payload_field, ()))
            | set(mutation["extra_data_categories"])
        )
    if "timestamp" in mutation:
        timestamp = datetime.fromisoformat(mutation["timestamp"])
    if "drop_provenance_for" in mutation:
        provenance.pop(mutation["drop_provenance_for"], None)

    argument_trust = {
        name: (
            SourceTrust.TRUSTED
            if all(origin.startswith("user_goal") for origin in origins)
            else SourceTrust.UNTRUSTED
        )
        for name, origins in provenance.items()
    }
    call = ToolCall(
        event_id=f"call:{variant['variant_id']}",
        tool_name=tool_name,
        arguments=arguments,
        user_goal=scenario["user_goal"],
        argument_provenance=provenance,
        argument_trust=argument_trust,
        argument_data_categories=categories,
        purpose=purpose,
        scope=frozenset(auth["scope"]),
        timestamp=timestamp,
        session_id=session_id,
    )
    contract = AuthorizationContract(
        contract_id=f"auth:{scenario['base_scenario_id']}",
        action=auth["action"],
        targets=frozenset(auth["targets"]),
        data_categories=frozenset(
            DataCategory(item) for item in auth["data_categories"]
        ),
        purpose=auth["purpose"],
        scope=frozenset(auth["scope"]),
        allowed_sources=frozenset(auth["allowed_sources"]),
        valid_from=datetime.fromisoformat(auth["validity"]["valid_from"]),
        expires_at=datetime.fromisoformat(auth["validity"]["expires_at"]),
        session_id=auth["session_id"],
    )
    return call, contract


def _action_target_decision(
    call: ToolCall,
    contract: AuthorizationContract,
) -> Decision:
    target = str(call.arguments.get("target") or call.arguments.get("to") or "").lower()
    if call.tool_name != contract.action:
        return Decision.BLOCK
    if target not in {item.lower() for item in contract.targets}:
        return Decision.BLOCK
    return Decision.ALLOW


def _rate(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--split", choices=("dev", "test"), required=True)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    from experiments_v3.validate_dataset import load_jsonl

    scenarios = load_jsonl(args.dataset)
    manifest = write_dataset_run(
        scenarios,
        split=args.split,
        output_directory=args.output,
    )
    print(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
