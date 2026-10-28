from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
from typing import Any

from experiments_v3.real_agent_benchmark import write_real_agent_run


BOOL_FIELDS = {
    "attack_attempted",
    "unauthorized_commit",
    "attack_success",
    "task_success",
}
INT_FIELDS = {
    "guard_blocks",
    "guard_reviews",
    "steps",
    "tool_calls",
    "prompt_tokens",
    "completion_tokens",
    "total_tokens",
}
FLOAT_FIELDS = {"elapsed_seconds"}
JSON_FIELDS = {"response_model_ids"}
NULLABLE_FIELDS = {"error_type", "failure_class"}


def merge_real_agent_run_directories(
    *,
    input_directories: list[Path],
    output_directory: Path,
    dataset_path: Path,
    split: str,
) -> dict[str, Any]:
    if not input_directories:
        raise ValueError("at least one input run directory is required")
    expected_dataset_hash = _sha256(dataset_path)
    rows: list[dict[str, Any]] = []
    reference_protocol: tuple[str, ...] | None = None
    reference_implementation: dict[str, str] | None = None

    for directory in input_directories:
        manifest = _load_manifest(directory)
        if manifest.get("split") != split:
            raise ValueError(f"split mismatch in {directory}")
        if manifest.get("dataset", {}).get("sha256") != expected_dataset_hash:
            raise ValueError(f"dataset hash mismatch in {directory}")
        protocol = tuple(manifest.get("agent_protocol_sha256") or ())
        implementation = manifest.get("implementation_sha256") or {}
        if reference_protocol is None:
            reference_protocol = protocol
            reference_implementation = implementation
        elif protocol != reference_protocol:
            raise ValueError(f"agent protocol mismatch in {directory}")
        elif implementation != reference_implementation:
            raise ValueError(f"implementation hash mismatch in {directory}")
        _verify_artifacts(directory, manifest)
        rows.extend(_load_rows_with_traces(directory))

    keys = [
        (
            row["provider"],
            row["mode"],
            row["base_scenario_id"],
            row["variant_id"],
        )
        for row in rows
    ]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate grid cell across input runs")
    rows.sort(
        key=lambda row: (
            row["provider"],
            row["base_scenario_id"],
            row["variant_id"],
            row["mode"],
        )
    )
    return write_real_agent_run(
        rows=rows,
        output_directory=output_directory,
        dataset_path=dataset_path,
        split=split,
    )


def _load_manifest(directory: Path) -> dict[str, Any]:
    path = directory / "run_manifest.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"unreadable run manifest: {directory}") from error


def _verify_artifacts(directory: Path, manifest: dict[str, Any]) -> None:
    for filename, expected in (manifest.get("artifacts") or {}).items():
        path = directory / filename
        if not path.is_file() or _sha256(path) != expected:
            raise ValueError(f"artifact hash mismatch: {path}")


def _load_rows_with_traces(directory: Path) -> list[dict[str, Any]]:
    trace_by_key: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for line in (directory / "traces.jsonl").read_text(encoding="utf-8").splitlines():
        item = json.loads(line)
        key = (
            item["provider"],
            item["mode"],
            item["base_scenario_id"],
            item["variant_id"],
        )
        if key in trace_by_key:
            raise ValueError(f"duplicate trace cell in {directory}: {key}")
        trace_by_key[key] = item

    rows: list[dict[str, Any]] = []
    with (directory / "rows.csv").open(encoding="utf-8", newline="") as handle:
        for raw in csv.DictReader(handle):
            row = {name: _parse_csv_value(name, value) for name, value in raw.items()}
            key = (
                row["provider"],
                row["mode"],
                row["base_scenario_id"],
                row["variant_id"],
            )
            trace_item = trace_by_key.pop(key, None)
            if trace_item is None:
                raise ValueError(f"missing trace cell in {directory}: {key}")
            row["committed_actions"] = trace_item.get("committed_actions") or []
            row["trace"] = trace_item.get("trace")
            rows.append(row)
    if trace_by_key:
        raise ValueError(f"orphan trace cells in {directory}: {len(trace_by_key)}")
    return rows


def _parse_csv_value(name: str, value: str) -> Any:
    if name in BOOL_FIELDS:
        return value == "True"
    if name in INT_FIELDS:
        return int(value or 0)
    if name in FLOAT_FIELDS:
        return float(value or 0.0)
    if name in JSON_FIELDS:
        return json.loads(value or "[]")
    if name in NULLABLE_FIELDS:
        return value or None
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", action="append", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--split", choices=("dev", "test"), required=True)
    args = parser.parse_args()
    manifest = merge_real_agent_run_directories(
        input_directories=args.input,
        output_directory=args.output,
        dataset_path=args.dataset,
        split=args.split,
    )
    print(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
