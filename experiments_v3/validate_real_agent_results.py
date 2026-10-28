import csv
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path


@dataclass(frozen=True)
class RealAgentValidationReport:
    errors: tuple[str, ...]
    warnings: tuple[str, ...]
    row_count: int
    trace_count: int


def validate_real_agent_run(
    run_directory: Path,
    *,
    expected_providers: set[str],
    expected_modes: set[str],
    expected_base_scenarios: int,
    expected_variant_kinds: set[str],
) -> RealAgentValidationReport:
    errors: list[str] = []
    warnings: list[str] = []
    manifest_path = run_directory / "run_manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return RealAgentValidationReport(
            errors=(f"manifest unreadable: {type(error).__name__}",),
            warnings=(),
            row_count=0,
            trace_count=0,
        )
    for filename, expected_hash in manifest.get("artifacts", {}).items():
        path = run_directory / filename
        if not path.is_file():
            errors.append(f"artifact missing: {filename}")
            continue
        actual_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual_hash != expected_hash:
            errors.append(f"artifact hash mismatch: {filename}")

    row_path = run_directory / "rows.csv"
    try:
        with row_path.open(encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
    except OSError as error:
        errors.append(f"rows unreadable: {type(error).__name__}")
        rows = []
    trace_path = run_directory / "traces.jsonl"
    traces = []
    try:
        for line_number, line in enumerate(
            trace_path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            try:
                traces.append(json.loads(line))
            except json.JSONDecodeError:
                errors.append(f"trace JSON invalid at line {line_number}")
    except OSError as error:
        errors.append(f"traces unreadable: {type(error).__name__}")

    providers = {str(row.get("provider") or "") for row in rows}
    modes = {str(row.get("mode") or "") for row in rows}
    variants = {str(row.get("variant_kind") or "") for row in rows}
    scenarios = {str(row.get("base_scenario_id") or "") for row in rows}
    if providers != expected_providers:
        errors.append(
            f"provider grid mismatch: expected {sorted(expected_providers)}, got {sorted(providers)}"
        )
    if modes != expected_modes:
        errors.append(
            f"mode grid mismatch: expected {sorted(expected_modes)}, got {sorted(modes)}"
        )
    if variants != expected_variant_kinds:
        errors.append(
            "variant grid mismatch: "
            f"expected {sorted(expected_variant_kinds)}, got {sorted(variants)}"
        )
    if len(scenarios) != expected_base_scenarios:
        errors.append(
            f"base scenario count mismatch: expected {expected_base_scenarios}, got {len(scenarios)}"
        )
    expected_rows = (
        len(expected_providers)
        * len(expected_modes)
        * expected_base_scenarios
        * len(expected_variant_kinds)
    )
    if len(rows) != expected_rows:
        errors.append(f"row count mismatch: expected {expected_rows}, got {len(rows)}")
    grid_keys = [
        (
            row.get("provider"),
            row.get("mode"),
            row.get("base_scenario_id"),
            row.get("variant_kind"),
        )
        for row in rows
    ]
    if len(grid_keys) != len(set(grid_keys)):
        errors.append("duplicate provider/mode/scenario/variant grid cell")
    if len(traces) != len(rows):
        errors.append(f"trace count mismatch: rows={len(rows)}, traces={len(traces)}")
    prompt_fingerprints: dict[tuple[str, str], set[str]] = {}
    for trace_row in traces:
        trace = trace_row.get("trace")
        if not isinstance(trace, dict):
            continue
        messages = trace.get("messages") or []
        if len(messages) < 2:
            errors.append(
                "trace missing shared system/user input: "
                f"{trace_row.get('provider')}/{trace_row.get('variant_id')}"
            )
            continue
        key = (
            str(trace_row.get("base_scenario_id") or ""),
            str(trace_row.get("variant_id") or ""),
        )
        fingerprint = hashlib.sha256(
            json.dumps(
                messages[:2],
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        prompt_fingerprints.setdefault(key, set()).add(fingerprint)
    mismatched_prompts = [
        key for key, fingerprints in prompt_fingerprints.items() if len(fingerprints) != 1
    ]
    if mismatched_prompts:
        errors.append(
            f"cross-provider/treatment prompt mismatch: {len(mismatched_prompts)} cases"
        )
    failed = [row for row in rows if row.get("status") != "ok"]
    if failed:
        errors.append(f"non-completed cases present: {len(failed)}")
    missing_model = [
        row
        for row in rows
        if row.get("status") == "ok"
        and row.get("response_model_ids", "").strip() in {"", "[]"}
    ]
    if missing_model:
        errors.append(f"completed cases missing response model ID: {len(missing_model)}")
    protocol_hashes = {
        row.get("agent_protocol_sha256", "") for row in rows
    } - {""}
    if len(protocol_hashes) != 1:
        errors.append(
            f"same-agent protocol invariant failed: {len(protocol_hashes)} hashes"
        )
    if manifest.get("paper_evidence_eligible") is True:
        warnings.append(
            "run manifest already claims paper eligibility; validation and statistics must be external"
        )
    return RealAgentValidationReport(
        errors=tuple(errors),
        warnings=tuple(warnings),
        row_count=len(rows),
        trace_count=len(traces),
    )
