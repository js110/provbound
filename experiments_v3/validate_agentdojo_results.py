from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def validate(directory: Path, freeze_path: Path) -> list[str]:
    errors: list[str] = []
    rows_path = directory / "rows.csv"
    manifest_path = directory / "manifest.json"
    stats_path = directory / "statistics.json"
    freeze = json.loads(freeze_path.read_text(encoding="utf-8"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    with rows_path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    expected = freeze["scope"]["cells"]
    if len(rows) != expected:
        errors.append(f"expected {expected} rows, found {len(rows)}")
    keys = [(r["mode"], r["user_task_id"], r["injection_task_id"]) for r in rows]
    if len(keys) != len(set(keys)):
        errors.append("duplicate experimental cells")
    failed = [row for row in rows if row["status"] != "ok"]
    if failed:
        errors.append(f"non-completed cells: {len(failed)}")
    for relative, expected_hash in freeze["implementation_sha256"].items():
        if _sha256(ROOT / relative) != expected_hash:
            errors.append(f"implementation hash mismatch: {relative}")
    if _sha256(ROOT / freeze["protocol_path"]) != freeze["protocol_sha256"]:
        errors.append("protocol hash mismatch")
    log_count = len(list((directory / "official_logs").rglob("*.json")))
    if log_count != expected:
        errors.append(f"expected {expected} official logs, found {log_count}")
    for name, expected_hash in manifest["artifacts"].items():
        if name == "resolved_config.json" or name == "rows.csv" or name == "summary.json":
            if _sha256(directory / name) != expected_hash:
                errors.append(f"artifact hash mismatch: {name}")
    if not stats_path.exists():
        errors.append("statistics.json missing")
    manifest["validation_status"] = "passed" if not errors else "failed"
    manifest["paper_evidence_eligible"] = not errors
    manifest["validation_errors"] = errors
    if stats_path.exists():
        manifest["artifacts"]["statistics.json"] = _sha256(stats_path)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return errors


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--freeze", type=Path, required=True)
    args = parser.parse_args()
    errors = validate(args.directory, args.freeze)
    print(json.dumps({"errors": errors, "passed": not errors}, indent=2))
    raise SystemExit(1 if errors else 0)


if __name__ == "__main__":
    main()
