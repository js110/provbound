from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from statistics import fmean
from typing import Any

from experiments_v3.real_agent_statistics import _bootstrap_interval
from experiments_v3.statistics import exact_mcnemar_p_value, wilson_interval


def analyze_agentdojo_rows(rows: list[dict[str, str]]) -> dict[str, Any]:
    pairs: dict[tuple[str, str], dict[str, dict[str, str]]] = {}
    for row in rows:
        pairs.setdefault((row["user_task_id"], row["injection_task_id"]), {})[
            row["mode"]
        ] = row
    complete_pairs = [
        (modes["base"], modes["full"])
        for modes in pairs.values()
        if set(modes) == {"base", "full"}
        and modes["base"]["status"] == "ok"
        and modes["full"]["status"] == "ok"
    ]
    result: dict[str, Any] = {
        "analysis_version": "agentdojo-external-statistics-v1",
        "statistical_unit": "user_task_id_x_injection_task_id",
        "confidence_level": 0.95,
        "modes": {},
        "paired_full_vs_base": {},
    }
    for mode in ("base", "full"):
        selected = [row for row in rows if row["mode"] == mode]
        completed = [row for row in selected if row["status"] == "ok"]
        result["modes"][mode] = {
            "attempted_cells": len(selected),
            "completed_cells": len(completed),
            "failed_cells": len(selected) - len(completed),
            "attack_success_rate": _rate(
                sum(_bool(row["attack_success"]) for row in completed), len(completed)
            ),
            "utility_rate": _rate(
                sum(_bool(row["utility"]) for row in completed), len(completed)
            ),
        }
    result["paired_full_vs_base"]["attack_success_reduction"] = _paired(
        complete_pairs, "attack_success", "base_minus_full"
    )
    result["paired_full_vs_base"]["utility_gain"] = _paired(
        complete_pairs, "utility", "full_minus_base"
    )
    return result


def _paired(pairs, field: str, direction: str) -> dict[str, Any]:
    differences = []
    base_only = 0
    full_only = 0
    for base, full in pairs:
        b, f = _bool(base[field]), _bool(full[field])
        base_only += int(b and not f)
        full_only += int(f and not b)
        differences.append(float(b) - float(f) if direction == "base_minus_full" else float(f) - float(b))
    return {
        "direction": direction,
        "paired_n": len(pairs),
        "estimate": fmean(differences) if differences else None,
        "paired_bootstrap_95": _bootstrap_interval(differences) if differences else None,
        "base_only_event": base_only,
        "full_only_event": full_only,
        "mcnemar_exact_two_sided_p": exact_mcnemar_p_value(base_only, full_only) if pairs else None,
    }


def _rate(events: int, n: int) -> dict[str, Any]:
    return {
        "events": events,
        "n": n,
        "estimate": events / n if n else None,
        "wilson_95": list(wilson_interval(events, n)) if n else None,
    }


def _bool(value: Any) -> bool:
    return value is True or str(value).lower() == "true"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rows", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    with args.rows.open(encoding="utf-8", newline="") as handle:
        result = analyze_agentdojo_rows(list(csv.DictReader(handle)))
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
