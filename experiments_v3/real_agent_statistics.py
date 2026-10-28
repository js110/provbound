from __future__ import annotations

import argparse
import csv
import json
import math
import random
from collections import Counter
from pathlib import Path
from statistics import fmean, median
from typing import Any, Callable

from experiments_v3.statistics import exact_mcnemar_p_value, wilson_interval


def analyze_real_agent_rows(
    rows: list[dict[str, str]],
    *,
    primary_providers: set[str] | None = None,
) -> dict[str, Any]:
    providers = sorted({row["provider"] for row in rows})
    primary = set(providers) if primary_providers is None else set(primary_providers)
    unknown_primary = primary - set(providers)
    if unknown_primary:
        raise ValueError(f"primary providers missing from rows: {sorted(unknown_primary)}")
    output: dict[str, Any] = {
        "analysis_version": "real-agent-statistics-v1",
        "confidence_level": 0.95,
        "statistical_unit": "provider_x_base_scenario_id",
        "failure_policy": (
            "Failures are reported over all attempted cells. Utility and efficiency "
            "denominators use completed cells. A failed cell enters an adverse safety "
            "denominator only when the final sandbox state proves the adverse event "
            "already occurred. Paired effects require an observable outcome on both sides."
        ),
        "providers": {},
    }
    for provider in providers:
        selected = [row for row in rows if row["provider"] == provider]
        output["providers"][provider] = {
            "attempted_cells": len(selected),
            "completed_cells": sum(_completed(row) for row in selected),
            "modes": {
                mode: _mode_summary([row for row in selected if row["mode"] == mode])
                for mode in sorted({row["mode"] for row in selected})
            },
            "paired_full_vs_base": _paired_summary(selected),
        }
    primary_rows = [row for row in rows if row["provider"] in primary]
    output["primary_pooled"] = {
        "providers": sorted(primary),
        "attempted_cells": len(primary_rows),
        "completed_cells": sum(_completed(row) for row in primary_rows),
        "modes": {
            mode: _mode_summary(
                [row for row in primary_rows if row["mode"] == mode]
            )
            for mode in sorted({row["mode"] for row in primary_rows})
        },
        "paired_full_vs_base": _paired_summary(primary_rows),
    }
    return output


def _mode_summary(rows: list[dict[str, str]]) -> dict[str, Any]:
    completed = [row for row in rows if _completed(row)]
    attempted_attacks = [row for row in rows if row["variant_kind"] == "attack"]
    attacks = [
        row
        for row in attempted_attacks
        if _completed(row) or _boolean(row.get("attack_success"))
    ]
    attack_attempt_observed = [
        row
        for row in attempted_attacks
        if _completed(row) or _boolean(row.get("attack_attempted"))
    ]
    attempted_benign = [row for row in rows if row["variant_kind"] == "benign"]
    benign = [row for row in attempted_benign if _completed(row)]
    benign_unauthorized_observed = [
        row
        for row in attempted_benign
        if _completed(row) or _boolean(row.get("unauthorized_commit"))
    ]
    failures = [row for row in rows if not _completed(row)]
    return {
        "attempted_cells": len(rows),
        "completed_cells": len(completed),
        "failure_rate": _rate(len(failures), len(rows)),
        "failures": {
            "count": len(failures),
            "by_class": dict(sorted(Counter(row.get("failure_class") or "unknown" for row in failures).items())),
        },
        "attack_success_rate": _binary_row_rate(attacks, "attack_success"),
        "attack_attempt_rate": _binary_row_rate(attack_attempt_observed, "attack_attempted"),
        "benign_task_success_rate": _binary_row_rate(benign, "task_success"),
        "benign_unauthorized_commit_rate": _binary_row_rate(
            benign_unauthorized_observed, "unauthorized_commit"
        ),
        "efficiency_completed": {
            "elapsed_seconds": _distribution(completed, "elapsed_seconds", float),
            "total_tokens": _distribution(completed, "total_tokens", int),
            "steps": _distribution(completed, "steps", int),
            "tool_calls": _distribution(completed, "tool_calls", int),
        },
    }


def _paired_summary(rows: list[dict[str, str]]) -> dict[str, Any]:
    return {
        "attack_success_reduction": _paired_effect(
            rows,
            variant_kind="attack",
            field="attack_success",
            direction="base_minus_full",
        ),
        "benign_task_success_gain": _paired_effect(
            rows,
            variant_kind="benign",
            field="task_success",
            direction="full_minus_base",
        ),
        "benign_unauthorized_commit_reduction": _paired_effect(
            rows,
            variant_kind="benign",
            field="unauthorized_commit",
            direction="base_minus_full",
        ),
    }


def _paired_effect(
    rows: list[dict[str, str]],
    *,
    variant_kind: str,
    field: str,
    direction: str,
) -> dict[str, Any]:
    cells: dict[tuple[str, str], dict[str, dict[str, str]]] = {}
    for row in rows:
        if row["variant_kind"] != variant_kind:
            continue
        cells.setdefault(
            (row["provider"], row["base_scenario_id"], variant_kind), {}
        )[row["mode"]] = row
    pairs = [
        (modes["base"], modes["full"])
        for modes in cells.values()
        if {"base", "full"} <= modes.keys()
        and _observable_for_field(modes["base"], field)
        and _observable_for_field(modes["full"], field)
    ]
    differences: list[float] = []
    base_only = 0
    full_only = 0
    for base, full in pairs:
        base_event = _boolean(base.get(field))
        full_event = _boolean(full.get(field))
        base_only += base_event and not full_event
        full_only += full_event and not base_event
        if direction == "base_minus_full":
            differences.append(float(base_event) - float(full_event))
        elif direction == "full_minus_base":
            differences.append(float(full_event) - float(base_event))
        else:
            raise ValueError(f"unsupported effect direction: {direction}")
    return {
        "direction": direction,
        "paired_n": len(pairs),
        "estimate": (fmean(differences) if differences else None),
        "paired_bootstrap_95": (_bootstrap_interval(differences) if differences else None),
        "base_only_event": int(base_only),
        "full_only_event": int(full_only),
        "mcnemar_exact_two_sided_p": (
            exact_mcnemar_p_value(int(base_only), int(full_only)) if pairs else None
        ),
    }


def _rate(events: int, trials: int) -> dict[str, Any]:
    if trials == 0:
        return {"events": events, "n": 0, "estimate": None, "wilson_95": None}
    return {
        "events": events,
        "n": trials,
        "estimate": events / trials,
        "wilson_95": list(wilson_interval(events, trials)),
    }


def _binary_row_rate(rows: list[dict[str, str]], field: str) -> dict[str, Any]:
    return _rate(sum(_boolean(row.get(field)) for row in rows), len(rows))


def _distribution(
    rows: list[dict[str, str]], field: str, conversion: Callable[[str], float | int]
) -> dict[str, Any]:
    values = sorted(float(conversion(row.get(field) or "0")) for row in rows)
    if not values:
        return {"n": 0, "mean": None, "median": None, "q1": None, "q3": None, "min": None, "max": None}
    return {
        "n": len(values),
        "mean": fmean(values),
        "median": median(values),
        "q1": _percentile(values, 0.25),
        "q3": _percentile(values, 0.75),
        "min": values[0],
        "max": values[-1],
    }


def _bootstrap_interval(values: list[float], *, iterations: int = 10_000, seed: int = 20260719) -> list[float]:
    rng = random.Random(seed)
    estimates = sorted(
        fmean(rng.choice(values) for _ in values) for _ in range(iterations)
    )
    return [_percentile(estimates, 0.025), _percentile(estimates, 0.975)]


def _percentile(values: list[float], quantile: float) -> float:
    position = (len(values) - 1) * quantile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return values[lower]
    fraction = position - lower
    return values[lower] * (1 - fraction) + values[upper] * fraction


def _completed(row: dict[str, str]) -> bool:
    return row.get("status") == "ok"


def _observable_for_field(row: dict[str, str], field: str) -> bool:
    if _completed(row):
        return True
    return field in {"attack_success", "unauthorized_commit"} and _boolean(
        row.get(field)
    )


def _boolean(value: Any) -> bool:
    return value is True or str(value).lower() == "true"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rows", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--primary-provider", action="append")
    args = parser.parse_args()
    with args.rows.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    result = analyze_real_agent_rows(
        rows,
        primary_providers=(set(args.primary_provider) if args.primary_provider else None),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
