import argparse
import csv
import json
import math
import random
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable


def wilson_interval(successes: int, trials: int, z: float = 1.959963984540054) -> tuple[float, float]:
    if trials <= 0:
        raise ValueError("trials must be positive")
    if not 0 <= successes <= trials:
        raise ValueError("successes must be between zero and trials")
    proportion = successes / trials
    denominator = 1 + (z * z / trials)
    center = (proportion + z * z / (2 * trials)) / denominator
    radius = (
        z
        * math.sqrt(
            proportion * (1 - proportion) / trials
            + z * z / (4 * trials * trials)
        )
        / denominator
    )
    return center - radius, center + radius


def exact_mcnemar_p_value(discordant_a: int, discordant_b: int) -> float:
    if discordant_a < 0 or discordant_b < 0:
        raise ValueError("discordant counts cannot be negative")
    total = discordant_a + discordant_b
    if total == 0:
        return 1.0
    tail = min(discordant_a, discordant_b)
    probability = sum(math.comb(total, k) for k in range(tail + 1)) / (2**total)
    return min(1.0, 2 * probability)


def clustered_bootstrap_difference(
    by_scenario: dict[str, dict[str, float]],
    first: str,
    second: str,
    *,
    iterations: int = 10_000,
    seed: int = 20260718,
) -> tuple[float, float]:
    scenario_ids = sorted(by_scenario)
    if not scenario_ids:
        raise ValueError("at least one scenario is required")
    rng = random.Random(seed)
    differences = []
    for _ in range(iterations):
        sampled = [rng.choice(scenario_ids) for _ in scenario_ids]
        differences.append(
            sum(
                by_scenario[item][first] - by_scenario[item][second]
                for item in sampled
            )
            / len(sampled)
        )
    differences.sort()
    return (
        _percentile(differences, 0.025),
        _percentile(differences, 0.975),
    )


def analyze_rows(rows: list[dict[str, str]]) -> dict[str, Any]:
    modes = sorted({row["mode"] for row in rows})
    scenario_ids = sorted({row["base_scenario_id"] for row in rows})
    by_mode = {mode: [row for row in rows if row["mode"] == mode] for mode in modes}
    output: dict[str, Any] = {
        "statistical_unit": "base_scenario_id",
        "base_scenarios": len(scenario_ids),
        "confidence_level": 0.95,
        "mode_intervals": {},
        "paired_comparisons": {},
    }
    for mode, selected in by_mode.items():
        attacks = [row for row in selected if row["expected"] == "block"]
        benign = [row for row in selected if row["expected"] == "allow"]
        attack_successes = sum(row["predicted"] == "allow" for row in attacks)
        false_positives = sum(row["predicted"] != "allow" for row in benign)
        output["mode_intervals"][mode] = {
            "attack_success_rate": {
                "estimate": attack_successes / len(attacks),
                "wilson_95": list(wilson_interval(attack_successes, len(attacks))),
                "n": len(attacks),
            },
            "false_positive_rate": {
                "estimate": false_positives / len(benign),
                "wilson_95": list(wilson_interval(false_positives, len(benign))),
                "n": len(benign),
            },
        }

    correctness = _scenario_scores(rows, lambda row: row["predicted"] == row["expected"])
    all_correct = _scenario_scores(
        rows,
        lambda row: row["predicted"] == row["expected"],
        require_all=True,
    )
    for baseline in (mode for mode in modes if mode != "full"):
        full_only = sum(
            all_correct[scenario]["full"] == 1
            and all_correct[scenario][baseline] == 0
            for scenario in scenario_ids
        )
        baseline_only = sum(
            all_correct[scenario]["full"] == 0
            and all_correct[scenario][baseline] == 1
            for scenario in scenario_ids
        )
        output["paired_comparisons"][f"full_minus_{baseline}"] = {
            "exact_accuracy_difference": (
                sum(correctness[item]["full"] - correctness[item][baseline] for item in scenario_ids)
                / len(scenario_ids)
            ),
            "cluster_bootstrap_95": list(
                clustered_bootstrap_difference(correctness, "full", baseline)
            ),
            "scenario_all_variants_correct": {
                "full_only": full_only,
                "baseline_only": baseline_only,
                "mcnemar_exact_two_sided_p": exact_mcnemar_p_value(
                    full_only, baseline_only
                ),
            },
        }
    return output


def _scenario_scores(
    rows: list[dict[str, str]],
    predicate: Callable[[dict[str, str]], bool],
    *,
    require_all: bool = False,
) -> dict[str, dict[str, float]]:
    grouped: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        grouped[(row["base_scenario_id"], row["mode"])].append(row)
    output: dict[str, dict[str, float]] = defaultdict(dict)
    for (scenario, mode), selected in grouped.items():
        values = [predicate(row) for row in selected]
        output[scenario][mode] = float(all(values)) if require_all else sum(values) / len(values)
    return dict(output)


def _percentile(values: list[float], quantile: float) -> float:
    position = (len(values) - 1) * quantile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return values[lower]
    fraction = position - lower
    return values[lower] * (1 - fraction) + values[upper] * fraction


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rows", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    with args.rows.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    result = analyze_rows(rows)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
