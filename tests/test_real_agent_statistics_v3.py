import unittest

from experiments_v3.real_agent_statistics import analyze_real_agent_rows


def row(
    *,
    provider: str = "model-a",
    scenario: str,
    mode: str,
    variant: str,
    status: str = "ok",
    attack_success: bool = False,
    task_success: bool = True,
    unauthorized_commit: bool = False,
    failure_class: str = "",
    elapsed: float = 1.0,
    tokens: int = 100,
    steps: int = 2,
) -> dict[str, str]:
    return {
        "provider": provider,
        "mode": mode,
        "base_scenario_id": scenario,
        "variant_kind": variant,
        "status": status,
        "failure_class": failure_class,
        "attack_success": str(attack_success),
        "task_success": str(task_success),
        "unauthorized_commit": str(unauthorized_commit),
        "attack_attempted": str(attack_success),
        "elapsed_seconds": str(elapsed),
        "total_tokens": str(tokens),
        "steps": str(steps),
        "tool_calls": "1",
        "guard_blocks": "0",
        "guard_reviews": "0",
    }


class RealAgentStatisticsV3Tests(unittest.TestCase):
    def test_reports_wilson_intervals_failures_and_robust_efficiency(self):
        rows = [
            row(scenario="s1", mode="base", variant="attack", attack_success=True, elapsed=1, tokens=10, steps=1),
            row(scenario="s1", mode="full", variant="attack", elapsed=3, tokens=30, steps=3),
            row(scenario="s1", mode="base", variant="benign", unauthorized_commit=True, elapsed=2, tokens=20, steps=2),
            row(scenario="s1", mode="full", variant="benign", elapsed=4, tokens=40, steps=4),
            row(
                scenario="s2",
                mode="full",
                variant="attack",
                status="error",
                failure_class="connection",
                task_success=False,
            ),
        ]

        result = analyze_real_agent_rows(rows)

        base_attack = result["providers"]["model-a"]["modes"]["base"]["attack_success_rate"]
        self.assertEqual((base_attack["events"], base_attack["n"]), (1, 1))
        self.assertGreater(base_attack["wilson_95"][1], 0)
        full = result["providers"]["model-a"]["modes"]["full"]
        self.assertEqual(full["failures"]["by_class"], {"connection": 1})
        self.assertEqual(full["failure_rate"]["n"], 3)
        self.assertEqual(full["efficiency_completed"]["elapsed_seconds"]["median"], 3.5)

    def test_paired_effect_excludes_incomplete_pairs_and_uses_directional_effects(self):
        rows = []
        for scenario, base_attack, full_attack in (
            ("s1", True, False),
            ("s2", False, False),
        ):
            rows.extend(
                [
                    row(scenario=scenario, mode="base", variant="attack", attack_success=base_attack),
                    row(scenario=scenario, mode="full", variant="attack", attack_success=full_attack),
                    row(scenario=scenario, mode="base", variant="benign", task_success=scenario == "s2"),
                    row(scenario=scenario, mode="full", variant="benign", task_success=True),
                ]
            )
        rows.extend(
            [
                row(scenario="s3", mode="base", variant="attack", attack_success=True),
                row(
                    scenario="s3",
                    mode="full",
                    variant="attack",
                    status="error",
                    failure_class="connection",
                    task_success=False,
                ),
            ]
        )

        result = analyze_real_agent_rows(rows)["providers"]["model-a"]["paired_full_vs_base"]

        safety = result["attack_success_reduction"]
        self.assertEqual(safety["paired_n"], 2)
        self.assertEqual(safety["estimate"], 0.5)
        self.assertEqual(safety["base_only_event"], 1)
        utility = result["benign_task_success_gain"]
        self.assertEqual(utility["paired_n"], 2)
        self.assertEqual(utility["estimate"], 0.5)
        self.assertEqual(utility["full_only_event"], 1)

    def test_error_after_harm_remains_in_safety_denominator(self):
        rows = [
            row(
                scenario="s1",
                mode="base",
                variant="attack",
                status="error",
                failure_class="connection",
                attack_success=True,
                task_success=False,
            ),
            row(
                scenario="s2",
                mode="base",
                variant="attack",
                status="error",
                failure_class="connection",
                attack_success=False,
                task_success=False,
            ),
            row(
                scenario="s3",
                mode="base",
                variant="benign",
                status="error",
                failure_class="connection",
                unauthorized_commit=True,
                task_success=False,
            ),
        ]

        mode = analyze_real_agent_rows(rows)["providers"]["model-a"]["modes"]["base"]

        self.assertEqual(mode["attack_success_rate"]["events"], 1)
        self.assertEqual(mode["attack_success_rate"]["n"], 1)
        self.assertEqual(mode["benign_unauthorized_commit_rate"]["events"], 1)
        self.assertEqual(mode["benign_unauthorized_commit_rate"]["n"], 1)
        self.assertEqual(mode["benign_task_success_rate"]["n"], 0)

    def test_primary_pooled_analysis_uses_provider_scenario_pairs(self):
        rows = []
        for provider in ("model-a", "model-b"):
            rows.extend(
                [
                    row(
                        provider=provider,
                        scenario="s1",
                        mode="base",
                        variant="attack",
                        attack_success=True,
                    ),
                    row(
                        provider=provider,
                        scenario="s1",
                        mode="full",
                        variant="attack",
                        attack_success=False,
                    ),
                ]
            )

        pooled = analyze_real_agent_rows(
            rows, primary_providers={"model-a", "model-b"}
        )["primary_pooled"]["paired_full_vs_base"]["attack_success_reduction"]

        self.assertEqual(pooled["paired_n"], 2)
        self.assertEqual(pooled["estimate"], 1.0)
        self.assertEqual(pooled["base_only_event"], 2)


if __name__ == "__main__":
    unittest.main()
