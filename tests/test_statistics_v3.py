import unittest

from experiments_v3.statistics import (
    analyze_rows,
    exact_mcnemar_p_value,
    wilson_interval,
)


class StatisticsV3Tests(unittest.TestCase):
    def test_zero_of_thirty_wilson_interval_has_nonzero_upper_bound(self):
        lower, upper = wilson_interval(0, 30)

        self.assertEqual(lower, 0.0)
        self.assertGreater(upper, 0.11)
        self.assertLess(upper, 0.12)

    def test_exact_mcnemar_uses_two_sided_binomial_tail(self):
        self.assertAlmostEqual(exact_mcnemar_p_value(30, 0), 2 / (2**30))
        self.assertEqual(exact_mcnemar_p_value(0, 0), 1.0)

    def test_analysis_clusters_three_variants_under_one_scenario(self):
        rows = []
        expected = ("allow", "block", "review")
        for scenario in ("s1", "s2"):
            for index, gold in enumerate(expected):
                rows.extend(
                    [
                        {
                            "mode": "base",
                            "base_scenario_id": scenario,
                            "variant_id": f"{scenario}-{index}",
                            "expected": gold,
                            "predicted": "allow",
                        },
                        {
                            "mode": "full",
                            "base_scenario_id": scenario,
                            "variant_id": f"{scenario}-{index}",
                            "expected": gold,
                            "predicted": gold,
                        },
                    ]
                )

        result = analyze_rows(rows)

        self.assertEqual(result["base_scenarios"], 2)
        comparison = result["paired_comparisons"]["full_minus_base"]
        self.assertAlmostEqual(comparison["exact_accuracy_difference"], 2 / 3)
        self.assertEqual(
            comparison["scenario_all_variants_correct"]["full_only"], 2
        )


if __name__ == "__main__":
    unittest.main()
