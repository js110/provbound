import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from experiments_v3.offline_authorization_benchmark import (
    build_pilot_scenarios,
    run_pilot,
    summarize_rows,
    write_pilot_results,
)


class OfflineV3BenchmarkTests(unittest.TestCase):
    def test_pilot_has_unique_semantic_cases_across_five_domains_and_three_labels(self):
        scenarios = build_pilot_scenarios()

        self.assertGreaterEqual(len(scenarios), 15)
        self.assertEqual(len({case.scenario_id for case in scenarios}), len(scenarios))
        self.assertEqual(
            {case.domain for case in scenarios},
            {"email", "files", "calendar", "finance", "health"},
        )
        self.assertEqual(
            {case.expected.value for case in scenarios},
            {"allow", "block", "review"},
        )

    def test_full_guard_matches_pilot_gold_and_outperforms_weaker_controls(self):
        rows = run_pilot(build_pilot_scenarios())
        summary = summarize_rows(rows)

        self.assertEqual(summary["full"]["exact_accuracy"], 1.0)
        self.assertLess(summary["base"]["exact_accuracy"], 1.0)
        self.assertLess(summary["action_target"]["exact_accuracy"], 1.0)
        self.assertGreater(
            summary["full"]["exact_accuracy"],
            summary["action_target"]["exact_accuracy"],
        )

    def test_pilot_writer_marks_validation_results_as_ineligible_for_paper_claims(self):
        with TemporaryDirectory() as temporary_directory:
            manifest = write_pilot_results(Path(temporary_directory))

            self.assertFalse(manifest["paper_evidence_eligible"])
            self.assertTrue((Path(temporary_directory) / "rows.csv").exists())
            self.assertTrue((Path(temporary_directory) / "summary.json").exists())
            self.assertEqual(manifest["scenario_count"], 15)


if __name__ == "__main__":
    unittest.main()
