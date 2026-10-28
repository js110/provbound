import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from experiments_v3.dataset_runner import (
    run_dataset,
    summarize_dataset_rows,
    write_dataset_run,
)
from experiments_v3.validate_dataset import load_jsonl


DATASET = (
    Path(__file__).resolve().parents[1]
    / "experiments_v3"
    / "datasets"
    / "base_scenarios.jsonl"
)


class DatasetRunnerV3Tests(unittest.TestCase):
    def test_full_guard_matches_all_frozen_development_variants(self):
        scenarios = load_jsonl(DATASET)

        rows = run_dataset(scenarios, split="dev", modes=("full",))

        self.assertEqual(len(rows), 90)
        mismatches = [row for row in rows if row.predicted != row.expected]
        self.assertEqual(mismatches, [])
        invalid_certificates = [
            row
            for row in rows
            if row.predicted.value != "allow" and row.certificate_valid is not True
        ]
        self.assertEqual(invalid_certificates, [])

    def test_development_summary_exposes_safety_utility_and_review_tradeoffs(self):
        scenarios = load_jsonl(DATASET)
        rows = run_dataset(scenarios, split="dev")

        summary = summarize_dataset_rows(rows)

        self.assertEqual(summary["full"]["exact_accuracy"], 1.0)
        self.assertEqual(summary["full"]["attack_success_rate"], 0.0)
        self.assertEqual(summary["full"]["false_positive_rate"], 0.0)
        self.assertEqual(summary["base"]["attack_success_rate"], 1.0)
        self.assertGreater(
            summary["full"]["exact_accuracy"],
            summary["action_target"]["exact_accuracy"],
        )

    def test_development_writer_marks_run_as_non_paper_evidence(self):
        scenarios = load_jsonl(DATASET)
        with TemporaryDirectory() as temporary_directory:
            manifest = write_dataset_run(
                scenarios,
                split="dev",
                output_directory=Path(temporary_directory),
            )

            self.assertFalse(manifest["paper_evidence_eligible"])
            self.assertEqual(manifest["variant_count"], 90)
            self.assertTrue((Path(temporary_directory) / "rows.csv").exists())
            self.assertTrue((Path(temporary_directory) / "summary.json").exists())


if __name__ == "__main__":
    unittest.main()
