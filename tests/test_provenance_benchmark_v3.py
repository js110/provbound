from pathlib import Path
import hashlib
import json
import unittest

from experiments_v3.provenance_benchmark import run_provenance_benchmark
from experiments_v3.validate_dataset import load_jsonl


DATASET = (
    Path(__file__).resolve().parents[1]
    / "experiments_v3"
    / "datasets"
    / "base_scenarios.jsonl"
)
WORKSPACE = Path(__file__).resolve().parents[1]


class ProvenanceBenchmarkV3Tests(unittest.TestCase):
    def test_development_split_matches_independent_field_origin_gold(self):
        result = run_provenance_benchmark(load_jsonl(DATASET), split="dev")

        self.assertEqual(result["summary"]["base_scenarios"], 30)
        self.assertEqual(result["summary"]["arguments"], 60)
        self.assertEqual(result["summary"]["origin_precision"], 1.0)
        self.assertEqual(result["summary"]["origin_recall"], 1.0)
        self.assertEqual(result["summary"]["origin_f1"], 1.0)
        self.assertEqual(result["summary"]["forged_reference_review_rate"], 1.0)

    def test_test_protocol_files_match_pre_registered_hashes(self):
        freeze = json.loads(
            (
                WORKSPACE
                / "experiments_v3"
                / "configs"
                / "provenance_test_freeze_v2.json"
            ).read_text(encoding="utf-8")
        )

        self.assertFalse(freeze["test_split_may_guide_implementation"])
        for relative_path, expected in freeze["sha256"].items():
            actual = hashlib.sha256(
                (WORKSPACE / relative_path).read_bytes()
            ).hexdigest()
            self.assertEqual(actual, expected, relative_path)


if __name__ == "__main__":
    unittest.main()
