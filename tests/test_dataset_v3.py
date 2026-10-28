import unittest
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from experiments_v3.validate_dataset import load_jsonl, validate_base_scenarios


DATASET = (
    Path(__file__).resolve().parents[1]
    / "experiments_v3"
    / "datasets"
    / "base_scenarios.jsonl"
)
DATASET_DIRECTORY = DATASET.parent
WORKSPACE = Path(__file__).resolve().parents[1]
TEST_FREEZE = (
    WORKSPACE / "experiments_v3" / "configs" / "offline_test_freeze.json"
)


class DatasetV3Tests(unittest.TestCase):
    def test_frozen_base_dataset_has_sixty_valid_semantic_scenarios(self):
        scenarios = load_jsonl(DATASET)
        report = validate_base_scenarios(scenarios)

        self.assertEqual(report.errors, ())
        self.assertEqual(report.scenario_count, 60)
        self.assertEqual(
            report.domain_counts,
            {
                "email": 12,
                "calendar": 12,
                "files": 12,
                "memory": 12,
                "network": 12,
            },
        )
        self.assertGreaterEqual(len(report.attack_families), 10)

    def test_json_schema_rejects_unregistered_scenario_fields(self):
        scenarios = load_jsonl(DATASET)
        tampered = deepcopy(scenarios)
        tampered[0]["implementation_hint"] = "special-case this test"

        report = validate_base_scenarios(tampered)

        self.assertTrue(
            any("schema" in error for error in report.errors),
            report.errors,
        )

    def test_frozen_dataset_files_match_manifest_hashes(self):
        manifest = json.loads(
            (DATASET_DIRECTORY / "dataset_manifest.json").read_text(
                encoding="utf-8"
            )
        )

        self.assertEqual(manifest["status"], "frozen")
        for relative_path, expected_hash in manifest["files"].items():
            actual_hash = hashlib.sha256(
                (DATASET_DIRECTORY / relative_path).read_bytes()
            ).hexdigest()
            self.assertEqual(
                actual_hash,
                expected_hash,
                f"frozen dataset artifact changed: {relative_path}",
            )

    def test_test_split_configuration_matches_frozen_implementation(self):
        freeze = json.loads(TEST_FREEZE.read_text(encoding="utf-8"))

        self.assertFalse(freeze["protocol"]["test_split_may_guide_implementation"])
        for relative_path, expected_hash in freeze["sha256"].items():
            actual_hash = hashlib.sha256(
                (WORKSPACE / relative_path).read_bytes()
            ).hexdigest()
            self.assertEqual(
                actual_hash,
                expected_hash,
                f"test-frozen implementation changed: {relative_path}",
            )


if __name__ == "__main__":
    unittest.main()
