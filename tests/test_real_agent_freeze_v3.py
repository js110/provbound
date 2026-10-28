import hashlib
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
FREEZE = ROOT / "experiments_v3/configs/real_agent_test_freeze_v2.json"


class RealAgentFreezeV3Tests(unittest.TestCase):
    def test_frozen_test_files_match_registered_hashes(self):
        freeze = json.loads(FREEZE.read_text(encoding="utf-8"))

        self.assertEqual(freeze["status"], "frozen-before-sensenova-test-extension")
        self.assertFalse(freeze["protocol"]["test_split_may_guide_implementation"])
        self.assertTrue(
            freeze["sensenova_extension"]["outcome_driven_reruns_forbidden"]
        )
        for relative, expected in freeze["sha256"].items():
            actual = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
            self.assertEqual(actual, expected, relative)

    def test_primary_and_sensitivity_provider_roles_are_predeclared(self):
        freeze = json.loads(FREEZE.read_text(encoding="utf-8"))

        self.assertEqual(
            freeze["preserved_primary_test"]["providers"],
            ["deepseek", "mimo"],
        )
        self.assertEqual(
            freeze["sensenova_extension"]["provider"],
            "sensenova",
        )


if __name__ == "__main__":
    unittest.main()
