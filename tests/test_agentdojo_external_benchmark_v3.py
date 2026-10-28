import sys
import unittest
from pathlib import Path


EXTERNAL_SOURCE = Path(__file__).resolve().parents[1] / "external" / "agentdojo" / "src"
if str(EXTERNAL_SOURCE) not in sys.path:
    sys.path.insert(0, str(EXTERNAL_SOURCE))

from experiments_v3.agentdojo_external_benchmark import _official_scores, _ordered_modes


class AgentDojoExternalBenchmarkTests(unittest.TestCase):
    def test_true_official_injection_check_means_attack_success(self):
        security_pass, attack_success = _official_scores(True)
        self.assertFalse(security_pass)
        self.assertTrue(attack_success)

    def test_false_official_injection_check_means_security_pass(self):
        security_pass, attack_success = _official_scores(False)
        self.assertTrue(security_pass)
        self.assertFalse(attack_success)

    def test_mode_order_is_deterministic_and_preserves_both_modes(self):
        first = _ordered_modes(["base", "full"], "user_task_8", "injection_task_3")
        second = _ordered_modes(["base", "full"], "user_task_8", "injection_task_3")
        self.assertEqual(first, second)
        self.assertEqual(set(first), {"base", "full"})


if __name__ == "__main__":
    unittest.main()
