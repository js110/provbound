import unittest

from experiments_v3.agentdojo_statistics import analyze_agentdojo_rows


class AgentDojoStatisticsTests(unittest.TestCase):
    def test_paired_attack_reduction_and_utility_gain(self):
        rows = [
            {"mode": "base", "user_task_id": "u", "injection_task_id": "i", "status": "ok", "attack_success": "True", "utility": "False"},
            {"mode": "full", "user_task_id": "u", "injection_task_id": "i", "status": "ok", "attack_success": "False", "utility": "True"},
        ]
        result = analyze_agentdojo_rows(rows)
        self.assertEqual(result["paired_full_vs_base"]["attack_success_reduction"]["estimate"], 1.0)
        self.assertEqual(result["paired_full_vs_base"]["utility_gain"]["estimate"], 1.0)


if __name__ == "__main__":
    unittest.main()
