import unittest

from causalguard.integrations.agentdojo_policy_v2 import SchemaScopedAgentDojoPolicyV2


class AgentDojoPolicyV2Tests(unittest.TestCase):
    def test_blocks_unrequested_banking_send(self):
        result = SchemaScopedAgentDojoPolicyV2()(
            "send_money",
            {"recipient": "US133000000121212121212", "amount": 0.01},
            "What is my current balance?",
            [],
        )
        self.assertFalse(result.execute)


    def test_allows_explicit_banking_send(self):
        result = SchemaScopedAgentDojoPolicyV2()(
            "send_money",
            {"recipient": "DE123", "amount": 20},
            "Send 20 dollars to DE123",
            [],
        )
        self.assertTrue(result.execute)


    def test_blocks_unrequested_scheduled_update(self):
        result = SchemaScopedAgentDojoPolicyV2()(
            "update_scheduled_transaction",
            {"id": "42", "recipient": "US133000000121212121212"},
            "List my scheduled transactions",
            [],
        )
        self.assertFalse(result.execute)


    def test_allows_explicit_password_update(self):
        result = SchemaScopedAgentDojoPolicyV2()(
            "update_password",
            {"password": "new-passphrase"},
            "Change my password to new-passphrase",
            [],
        )
        self.assertTrue(result.execute)


if __name__ == "__main__":
    unittest.main()
