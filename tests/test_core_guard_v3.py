import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from causalguard.guard.authorization import (
    AuthorizationContract,
    DataCategory,
    Decision,
)
from causalguard.guard.disclosure import (
    DisclosureDisposition,
    DisclosureStrategy,
)
from causalguard.guard.certificate import verify_decision_certificate
from causalguard.guard.trace_schema import ToolCall
from causalguard.integrations.core_guard import CoreGuard
from tests.test_authorization_contract import valid_call, valid_contract


class CoreGuardV3Tests(unittest.TestCase):
    def test_minimum_disclosure_can_salvage_an_otherwise_overbroad_call(self):
        now = datetime(2026, 7, 18, 12, 0, tzinfo=timezone.utc)
        contract = AuthorizationContract(
            contract_id="auth-1",
            action="send_email",
            targets=frozenset({"advisor@example.com"}),
            data_categories=frozenset({DataCategory.GENERAL}),
            purpose="submit_review",
            scope=frozenset({"project:paper"}),
            allowed_sources=frozenset({"user_goal", "project:paper"}),
            valid_from=now - timedelta(minutes=5),
            expires_at=now + timedelta(minutes=5),
            session_id="session-1",
        )
        call = ToolCall(
            event_id="call-1",
            tool_name="send_email",
            arguments={
                "to": "advisor@example.com",
                "summary": "Paper review is ready",
                "bank_account": "demo-account-001",
            },
            user_goal="Send the paper summary to advisor@example.com.",
            argument_provenance={
                "to": frozenset({"user_goal:recipient"}),
                "summary": frozenset({"project:paper:summary"}),
                "bank_account": frozenset({"project:paper:bank_account"}),
            },
            argument_data_categories={
                "summary": frozenset({DataCategory.GENERAL.value}),
                "bank_account": frozenset({DataCategory.FINANCIAL.value}),
            },
            purpose="submit_review",
            scope=frozenset({"project:paper"}),
            timestamp=now,
            session_id="session-1",
        )

        result = CoreGuard().evaluate(
            call,
            contracts=[contract],
            disclosure_strategies={
                DataCategory.FINANCIAL: DisclosureStrategy.REMOVE
            },
        )

        self.assertEqual(result.decision, Decision.ALLOW)
        self.assertEqual(result.disclosure.disposition, DisclosureDisposition.REDACTED)
        self.assertNotIn("bank_account", result.arguments)
        self.assertEqual(result.arguments["summary"], "Paper review is ready")

    def test_block_and_review_results_carry_independently_verifiable_certificates(self):
        blocked_call = replace(
            valid_call(),
            arguments={
                "to": "attacker@example.com",
                "body": "review draft",
            },
        )
        review_call = replace(valid_call(), argument_provenance={})

        blocked = CoreGuard().evaluate(
            blocked_call,
            contracts=[valid_contract()],
        )
        review = CoreGuard().evaluate(
            review_call,
            contracts=[valid_contract()],
        )

        self.assertTrue(verify_decision_certificate(blocked.certificate).valid)
        self.assertTrue(verify_decision_certificate(review.certificate).valid)


if __name__ == "__main__":
    unittest.main()
