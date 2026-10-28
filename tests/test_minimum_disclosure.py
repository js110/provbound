import unittest

from causalguard.guard.authorization import DataCategory
from causalguard.guard.disclosure import (
    DisclosureDisposition,
    DisclosureStrategy,
    minimize_disclosure,
)
from causalguard.guard.trace_schema import ToolCall


class MinimumDisclosureTests(unittest.TestCase):
    def test_unauthorized_structured_field_can_be_removed_without_blocking_the_call(self):
        call = ToolCall(
            event_id="call-1",
            tool_name="send_email",
            arguments={
                "to": "advisor@example.com",
                "summary": "Paper review is ready",
                "bank_account": "demo-account-001",
            },
            user_goal="Send the paper summary.",
            argument_data_categories={
                "summary": frozenset({DataCategory.GENERAL.value}),
                "bank_account": frozenset({DataCategory.FINANCIAL.value}),
            },
        )

        result = minimize_disclosure(
            call,
            allowed_categories={DataCategory.GENERAL},
            strategies={DataCategory.FINANCIAL: DisclosureStrategy.REMOVE},
        )

        self.assertEqual(result.disposition, DisclosureDisposition.REDACTED)
        self.assertEqual(
            result.arguments,
            {
                "to": "advisor@example.com",
                "summary": "Paper review is ready",
            },
        )
        self.assertEqual(result.removed_fields, ("bank_account",))


if __name__ == "__main__":
    unittest.main()
