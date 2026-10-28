import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from causalguard.guard.authorization import (
    AuthorizationContract,
    DataCategory,
    Decision,
    evaluate_authorization,
)
from causalguard.guard.trace_schema import SourceTrust, ToolCall


NOW = datetime(2026, 7, 18, 12, 0, tzinfo=timezone.utc)


def valid_contract() -> AuthorizationContract:
    return AuthorizationContract(
        contract_id="auth-1",
        action="send_email",
        targets=frozenset({"advisor@example.com"}),
        data_categories=frozenset({DataCategory.PROJECT_CONFIDENTIAL}),
        purpose="submit_review",
        scope=frozenset({"project:paper", "email:latest"}),
        allowed_sources=frozenset({"user_goal", "email:latest"}),
        valid_from=NOW - timedelta(minutes=5),
        expires_at=NOW + timedelta(minutes=5),
        session_id="session-1",
    )


def valid_call() -> ToolCall:
    return ToolCall(
        event_id="call-1",
        tool_name="send_email",
        arguments={"to": "advisor@example.com", "body": "review draft"},
        user_goal="Send the review draft to advisor@example.com.",
        argument_provenance={
            "to": frozenset({"user_goal"}),
            "body": frozenset({"email:latest"}),
        },
        argument_data_categories={
            "body": frozenset({DataCategory.PROJECT_CONFIDENTIAL.value})
        },
        purpose="submit_review",
        scope=frozenset({"project:paper", "email:latest"}),
        timestamp=NOW,
        session_id="session-1",
    )


class AuthorizationContractTests(unittest.TestCase):
    def test_high_risk_action_without_any_contract_is_blocked(self):
        call = ToolCall(
            event_id="call-1",
            tool_name="send_email",
            arguments={"to": "advisor@example.com", "body": "report"},
            user_goal="Send the report.",
        )

        result = evaluate_authorization(call, contracts=[])

        self.assertEqual(result.decision, Decision.BLOCK)
        self.assertEqual(
            [violation.predicate for violation in result.violations],
            ["missing_authorization"],
        )

    def test_contract_covering_every_call_dimension_allows_the_action(self):
        contract = valid_contract()
        call = valid_call()

        result = evaluate_authorization(call, contracts=[contract])

        self.assertEqual(result.decision, Decision.ALLOW)
        self.assertEqual(result.violations, ())
        self.assertEqual(result.matched_contract_id, "auth-1")

    def test_target_substitution_is_blocked_with_a_target_predicate(self):
        call = replace(
            valid_call(),
            arguments={"to": "attacker@example.com", "body": "review draft"},
        )

        result = evaluate_authorization(call, contracts=[valid_contract()])

        self.assertEqual(result.decision, Decision.BLOCK)
        self.assertEqual(
            [violation.predicate for violation in result.violations],
            ["target_not_authorized"],
        )
        self.assertEqual(result.violations[0].actual, "attacker@example.com")

    def test_unauthorized_data_category_is_blocked(self):
        call = replace(
            valid_call(),
            argument_data_categories={
                "body": frozenset(
                    {
                        DataCategory.PROJECT_CONFIDENTIAL.value,
                        DataCategory.FINANCIAL.value,
                    }
                )
            },
        )

        result = evaluate_authorization(call, contracts=[valid_contract()])

        self.assertEqual(result.decision, Decision.BLOCK)
        self.assertEqual(
            [violation.predicate for violation in result.violations],
            ["data_category_not_authorized"],
        )
        self.assertEqual(result.violations[0].actual, ["financial"])

    def test_purpose_substitution_is_blocked(self):
        call = replace(valid_call(), purpose="marketing_outreach")

        result = evaluate_authorization(call, contracts=[valid_contract()])

        self.assertEqual(result.decision, Decision.BLOCK)
        self.assertEqual(
            [violation.predicate for violation in result.violations],
            ["purpose_not_authorized"],
        )
        self.assertEqual(result.violations[0].actual, "marketing_outreach")

    def test_scope_expansion_is_blocked(self):
        call = replace(
            valid_call(),
            scope=frozenset({"project:paper", "email:latest", "drive:all"}),
        )

        result = evaluate_authorization(call, contracts=[valid_contract()])

        self.assertEqual(result.decision, Decision.BLOCK)
        self.assertEqual(
            [violation.predicate for violation in result.violations],
            ["scope_not_authorized"],
        )
        self.assertEqual(result.violations[0].actual, ["drive:all"])

    def test_argument_from_an_unauthorized_source_is_blocked(self):
        call = replace(
            valid_call(),
            argument_provenance={
                "to": frozenset({"user_goal"}),
                "body": frozenset({"untrusted:web-page"}),
            },
        )

        result = evaluate_authorization(call, contracts=[valid_contract()])

        self.assertEqual(result.decision, Decision.BLOCK)
        self.assertEqual(
            [violation.predicate for violation in result.violations],
            ["source_not_authorized"],
        )
        self.assertEqual(result.violations[0].actual, ["untrusted:web-page"])

    def test_authorized_source_namespace_covers_field_level_origins(self):
        call = replace(
            valid_call(),
            argument_provenance={
                "to": frozenset({"user_goal:recipient"}),
                "body": frozenset({"email:latest:body"}),
            },
        )

        result = evaluate_authorization(call, contracts=[valid_contract()])

        self.assertEqual(result.decision, Decision.ALLOW)
        self.assertEqual(result.matched_contract_id, "auth-1")

    def test_expired_contract_is_blocked(self):
        call = replace(valid_call(), timestamp=NOW + timedelta(minutes=6))

        result = evaluate_authorization(call, contracts=[valid_contract()])

        self.assertEqual(result.decision, Decision.BLOCK)
        self.assertEqual(
            [violation.predicate for violation in result.violations],
            ["authorization_expired"],
        )

    def test_contract_cannot_be_used_before_valid_from(self):
        call = replace(valid_call(), timestamp=NOW - timedelta(minutes=6))

        result = evaluate_authorization(call, contracts=[valid_contract()])

        self.assertEqual(result.decision, Decision.BLOCK)
        self.assertEqual(
            [violation.predicate for violation in result.violations],
            ["authorization_not_yet_valid"],
        )

    def test_contract_cannot_be_reused_in_another_session(self):
        call = replace(valid_call(), session_id="session-2")

        result = evaluate_authorization(call, contracts=[valid_contract()])

        self.assertEqual(result.decision, Decision.BLOCK)
        self.assertEqual(
            [violation.predicate for violation in result.violations],
            ["session_not_authorized"],
        )
        self.assertEqual(result.violations[0].actual, "session-2")

    def test_missing_argument_provenance_requires_review_instead_of_allow(self):
        call = replace(valid_call(), argument_provenance={})

        result = evaluate_authorization(call, contracts=[valid_contract()])

        self.assertEqual(result.decision, Decision.REVIEW)
        self.assertEqual(
            [violation.predicate for violation in result.violations],
            ["provenance_unknown"],
        )
        self.assertEqual(result.violations[0].actual, ["body", "to"])

    def test_explicitly_unknown_argument_trust_requires_review(self):
        call = replace(
            valid_call(),
            argument_trust={
                "to": SourceTrust.TRUSTED,
                "body": SourceTrust.UNKNOWN,
            },
        )

        result = evaluate_authorization(call, contracts=[valid_contract()])

        self.assertEqual(result.decision, Decision.REVIEW)
        self.assertEqual(
            [violation.predicate for violation in result.violations],
            ["argument_trust_unknown"],
        )
        self.assertEqual(result.violations[0].actual, ["body"])

    def test_missing_execution_time_requires_review(self):
        call = replace(valid_call(), timestamp=None)

        result = evaluate_authorization(call, contracts=[valid_contract()])

        self.assertEqual(result.decision, Decision.REVIEW)
        self.assertEqual(
            [violation.predicate for violation in result.violations],
            ["timestamp_unknown"],
        )

    def test_missing_payload_data_category_requires_review(self):
        call = replace(valid_call(), argument_data_categories={})

        result = evaluate_authorization(call, contracts=[valid_contract()])

        self.assertEqual(result.decision, Decision.REVIEW)
        self.assertEqual(
            [violation.predicate for violation in result.violations],
            ["data_categories_unknown"],
        )
        self.assertEqual(result.violations[0].actual, ["body"])

    def test_unknown_category_label_requires_review_instead_of_crashing(self):
        call = replace(
            valid_call(),
            argument_data_categories={
                "body": frozenset({"vendor_specific_unknown_category"})
            },
        )

        result = evaluate_authorization(call, contracts=[valid_contract()])

        self.assertEqual(result.decision, Decision.REVIEW)
        self.assertEqual(
            [violation.predicate for violation in result.violations],
            ["data_category_invalid"],
        )

    def test_human_confirmation_can_resolve_review_but_not_change_the_contract(self):
        call = replace(valid_call(), argument_provenance={})

        result = evaluate_authorization(
            call,
            contracts=[valid_contract()],
            human_confirmed=True,
        )

        self.assertEqual(result.decision, Decision.ALLOW)
        self.assertEqual(result.matched_contract_id, "auth-1")

    def test_contract_for_another_action_does_not_authorize_this_tool(self):
        contract = replace(valid_contract(), action="upload_file")

        result = evaluate_authorization(valid_call(), contracts=[contract])

        self.assertEqual(result.decision, Decision.BLOCK)
        self.assertEqual(
            [violation.predicate for violation in result.violations],
            ["action_not_authorized"],
        )
        self.assertEqual(result.violations[0].actual, "send_email")


if __name__ == "__main__":
    unittest.main()
