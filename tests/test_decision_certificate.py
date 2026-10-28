from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
import unittest

from causalguard.guard.authorization import (
    DataCategory,
    Decision,
    evaluate_authorization,
)
from causalguard.guard.certificate import (
    build_decision_certificate,
    explain_verified_certificate,
    verify_certificate_minimality,
    verify_decision_certificate,
)
from causalguard.guard.trace_schema import SourceTrust
from tests.test_authorization_contract import NOW, valid_call, valid_contract


class DecisionCertificateTests(unittest.TestCase):
    def test_target_violation_certificate_is_independently_verifiable(self):
        call = replace(
            valid_call(),
            arguments={
                "to": "attacker@example.com",
                "body": "review draft",
            },
        )
        decision = evaluate_authorization(call, contracts=[valid_contract()])
        self.assertEqual(decision.decision, Decision.BLOCK)

        certificate = build_decision_certificate(call, decision)
        verification = verify_decision_certificate(certificate)

        self.assertTrue(verification.valid)
        self.assertEqual(verification.proved_predicates, ("target_not_authorized",))
        self.assertEqual(set(certificate["argument_evidence"]), {"to"})
        self.assertEqual(
            set(certificate["argument_evidence"]["to"]),
            {"value", "origin_ids"},
        )
        self.assertTrue(verify_certificate_minimality(certificate).minimal)

        tampered = deepcopy(certificate)
        del tampered["argument_evidence"]["to"]["origin_ids"]
        self.assertFalse(verify_decision_certificate(tampered).valid)

        explanation = explain_verified_certificate(certificate)
        self.assertIn("attacker@example.com", explanation)
        with self.assertRaises(ValueError):
            explain_verified_certificate(tampered)

    def test_data_category_violation_certificate_links_category_to_argument_origin(self):
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
        decision = evaluate_authorization(call, contracts=[valid_contract()])
        self.assertEqual(decision.decision, Decision.BLOCK)

        certificate = build_decision_certificate(call, decision)
        verification = verify_decision_certificate(certificate)

        self.assertTrue(verification.valid)
        self.assertEqual(
            verification.proved_predicates,
            ("data_category_not_authorized",),
        )
        self.assertEqual(set(certificate["argument_evidence"]), {"body"})
        tampered = deepcopy(certificate)
        tampered["argument_evidence"]["body"]["data_categories"] = []
        self.assertFalse(verify_decision_certificate(tampered).valid)

    def test_purpose_violation_certificate_uses_only_the_recorded_call_purpose(self):
        call = replace(valid_call(), purpose="marketing_outreach")
        decision = evaluate_authorization(call, contracts=[valid_contract()])

        certificate = build_decision_certificate(call, decision)
        verification = verify_decision_certificate(certificate)

        self.assertTrue(verification.valid)
        self.assertEqual(
            verification.proved_predicates,
            ("purpose_not_authorized",),
        )
        self.assertEqual(
            certificate["context_evidence"],
            {"purpose": "marketing_outreach"},
        )
        tampered = deepcopy(certificate)
        tampered["context_evidence"]["purpose"] = "submit_review"
        self.assertFalse(verify_decision_certificate(tampered).valid)

    def test_every_public_violation_predicate_has_an_independent_verifier(self):
        base = valid_call()
        contract = valid_contract()
        cases = [
            (base, [], "missing_authorization"),
            (replace(base, argument_provenance={}), [contract], "provenance_unknown"),
            (
                replace(
                    base,
                    argument_trust={"body": SourceTrust.UNKNOWN},
                ),
                [contract],
                "argument_trust_unknown",
            ),
            (
                replace(base, argument_data_categories={}),
                [contract],
                "data_categories_unknown",
            ),
            (
                replace(
                    base,
                    argument_data_categories={
                        "body": frozenset({"vendor_unknown"})
                    },
                ),
                [contract],
                "data_category_invalid",
            ),
            (replace(base, timestamp=None), [contract], "timestamp_unknown"),
            (
                replace(
                    base,
                    arguments={
                        "to": "attacker@example.com",
                        "body": "review draft",
                    },
                ),
                [contract],
                "target_not_authorized",
            ),
            (
                replace(
                    base,
                    argument_data_categories={
                        "body": frozenset({DataCategory.FINANCIAL.value})
                    },
                ),
                [contract],
                "data_category_not_authorized",
            ),
            (
                replace(base, purpose="marketing_outreach"),
                [contract],
                "purpose_not_authorized",
            ),
            (
                replace(base, scope=base.scope | {"drive:all"}),
                [contract],
                "scope_not_authorized",
            ),
            (
                replace(
                    base,
                    argument_provenance={
                        "to": frozenset({"user_goal"}),
                        "body": frozenset({"web:untrusted"}),
                    },
                ),
                [contract],
                "source_not_authorized",
            ),
            (
                replace(base, timestamp=NOW + timedelta(minutes=6)),
                [contract],
                "authorization_expired",
            ),
            (
                replace(base, timestamp=NOW - timedelta(minutes=6)),
                [contract],
                "authorization_not_yet_valid",
            ),
            (
                replace(base, session_id="session-other"),
                [contract],
                "session_not_authorized",
            ),
            (
                base,
                [replace(contract, action="upload_file")],
                "action_not_authorized",
            ),
        ]

        for call, contracts, expected_predicate in cases:
            with self.subTest(predicate=expected_predicate):
                decision = evaluate_authorization(call, contracts=contracts)
                self.assertEqual(
                    decision.violations[0].predicate,
                    expected_predicate,
                )
                certificate = build_decision_certificate(
                    call,
                    decision,
                    contracts=contracts,
                )
                verification = verify_decision_certificate(certificate)
                self.assertTrue(verification.valid, verification.errors)
                self.assertEqual(
                    verification.proved_predicates,
                    (expected_predicate,),
                )
                minimality = verify_certificate_minimality(certificate)
                self.assertTrue(
                    minimality.minimal,
                    minimality.removable_evidence_paths,
                )


if __name__ == "__main__":
    unittest.main()
