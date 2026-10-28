import unittest

from causalguard.guard.capability_registry import CapabilityRegistry
from causalguard.guard.trace_schema import SourceTrust


class CapabilityRegistryTests(unittest.TestCase):
    def test_runtime_reference_is_immutable_and_cannot_be_rebound(self):
        registry = CapabilityRegistry()
        registry.issue(
            "user_goal:target",
            value="approved@example.test",
            origin="user_goal:target",
            trust=SourceTrust.TRUSTED,
            data_categories=(),
        )

        with self.assertRaises(ValueError):
            registry.issue(
                "user_goal:target",
                value="substitute@example.test",
                origin="untrusted:observation",
                trust=SourceTrust.UNTRUSTED,
                data_categories=(),
            )

        self.assertEqual(
            registry.resolve("user_goal:target").value,
            "approved@example.test",
        )

    def test_derived_value_preserves_all_parent_origins_and_categories(self):
        registry = CapabilityRegistry()
        registry.issue(
            "file:report:body",
            value="Quarterly report",
            origin="file:report:body",
            trust=SourceTrust.DERIVED,
            data_categories=("project_confidential",),
        )
        registry.issue(
            "user_goal:format",
            value="brief",
            origin="user_goal:format",
            trust=SourceTrust.TRUSTED,
            data_categories=("general",),
        )

        derived = registry.derive(
            "derived:summary",
            parent_refs=("file:report:body", "user_goal:format"),
            value="Brief quarterly report",
        )

        self.assertEqual(
            derived.origins,
            frozenset({"file:report:body", "user_goal:format"}),
        )
        self.assertEqual(
            derived.data_categories,
            frozenset({"project_confidential", "general"}),
        )
        self.assertEqual(derived.trust, SourceTrust.DERIVED)

    def test_unknown_reference_is_rejected_instead_of_becoming_a_literal(self):
        registry = CapabilityRegistry()

        with self.assertRaises(KeyError):
            registry.resolve("forged:reference")


if __name__ == "__main__":
    unittest.main()
