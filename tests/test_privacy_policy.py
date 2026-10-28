import unittest

from causalguard.guard.authorization import DataCategory
from causalguard.guard.privacy_policy import PrivacyPolicy


class PrivacyPolicyTests(unittest.TestCase):
    def test_structured_field_and_value_can_have_multiple_privacy_categories(self):
        policy = PrivacyPolicy()

        categories = policy.classify(
            field_name="finance_contact_note",
            value="Send the bank account summary to analyst@example.com",
        )

        self.assertEqual(
            categories,
            frozenset(
                {
                    DataCategory.FINANCIAL.value,
                    DataCategory.CONTACT.value,
                }
            ),
        )


if __name__ == "__main__":
    unittest.main()
