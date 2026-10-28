import re
from typing import Iterable

from causalguard.guard.authorization import DataCategory


class PrivacyPolicy:
    """High-confidence category rules for structured tool payloads."""

    _FIELD_TERMS = {
        DataCategory.CREDENTIAL: {
            "api_key",
            "credential",
            "password",
            "secret",
            "token",
        },
        DataCategory.FINANCIAL: {
            "bank",
            "card",
            "finance",
            "financial",
            "iban",
            "revenue",
            "salary",
        },
        DataCategory.HEALTH: {
            "diagnosis",
            "health",
            "medical",
            "medication",
        },
        DataCategory.IDENTITY: {
            "identity",
            "passport",
            "ssn",
        },
        DataCategory.CONTACT: {
            "contact",
            "email",
            "phone",
            "recipient",
        },
        DataCategory.PROJECT_CONFIDENTIAL: {
            "confidential",
            "project_secret",
            "roadmap",
            "source_code",
        },
    }

    def classify(
        self,
        *,
        field_name: str,
        value: object,
        declared: Iterable[str] = (),
    ) -> frozenset[str]:
        categories = {DataCategory(item) for item in declared}
        normalized_field = field_name.strip().lower()
        field_tokens = set(re.split(r"[^a-z0-9]+", normalized_field))
        text = str(value)
        lowered = text.lower()

        for category, terms in self._FIELD_TERMS.items():
            if field_tokens & terms or any(
                phrase in normalized_field for phrase in terms if "_" in phrase
            ):
                categories.add(category)

        if re.search(r"[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}", text):
            categories.add(DataCategory.CONTACT)
        if any(term in lowered for term in ("bank account", "credit card", "iban")):
            categories.add(DataCategory.FINANCIAL)

        if not categories:
            categories.add(DataCategory.GENERAL)
        return frozenset(category.value for category in categories)
