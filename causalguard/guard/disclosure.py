from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Mapping

from causalguard.guard.authorization import DataCategory
from causalguard.guard.trace_schema import ToolCall


class DisclosureStrategy(str, Enum):
    REMOVE = "remove"
    ANONYMIZE = "anonymize"
    BLOCK = "block"


class DisclosureDisposition(str, Enum):
    PASS = "pass"
    REDACTED = "redacted"
    BLOCKED = "blocked"


@dataclass(frozen=True)
class DisclosureResult:
    disposition: DisclosureDisposition
    arguments: dict[str, object]
    removed_fields: tuple[str, ...] = ()
    anonymized_fields: tuple[str, ...] = ()
    unauthorized_categories: tuple[str, ...] = ()


def minimize_disclosure(
    call: ToolCall,
    *,
    allowed_categories: Iterable[DataCategory],
    strategies: Mapping[DataCategory, DisclosureStrategy],
) -> DisclosureResult:
    allowed = set(allowed_categories)
    output = dict(call.arguments)
    removed: list[str] = []
    anonymized: list[str] = []
    unauthorized_seen: set[DataCategory] = set()

    for field, raw_categories in call.argument_data_categories.items():
        categories = {DataCategory(item) for item in raw_categories}
        unauthorized = categories - allowed
        if not unauthorized:
            continue
        unauthorized_seen.update(unauthorized)
        field_strategies = {
            strategies.get(category, DisclosureStrategy.BLOCK)
            for category in unauthorized
        }
        if DisclosureStrategy.BLOCK in field_strategies:
            return DisclosureResult(
                disposition=DisclosureDisposition.BLOCKED,
                arguments={},
                unauthorized_categories=tuple(
                    sorted(category.value for category in unauthorized_seen)
                ),
            )
        if DisclosureStrategy.REMOVE in field_strategies:
            output.pop(field, None)
            removed.append(field)
        else:
            output[field] = "[REDACTED]"
            anonymized.append(field)

    disposition = (
        DisclosureDisposition.REDACTED
        if removed or anonymized
        else DisclosureDisposition.PASS
    )
    return DisclosureResult(
        disposition=disposition,
        arguments=output,
        removed_fields=tuple(sorted(removed)),
        anonymized_fields=tuple(sorted(anonymized)),
        unauthorized_categories=tuple(
            sorted(category.value for category in unauthorized_seen)
        ),
    )
