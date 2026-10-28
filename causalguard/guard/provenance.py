from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Generic, Iterable, TypeVar

from causalguard.guard.trace_schema import SourceTrust, ToolCall


T = TypeVar("T")
R = TypeVar("R")


@dataclass(frozen=True)
class TaggedValue(Generic[T]):
    value: T
    origin_ids: frozenset[str]
    trust: SourceTrust
    data_categories: frozenset[str]
    transforms: tuple[str, ...] = ()

    @classmethod
    def from_source(
        cls,
        value: T,
        *,
        origin_id: str,
        trust: SourceTrust,
        data_categories: Iterable[str] = (),
    ) -> "TaggedValue[T]":
        if not origin_id.strip():
            raise ValueError("origin_id must not be empty")
        return cls(
            value=value,
            origin_ids=frozenset({origin_id}),
            trust=trust,
            data_categories=frozenset(data_categories),
        )


def combine_tagged(
    values: Iterable[TaggedValue[T]],
    *,
    transform: str,
    combine: Callable[[list[T]], R],
) -> TaggedValue[R]:
    inputs = list(values)
    if not inputs:
        raise ValueError("at least one tagged value is required")
    if not transform.strip():
        raise ValueError("transform must not be empty")
    return TaggedValue(
        value=combine([item.value for item in inputs]),
        origin_ids=frozenset(
            origin for item in inputs for origin in item.origin_ids
        ),
        trust=_derived_trust(inputs),
        data_categories=frozenset(
            category
            for item in inputs
            for category in item.data_categories
        ),
        transforms=tuple(
            step for item in inputs for step in item.transforms
        )
        + (transform,),
    )


def tag_structured_result(
    *,
    observation_id: str,
    result: dict[str, T],
    trust: SourceTrust,
    categories_by_field: dict[str, Iterable[str]] | None = None,
) -> dict[str, TaggedValue[T]]:
    if not observation_id.strip():
        raise ValueError("observation_id must not be empty")
    category_map = categories_by_field or {}
    return {
        field: TaggedValue.from_source(
            value,
            origin_id=f"{observation_id}:{field}",
            trust=trust,
            data_categories=category_map.get(field, ()),
        )
        for field, value in result.items()
    }


def tool_call_from_tagged_arguments(
    *,
    event_id: str,
    tool_name: str,
    arguments: dict[str, TaggedValue[Any]],
    user_goal: str,
    purpose: str,
    scope: Iterable[str],
    timestamp: datetime,
    session_id: str,
) -> ToolCall:
    return ToolCall(
        event_id=event_id,
        tool_name=tool_name,
        arguments={name: tagged.value for name, tagged in arguments.items()},
        user_goal=user_goal,
        argument_provenance={
            name: tagged.origin_ids for name, tagged in arguments.items()
        },
        argument_trust={
            name: tagged.trust for name, tagged in arguments.items()
        },
        argument_data_categories={
            name: tagged.data_categories for name, tagged in arguments.items()
        },
        purpose=purpose,
        scope=frozenset(scope),
        timestamp=timestamp,
        session_id=session_id,
    )


def _derived_trust(values: list[TaggedValue[object]]) -> SourceTrust:
    if any(item.trust == SourceTrust.UNTRUSTED for item in values):
        return SourceTrust.UNTRUSTED
    if any(item.trust == SourceTrust.UNKNOWN for item in values):
        return SourceTrust.UNKNOWN
    return SourceTrust.DERIVED
