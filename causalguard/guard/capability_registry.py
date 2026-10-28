from dataclasses import dataclass
from typing import Any, Iterable

from causalguard.guard.trace_schema import SourceTrust


@dataclass(frozen=True)
class CapabilityValue:
    ref: str
    value: Any
    origins: frozenset[str]
    trust: SourceTrust
    data_categories: frozenset[str]


class CapabilityRegistry:
    """Binds model-visible references to immutable values and runtime provenance."""

    def __init__(self) -> None:
        self._values: dict[str, CapabilityValue] = {}

    def issue(
        self,
        ref: str,
        *,
        value: Any,
        origin: str,
        trust: SourceTrust,
        data_categories: Iterable[str],
    ) -> CapabilityValue:
        capability = CapabilityValue(
            ref=ref,
            value=value,
            origins=frozenset({origin}),
            trust=trust,
            data_categories=frozenset(data_categories),
        )
        existing = self._values.get(ref)
        if existing is not None and existing != capability:
            raise ValueError(f"capability reference cannot be rebound: {ref}")
        self._values[ref] = capability
        return capability

    def derive(
        self,
        ref: str,
        *,
        parent_refs: Iterable[str],
        value: Any,
    ) -> CapabilityValue:
        parents = tuple(self.resolve(parent) for parent in parent_refs)
        if not parents:
            raise ValueError("derived capability requires at least one parent")
        capability = CapabilityValue(
            ref=ref,
            value=value,
            origins=frozenset(
                origin for parent in parents for origin in parent.origins
            ),
            trust=_derived_trust(parents),
            data_categories=frozenset(
                category
                for parent in parents
                for category in parent.data_categories
            ),
        )
        existing = self._values.get(ref)
        if existing is not None and existing != capability:
            raise ValueError(f"capability reference cannot be rebound: {ref}")
        self._values[ref] = capability
        return capability

    def resolve(self, ref: str) -> CapabilityValue:
        if ref not in self._values:
            raise KeyError(f"unknown capability reference: {ref}")
        return self._values[ref]

    def items(self) -> tuple[tuple[str, CapabilityValue], ...]:
        return tuple(self._values.items())


def _derived_trust(parents: tuple[CapabilityValue, ...]) -> SourceTrust:
    trusts = {parent.trust for parent in parents}
    if SourceTrust.UNKNOWN in trusts:
        return SourceTrust.UNKNOWN
    if SourceTrust.UNTRUSTED in trusts:
        return SourceTrust.UNTRUSTED
    return SourceTrust.DERIVED
