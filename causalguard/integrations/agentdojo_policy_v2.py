"""Schema-scoped AgentDojo policy with banking mutation coverage.

This adapter extends the frozen workspace policy only through a declarative
mutation taxonomy derived from public tool names.  It does not consume task
IDs, gold traces, injection goals, or attack text.
"""

from __future__ import annotations

from collections.abc import Sequence
import re
from typing import Any

from causalguard.integrations.agentdojo_policy import (
    QueryScopedAgentDojoPolicy,
    ROUTING_KEYS,
    _leaf_arguments,
    _matches_observation,
    _normalize,
    _observation_values,
    _query_grounded,
    _result,
)


MUTATING_VERB_ALIASES = {
    "send": frozenset({"send", "pay", "transfer"}),
    "schedule": frozenset({"schedule", "plan", "set"}),
    "update": frozenset({"update", "change", "modify", "edit", "reschedule"}),
}

OBJECT_ALIASES = {
    "money": frozenset({"money", "payment", "transaction", "transfer", "funds", "dollar", "dollars"}),
    "transaction": frozenset({"transaction", "payment", "transfer"}),
    "scheduled": frozenset({"scheduled", "recurring", "transaction", "payment"}),
    "password": frozenset({"password", "credentials", "login"}),
    "user": frozenset({"user", "account", "profile", "information", "info"}),
    "info": frozenset({"information", "info", "profile", "account"}),
}


class SchemaScopedAgentDojoPolicyV2(QueryScopedAgentDojoPolicy):
    """Apply the frozen query/provenance rules to banking mutation schemas."""

    def __call__(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        query: str,
        messages: Sequence[Any],
    ):
        verb = tool_name.split("_", 1)[0].lower()
        if verb not in MUTATING_VERB_ALIASES:
            return super().__call__(tool_name, arguments, query, messages)

        if not _banking_action_authorized(tool_name, query):
            return _result(False, {}, "block", "action_not_explicitly_authorized")

        trusted, untrusted = _observation_values(messages)
        query_norm = _normalize(query)
        for key, value in _leaf_arguments(arguments):
            value_norm = _normalize(value)
            if not value_norm or _query_grounded(value_norm, query_norm):
                continue
            from_untrusted = _matches_observation(value_norm, untrusted)
            from_trusted = _matches_observation(value_norm, trusted)
            if key.lower() in ROUTING_KEYS and from_untrusted and not from_trusted:
                return _result(False, {}, "block", f"untrusted_routing_value:{key}")
        return _result(True, arguments, "allow", "query_scoped_authorization")


def _banking_action_authorized(tool_name: str, query: str) -> bool:
    parts = tool_name.lower().split("_")
    verb = parts[0]
    words = set(re.findall(r"[a-z0-9]+", query.lower()))
    if not words.intersection(MUTATING_VERB_ALIASES[verb]):
        return False

    object_words: set[str] = set()
    for part in parts[1:]:
        object_words.add(part)
        object_words.update(OBJECT_ALIASES.get(part, ()))
    return not object_words or bool(words.intersection(object_words))
