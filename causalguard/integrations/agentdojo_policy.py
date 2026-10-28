"""Task-agnostic, query-scoped authorization for AgentDojo tool calls.

The policy deliberately consumes only the live user query, proposed call, and
prior messages. It has no interface for task IDs, gold traces, injection goals,
or attack strings.
"""

from __future__ import annotations

from collections.abc import Sequence
import json
import re
from typing import Any

import yaml

from causalguard.integrations.pre_execution import PreExecutionResult


COMMIT_VERBS = frozenset(
    {"send", "delete", "create", "cancel", "reschedule", "add", "append", "share", "invite", "remove"}
)
VERB_ALIASES = {
    "send": frozenset({"send", "email", "mail", "message", "forward"}),
    "delete": frozenset({"delete", "remove"}),
    "create": frozenset({"create", "book", "schedule", "new"}),
    "cancel": frozenset({"cancel"}),
    "reschedule": frozenset({"reschedule", "move"}),
    "add": frozenset({"add", "invite", "include"}),
    "append": frozenset({"append", "add", "write", "update"}),
    "share": frozenset({"share"}),
    "invite": frozenset({"invite", "add"}),
    "remove": frozenset({"remove", "delete"}),
}
UNTRUSTED_CONTENT_KEYS = frozenset(
    {"body", "content", "description", "text", "subject", "message", "notes", "summary"}
)
ROUTING_KEYS = frozenset(
    {
        "address",
        "email",
        "to",
        "recipient",
        "recipients",
        "participants",
        "email_id",
        "event_id",
        "file_id",
        "filename",
        "user",
        "channel",
    }
)
STRONG_ACTION_VERBS = frozenset(
    {"cancel", "delete", "reschedule", "share", "append", "invite", "remove"}
)


class QueryScopedAgentDojoPolicy:
    """Authorize commits from user intent and field-level observation provenance."""

    def __call__(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        query: str,
        messages: Sequence[Any],
    ) -> PreExecutionResult:
        verb = tool_name.split("_", 1)[0].lower()
        if verb not in COMMIT_VERBS:
            return _result(True, arguments, "allow", "read_only_tool")

        if not _action_authorized(tool_name, query) and not _delegation_authorized(
            query, messages
        ):
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
                return _result(
                    False,
                    {},
                    "block",
                    f"untrusted_routing_value:{key}",
                )
        return _result(True, arguments, "allow", "query_scoped_authorization")


def _action_authorized(tool_name: str, query: str) -> bool:
    parts = tool_name.lower().split("_")
    verb = parts[0]
    words = set(re.findall(r"[a-z0-9]+", query.lower()))
    if not words.intersection(VERB_ALIASES.get(verb, frozenset({verb}))):
        return False
    if verb in STRONG_ACTION_VERBS and verb in words:
        return True

    object_parts = {
        part
        for part in parts[1:]
        if part not in {"to", "by", "calendar", "event", "participants"}
    }
    object_aliases = set(object_parts)
    if "email" in parts:
        object_aliases.update({"email", "mail"})
    if "file" in parts:
        object_aliases.update({"file", "document", "drive", "list"})
    if "event" in parts or "calendar" in parts:
        object_aliases.update({"event", "calendar", "meeting", "appointment", "lunch", "trip", "reunion"})
    return not object_aliases or bool(words.intersection(object_aliases))


def _delegation_authorized(query: str, messages: Sequence[Any]) -> bool:
    query_words = set(re.findall(r"[a-z0-9]+", query.lower()))
    delegation = bool(query_words.intersection({"actions", "tasks"})) and bool(
        query_words.intersection({"do", "perform", "execute"})
    )
    if not delegation or "email" not in query_words:
        return False

    for index, message in enumerate(messages):
        if message.get("role") != "assistant":
            continue
        for call in message.get("tool_calls") or []:
            if call.function != "search_emails":
                continue
            grounded = [
                _normalize(value)
                for value in call.args.values()
                if _query_grounded(_normalize(value), _normalize(query))
            ]
            if len(grounded) < 2:
                continue
            for later in messages[index + 1 :]:
                if later.get("role") != "tool" or later.get("tool_call_id") != call.id:
                    continue
                output = _normalize(_message_text(later.get("content")))
                if all(value in output for value in grounded):
                    return True
    return False


def _observation_values(messages: Sequence[Any]) -> tuple[set[str], set[str]]:
    trusted: set[str] = set()
    untrusted: set[str] = set()
    for message in messages:
        if message.get("role") != "tool":
            continue
        text = _message_text(message.get("content"))
        try:
            parsed = yaml.safe_load(text)
        except yaml.YAMLError:
            parsed = None
        if parsed is None or isinstance(parsed, str):
            normalized = _normalize(text)
            if normalized:
                untrusted.add(normalized)
            continue
        _collect_values(parsed, (), trusted, untrusted)
    return trusted, untrusted


def _collect_values(
    value: Any,
    path: tuple[str, ...],
    trusted: set[str],
    untrusted: set[str],
) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            _collect_values(item, (*path, str(key).lower()), trusted, untrusted)
        return
    if isinstance(value, list):
        for item in value:
            _collect_values(item, path, trusted, untrusted)
        return
    normalized = _normalize(value)
    if not normalized:
        return
    if any(key in UNTRUSTED_CONTENT_KEYS for key in path):
        untrusted.add(normalized)
    else:
        trusted.add(normalized)


def _leaf_arguments(value: Any, path: tuple[str, ...] = ()):
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _leaf_arguments(item, (*path, str(key)))
    elif isinstance(value, list):
        for item in value:
            yield from _leaf_arguments(item, path)
    else:
        yield (path[-1] if path else "argument"), value


def _message_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(_message_text(item) for item in content)
    if isinstance(content, dict):
        if "content" in content and len(content) <= 3:
            return _message_text(content["content"])
        return json.dumps(content, ensure_ascii=False, sort_keys=True)
    return str(content)


def _normalize(value: Any) -> str:
    text = str(value).lower().strip()
    return re.sub(r"\s+", " ", text)


def _query_grounded(value: str, query: str) -> bool:
    if len(value) >= 3 and value in query:
        return True
    if "@" in value or value.startswith("http"):
        return value in query
    tokens = {token for token in re.findall(r"[a-z0-9]+", value) if len(token) >= 4}
    return bool(tokens) and tokens.issubset(set(re.findall(r"[a-z0-9]+", query)))


def _matches_observation(value: str, observations: set[str]) -> bool:
    for observed in observations:
        if value == observed:
            return True
        # Short identifiers such as file/event IDs must not be tainted merely
        # because their digits occur inside a date or a longer content field.
        if len(value) >= 5 and len(observed) >= 5 and (
            observed in value or value in observed
        ):
            return True
    return False


def _result(
    execute: bool,
    arguments: dict[str, Any],
    decision: str,
    reason: str,
) -> PreExecutionResult:
    payload = {
        "decision": decision,
        "executed": execute,
        "reason": reason,
    }
    return PreExecutionResult(
        execute=execute,
        arguments=dict(arguments),
        tool_message=json.dumps(payload, ensure_ascii=False, sort_keys=True),
        decision=decision,
    )
