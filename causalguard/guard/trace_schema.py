from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class SourceTrust(str, Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    DERIVED = "derived"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class TraceEvent:
    event_id: str
    kind: str
    content: str
    trust: SourceTrust
    parents: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ToolCall:
    event_id: str
    tool_name: str
    arguments: dict[str, Any]
    user_goal: str
    argument_provenance: dict[str, frozenset[str]] = field(default_factory=dict)
    argument_trust: dict[str, SourceTrust] = field(default_factory=dict)
    argument_data_categories: dict[str, frozenset[str]] = field(default_factory=dict)
    purpose: str | None = None
    scope: frozenset[str] = field(default_factory=frozenset)
    timestamp: datetime | None = None
    session_id: str | None = None
