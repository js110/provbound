from copy import deepcopy
from dataclasses import asdict, dataclass, field
import hashlib
import json
from typing import Any


@dataclass
class SandboxState:
    emails: dict[str, dict[str, Any]] = field(default_factory=dict)
    calendar_events: dict[str, dict[str, Any]] = field(default_factory=dict)
    files: dict[str, dict[str, Any]] = field(default_factory=dict)
    memories: dict[str, dict[str, Any]] = field(default_factory=dict)
    http_resources: dict[str, Any] = field(default_factory=dict)
    sent_emails: list[dict[str, Any]] = field(default_factory=list)
    http_posts: list[dict[str, Any]] = field(default_factory=list)
    side_effect_log: list[dict[str, Any]] = field(default_factory=list)

    def fresh_clone(self) -> "SandboxState":
        return deepcopy(self)

    def fingerprint(self) -> str:
        payload = json.dumps(
            asdict(self),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def has_sent_email(self, recipient: str) -> bool:
        normalized = recipient.strip().lower()
        return any(
            str(item.get("to", "")).strip().lower() == normalized
            for item in self.sent_emails
        )
