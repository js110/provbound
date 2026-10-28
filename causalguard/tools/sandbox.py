from copy import deepcopy
from typing import Any

from causalguard.env.state import SandboxState


class SandboxTools:
    """Deterministic local tools; no method performs real I/O or network access."""

    def __init__(self, state: SandboxState):
        self.state = state

    def read_email(self, arguments: dict[str, Any]) -> dict[str, Any]:
        email_id = _required(arguments, "email_id")
        record = deepcopy(_lookup(self.state.emails, email_id, "email"))
        return _observation(
            record,
            origin=f"email:{email_id}",
            categories={
                "sender": ["contact"],
                "subject": ["general"],
                "body": ["general", "project_confidential"],
            },
        )

    def send_email(self, arguments: dict[str, Any]) -> dict[str, Any]:
        record = {
            "to": _required(arguments, "to"),
            "subject": _required(arguments, "subject"),
            "body": _required(arguments, "body"),
        }
        self.state.sent_emails.append(deepcopy(record))
        return self._commit("send_email", record)

    def reply_email(self, arguments: dict[str, Any]) -> dict[str, Any]:
        email_id = _required(arguments, "email_id")
        original = _lookup(self.state.emails, email_id, "email")
        return self.send_email(
            {
                "to": original["sender"],
                "subject": f"Re: {original['subject']}",
                "body": _required(arguments, "body"),
            }
        )

    def delete_email(self, arguments: dict[str, Any]) -> dict[str, Any]:
        email_id = _required(arguments, "email_id")
        _lookup(self.state.emails, email_id, "email")
        del self.state.emails[email_id]
        return self._commit("delete_email", {"email_id": email_id})

    def query_calendar(self, arguments: dict[str, Any]) -> dict[str, Any]:
        return _observation(
            deepcopy(self.state.calendar_events),
            origin="calendar:query",
            categories={"*": ["contact", "general"]},
        )

    def create_event(self, arguments: dict[str, Any]) -> dict[str, Any]:
        event_id = _required(arguments, "event_id")
        if event_id in self.state.calendar_events:
            raise ValueError(f"calendar event already exists: {event_id}")
        record = {
            "title": _required(arguments, "title"),
            "time": _required(arguments, "time"),
            "attendees": list(arguments.get("attendees", [])),
        }
        self.state.calendar_events[event_id] = record
        return self._commit("create_event", {"event_id": event_id, **record})

    def reschedule_event(self, arguments: dict[str, Any]) -> dict[str, Any]:
        event_id = _required(arguments, "event_id")
        event = _lookup(self.state.calendar_events, event_id, "calendar event")
        event["time"] = _required(arguments, "time")
        return self._commit(
            "reschedule_event", {"event_id": event_id, "time": event["time"]}
        )

    def add_attendee(self, arguments: dict[str, Any]) -> dict[str, Any]:
        event_id = _required(arguments, "event_id")
        attendee = _required(arguments, "attendee")
        event = _lookup(self.state.calendar_events, event_id, "calendar event")
        event.setdefault("attendees", []).append(attendee)
        return self._commit(
            "add_attendee", {"event_id": event_id, "attendee": attendee}
        )

    def read_file(self, arguments: dict[str, Any]) -> dict[str, Any]:
        file_id = _required(arguments, "file_id")
        record = deepcopy(_lookup(self.state.files, file_id, "file"))
        return _observation(
            record,
            origin=f"file:{file_id}",
            categories={"name": ["general"], "content": ["project_confidential"]},
        )

    def create_file(self, arguments: dict[str, Any]) -> dict[str, Any]:
        file_id = _required(arguments, "file_id")
        if file_id in self.state.files:
            raise ValueError(f"file already exists: {file_id}")
        record = {
            "name": _required(arguments, "name"),
            "content": _required(arguments, "content"),
            "shared_with": [],
        }
        self.state.files[file_id] = record
        return self._commit("create_file", {"file_id": file_id, **record})

    def share_file(self, arguments: dict[str, Any]) -> dict[str, Any]:
        file_id = _required(arguments, "file_id")
        target = _required(arguments, "target")
        record = _lookup(self.state.files, file_id, "file")
        record.setdefault("shared_with", []).append(target)
        return self._commit("share_file", {"file_id": file_id, "target": target})

    def delete_file(self, arguments: dict[str, Any]) -> dict[str, Any]:
        file_id = _required(arguments, "file_id")
        _lookup(self.state.files, file_id, "file")
        del self.state.files[file_id]
        return self._commit("delete_file", {"file_id": file_id})

    def retrieve_memory(self, arguments: dict[str, Any]) -> dict[str, Any]:
        memory_id = _required(arguments, "memory_id")
        record = deepcopy(_lookup(self.state.memories, memory_id, "memory"))
        return _observation(
            record,
            origin=f"memory:{memory_id}",
            categories={"content": ["general"]},
        )

    def write_memory(self, arguments: dict[str, Any]) -> dict[str, Any]:
        memory_id = _required(arguments, "memory_id")
        record = {"content": _required(arguments, "content")}
        self.state.memories[memory_id] = record
        return self._commit("write_memory", {"memory_id": memory_id, **record})

    def delete_memory(self, arguments: dict[str, Any]) -> dict[str, Any]:
        memory_id = _required(arguments, "memory_id")
        _lookup(self.state.memories, memory_id, "memory")
        del self.state.memories[memory_id]
        return self._commit("delete_memory", {"memory_id": memory_id})

    def http_get(self, arguments: dict[str, Any]) -> dict[str, Any]:
        url = _required(arguments, "url")
        resource = deepcopy(_lookup(self.state.http_resources, url, "HTTP resource"))
        return _observation(
            resource,
            origin=f"network:{url}",
            categories={"*": ["general"]},
        )

    def http_post(self, arguments: dict[str, Any]) -> dict[str, Any]:
        url = _required(arguments, "url")
        _lookup(self.state.http_resources, url, "HTTP resource")
        record = {"url": url, "payload": deepcopy(arguments.get("payload"))}
        self.state.http_posts.append(record)
        return self._commit("http_post", record)

    def _commit(self, action: str, arguments: dict[str, Any]) -> dict[str, Any]:
        event = {"action": action, "arguments": deepcopy(arguments)}
        self.state.side_effect_log.append(event)
        return {
            "content": {"status": "committed", **deepcopy(arguments)},
            "meta": {"side_effect_committed": True, "action": action},
        }


def _required(arguments: dict[str, Any], key: str) -> Any:
    value = arguments.get(key)
    if value is None or value == "":
        raise ValueError(f"missing required argument: {key}")
    return value


def _lookup(collection: dict[str, Any], key: str, kind: str) -> Any:
    if key not in collection:
        raise ValueError(f"unknown {kind}: {key}")
    return collection[key]


def _observation(
    content: Any,
    *,
    origin: str,
    categories: dict[str, list[str]],
) -> dict[str, Any]:
    return {
        "content": content,
        "meta": {
            "origin": origin,
            "trust": "untrusted",
            "data_categories": categories,
            "side_effect_committed": False,
        },
    }
