from dataclasses import dataclass, field


@dataclass
class MockEmailTool:
    latest_email: str
    sent_messages: list[dict[str, str]] = field(default_factory=list)

    def read_email(self) -> str:
        return self.latest_email

    def send_email(self, to: str, body: str) -> None:
        self.sent_messages.append({"to": to, "body": body})
