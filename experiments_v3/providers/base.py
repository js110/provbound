from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass(frozen=True)
class ProviderSpec:
    """Connection metadata that may differ between model providers."""

    name: str
    model: str
    base_url: str
    api_key_env: str


class MissingCredentialError(RuntimeError):
    """Raised before any network request when a provider key is unavailable."""


@dataclass(frozen=True)
class ConfiguredProvider:
    spec: ProviderSpec
    api_key: str = field(repr=False)

    def complete(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        client_factory: Callable[..., Any] | None = None,
    ) -> Any:
        if client_factory is None:
            from openai import OpenAI

            client_factory = OpenAI
        client = client_factory(
            api_key=self.api_key,
            base_url=self.spec.base_url,
            timeout=60.0,
            max_retries=2,
        )
        return client.chat.completions.create(
            model=self.spec.model,
            messages=messages,
            tools=tools,
            tool_choice="auto",
            temperature=0,
            stream=False,
        )
