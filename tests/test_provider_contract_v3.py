import unittest
import json
from pathlib import Path
from types import SimpleNamespace

import httpx
from openai import OpenAI

from experiments_v3.real_agent_benchmark import MAX_AGENT_STEPS

from experiments_v3.providers import (
    MissingCredentialError,
    create_provider,
    provider_catalog,
)


class ProviderCatalogTests(unittest.TestCase):
    def test_pre_registered_real_agent_protocol_matches_provider_catalog(self):
        root = Path(__file__).resolve().parents[1]
        protocol = json.loads(
            (
                root
                / "experiments_v3"
                / "configs"
                / "real_agent_protocol_v1.json"
            ).read_text(encoding="utf-8")
        )
        catalog = provider_catalog()

        self.assertEqual(set(protocol["providers"]), set(catalog))
        for name, configured in protocol["providers"].items():
            self.assertEqual(configured["model"], catalog[name].model)
            self.assertEqual(configured["base_url"], catalog[name].base_url)
            self.assertEqual(configured["credential_env"], catalog[name].api_key_env)
        self.assertEqual(protocol["shared_request"]["temperature"], 0)
        self.assertEqual(
            protocol["shared_request"]["max_agent_steps"],
            MAX_AGENT_STEPS,
        )
        self.assertTrue(
            protocol["shared_request"]["json_action_fallback_forbidden"]
        )

    def test_catalog_uses_the_three_approved_official_endpoints(self):
        catalog = provider_catalog()

        self.assertEqual(
            {
                name: (spec.model, spec.base_url, spec.api_key_env)
                for name, spec in catalog.items()
            },
            {
                "deepseek": (
                    "deepseek-v4-pro",
                    "https://api.deepseek.com",
                    "DEEPSEEK_API_KEY",
                ),
                "mimo": (
                    "mimo-v2.5-pro",
                    "https://api.xiaomimimo.com/v1",
                    "MIMO_API_KEY",
                ),
                "sensenova": (
                    "sensenova-6.7-flash-lite",
                    "https://token.sensenova.cn/v1",
                    "SENSENOVA_API_KEY",
                ),
            },
        )

    def test_provider_refuses_to_start_without_its_environment_credential(self):
        with self.assertRaisesRegex(
            MissingCredentialError,
            "SENSENOVA_API_KEY is not set",
        ):
            create_provider("sensenova", environ={})

    def test_provider_representation_never_contains_the_api_key(self):
        provider = create_provider(
            "deepseek",
            environ={"DEEPSEEK_API_KEY": "test-only-secret"},
        )

        self.assertNotIn("test-only-secret", repr(provider))

    def test_all_providers_send_the_same_agent_request_except_for_model_id(self):
        client_initializations = []
        requests = []

        def client_factory(**kwargs):
            client_initializations.append(kwargs)

            def create(**request):
                requests.append(request)
                return {"request": request}

            return SimpleNamespace(
                chat=SimpleNamespace(
                    completions=SimpleNamespace(create=create),
                )
            )

        messages = [
            {"role": "system", "content": "Shared agent prompt"},
            {"role": "user", "content": "Shared task"},
        ]
        tools = [
            {
                "type": "function",
                "function": {
                    "name": "read_email",
                    "description": "Read one email",
                    "parameters": {"type": "object", "properties": {}},
                },
            }
        ]

        for name in ("deepseek", "mimo", "sensenova"):
            provider = create_provider(
                name,
                environ={provider_catalog()[name].api_key_env: "test-only-key"},
            )
            provider.complete(
                messages=messages,
                tools=tools,
                client_factory=client_factory,
            )

        comparable_requests = [
            {key: value for key, value in request.items() if key != "model"}
            for request in requests
        ]
        self.assertEqual(comparable_requests[0], comparable_requests[1])
        self.assertEqual(comparable_requests[1], comparable_requests[2])
        self.assertEqual(
            [request["model"] for request in requests],
            ["deepseek-v4-pro", "mimo-v2.5-pro", "sensenova-6.7-flash-lite"],
        )
        self.assertTrue(all(request["temperature"] == 0 for request in requests))
        self.assertTrue(all(item["timeout"] == 60.0 for item in client_initializations))
        self.assertTrue(all(item["max_retries"] == 2 for item in client_initializations))
        self.assertEqual(
            [item["base_url"] for item in client_initializations],
            [
                "https://api.deepseek.com",
                "https://api.xiaomimimo.com/v1",
                "https://token.sensenova.cn/v1",
            ],
        )

    def test_openai_sdk_builds_the_expected_chat_completion_path_for_each_provider(self):
        observed_paths = []

        def transport_handler(request):
            observed_paths.append(request.url.path)
            return httpx.Response(
                200,
                json={
                    "id": "offline-contract-test",
                    "object": "chat.completion",
                    "created": 0,
                    "model": "offline-model",
                    "choices": [
                        {
                            "index": 0,
                            "finish_reason": "stop",
                            "message": {
                                "role": "assistant",
                                "content": "ok",
                            },
                        }
                    ],
                    "usage": {
                        "prompt_tokens": 1,
                        "completion_tokens": 1,
                        "total_tokens": 2,
                    },
                },
            )

        def client_factory(**kwargs):
            return OpenAI(
                **kwargs,
                http_client=httpx.Client(
                    transport=httpx.MockTransport(transport_handler)
                ),
            )

        for name in ("deepseek", "mimo", "sensenova"):
            spec = provider_catalog()[name]
            provider = create_provider(
                name,
                environ={spec.api_key_env: "test-only-key"},
            )
            provider.complete(
                messages=[{"role": "user", "content": "ping"}],
                tools=[],
                client_factory=client_factory,
            )

        self.assertEqual(
            observed_paths,
            [
                "/chat/completions",
                "/v1/chat/completions",
                "/v1/chat/completions",
            ],
        )


if __name__ == "__main__":
    unittest.main()
