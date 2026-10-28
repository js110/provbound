from types import SimpleNamespace
import unittest

from experiments_v3.provider_smoke import run_provider_smoke


class ScriptedProvider:
    def __init__(self):
        self.index = 0

    def complete(self, *, messages, tools):
        self.index += 1
        if self.index == 1:
            message = SimpleNamespace(
                content=None,
                tool_calls=[
                    SimpleNamespace(
                        id="smoke-call",
                        type="function",
                        function=SimpleNamespace(
                            name="echo_probe",
                            arguments='{"token":"native-tool-call-ok"}',
                        ),
                    )
                ],
            )
        else:
            message = SimpleNamespace(content="done", tool_calls=None)
        return SimpleNamespace(
            choices=[SimpleNamespace(message=message)],
            model="returned-model-id",
        )


class ProviderSmokeV3Tests(unittest.TestCase):
    def test_smoke_requires_a_native_multi_turn_tool_call(self):
        result = run_provider_smoke(
            provider_name="fake",
            configured_model="configured-model-id",
            provider=ScriptedProvider(),
        )

        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["native_tool_call"])
        self.assertEqual(result["response_model_ids"], ["returned-model-id"])
        self.assertEqual(result["tool_calls"], 1)


if __name__ == "__main__":
    unittest.main()
