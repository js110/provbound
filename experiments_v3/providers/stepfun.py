from experiments_v3.providers.base import ProviderSpec


SPEC = ProviderSpec(
    name="stepfun",
    model="step-3.7-flash",
    base_url="https://api.stepfun.com/step_plan/v1",
    api_key_env="STEP_API_KEY",
)
