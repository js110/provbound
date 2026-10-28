from experiments_v3.providers.base import ProviderSpec


SPEC = ProviderSpec(
    name="mimo",
    model="mimo-v2.5-pro",
    base_url="https://api.xiaomimimo.com/v1",
    api_key_env="MIMO_API_KEY",
)
