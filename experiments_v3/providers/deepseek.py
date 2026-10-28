from experiments_v3.providers.base import ProviderSpec


SPEC = ProviderSpec(
    name="deepseek",
    model="deepseek-v4-pro",
    base_url="https://api.deepseek.com",
    api_key_env="DEEPSEEK_API_KEY",
)
