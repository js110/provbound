from experiments_v3.providers.base import ProviderSpec


SPEC = ProviderSpec(
    name="sensenova",
    model="sensenova-6.7-flash-lite",
    base_url="https://token.sensenova.cn/v1",
    api_key_env="SENSENOVA_API_KEY",
)
