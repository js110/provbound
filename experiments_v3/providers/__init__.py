from collections.abc import Mapping
import os

from experiments_v3.providers.base import ProviderSpec
from experiments_v3.providers.base import ConfiguredProvider, MissingCredentialError
from experiments_v3.providers.deepseek import SPEC as DEEPSEEK_SPEC
from experiments_v3.providers.mimo import SPEC as MIMO_SPEC
from experiments_v3.providers.sensenova import SPEC as SENSENOVA_SPEC


def provider_catalog() -> dict[str, ProviderSpec]:
    return {
        spec.name: spec
        for spec in (DEEPSEEK_SPEC, MIMO_SPEC, SENSENOVA_SPEC)
    }


def create_provider(
    name: str,
    *,
    environ: Mapping[str, str] | None = None,
) -> ConfiguredProvider:
    catalog = provider_catalog()
    if name not in catalog:
        raise ValueError(f"unknown provider: {name}")
    spec = catalog[name]
    source = os.environ if environ is None else environ
    api_key = source.get(spec.api_key_env, "").strip()
    if not api_key:
        raise MissingCredentialError(f"{spec.api_key_env} is not set")
    return ConfiguredProvider(spec=spec, api_key=api_key)


__all__ = [
    "ConfiguredProvider",
    "MissingCredentialError",
    "ProviderSpec",
    "create_provider",
    "provider_catalog",
]
