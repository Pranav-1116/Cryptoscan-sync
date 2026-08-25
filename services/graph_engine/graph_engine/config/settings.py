"""Neo4j connection settings. Empty URI keeps the memory backend."""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class GraphSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="allow", case_sensitive=False)

    NEO4J_URI: str = ""
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: str = "cryptoscan"
    NEO4J_DATABASE: str = "neo4j"
    NEO4J_REQUIRED: bool = False
    ISTIO_PROMETHEUS_URL: str = ""

    @property
    def enabled(self) -> bool:
        return bool(self.NEO4J_URI.strip())

    @property
    def uri(self) -> str:
        return self.NEO4J_URI.strip()

    @property
    def auth(self) -> tuple[str, str]:
        return (self.NEO4J_USER, self.NEO4J_PASSWORD)


@lru_cache
def get_graph_settings() -> GraphSettings:
    return GraphSettings()


def reset_graph_settings() -> None:
    get_graph_settings.cache_clear()
