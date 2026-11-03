"""Neo4j connection settings. Empty URI keeps the memory backend."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class GraphSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="allow", case_sensitive=False)

    NEO4J_URI: str = ""
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: str = "cryptoscan"
    NEO4J_PASSWORD_FILE: str = ""
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
    def password(self) -> str:
        if not self.NEO4J_PASSWORD_FILE:
            return self.NEO4J_PASSWORD
        file = Path(self.NEO4J_PASSWORD_FILE)
        try:
            if file.is_symlink() or not file.is_file() or file.stat().st_size > 512:
                raise RuntimeError("Neo4j credential file is linked, absent or oversized")
            value = file.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeError) as exc:
            raise RuntimeError("Neo4j credential file cannot be read") from exc
        prefix = self.NEO4J_USER + "/"
        if value.startswith(prefix):
            value = value[len(prefix):]
        if not value or "\n" in value or "\r" in value:
            raise RuntimeError("Neo4j credential file is empty or malformed")
        return value

    @property
    def auth(self) -> tuple[str, str]:
        return (self.NEO4J_USER, self.password)


@lru_cache
def get_graph_settings() -> GraphSettings:
    return GraphSettings()


def reset_graph_settings() -> None:
    get_graph_settings.cache_clear()
