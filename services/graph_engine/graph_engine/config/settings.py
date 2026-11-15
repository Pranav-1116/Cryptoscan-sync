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

    # Cassandra — dependency-edge history projection. Empty contact points
    # keeps the store disabled (reads report "unconfigured", never a fake
    # timeline). PostgreSQL stays the authoritative record; this is a
    # rebuildable projection of edge lifecycle events only.
    CASSANDRA_CONTACT_POINTS: str = ""
    CASSANDRA_PORT: int = 9042
    CASSANDRA_KEYSPACE: str = "cryptoscan_graph"
    CASSANDRA_USERNAME: str = ""
    CASSANDRA_PASSWORD: str = ""
    CASSANDRA_PASSWORD_FILE: str = ""
    CASSANDRA_REQUIRED: bool = False

    # Elasticsearch — dependency search projection. Empty URL keeps the
    # store disabled. Same authority boundary as above: searchable copies
    # of node/edge text, rebuildable from the relational inventory.
    ELASTICSEARCH_URL: str = ""
    ELASTICSEARCH_USERNAME: str = ""
    ELASTICSEARCH_PASSWORD: str = ""
    ELASTICSEARCH_PASSWORD_FILE: str = ""
    ELASTICSEARCH_INDEX: str = "cryptoscan-dependency-graph"
    ELASTICSEARCH_REQUIRED: bool = False

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

    @property
    def cassandra_enabled(self) -> bool:
        return bool(self.CASSANDRA_CONTACT_POINTS.strip())

    @property
    def contact_points(self) -> list[str]:
        return [point.strip() for point in self.CASSANDRA_CONTACT_POINTS.split(",") if point.strip()]

    @property
    def cassandra_password(self) -> str:
        return _secret_from_file(
            self.CASSANDRA_PASSWORD_FILE, self.CASSANDRA_PASSWORD,
            self.CASSANDRA_USERNAME or "cassandra", "Cassandra",
        )

    @property
    def elastic_enabled(self) -> bool:
        return bool(self.ELASTICSEARCH_URL.strip())

    @property
    def elastic_password(self) -> str:
        return _secret_from_file(
            self.ELASTICSEARCH_PASSWORD_FILE, self.ELASTICSEARCH_PASSWORD,
            self.ELASTICSEARCH_USERNAME or "elastic", "Elasticsearch",
        )


def _secret_from_file(file_path: str, fallback: str, user: str, label: str) -> str:
    """File-based secret with the Neo4j credential-file discipline.

    The file must be a regular, non-symlink file of at most 512 bytes, holding
    either the bare secret or a ``user/secret`` pair. Anything else refuses to
    read — a wrong secret must fail loudly, not half-work.
    """
    if not file_path:
        return fallback
    file = Path(file_path)
    try:
        if file.is_symlink() or not file.is_file() or file.stat().st_size > 512:
            raise RuntimeError(f"{label} credential file is linked, absent or oversized")
        value = file.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as exc:
        raise RuntimeError(f"{label} credential file cannot be read") from exc
    prefix = user + "/"
    if value.startswith(prefix):
        value = value[len(prefix):]
    if not value or "\n" in value or "\r" in value:
        raise RuntimeError(f"{label} credential file is empty or malformed")
    return value


@lru_cache
def get_graph_settings() -> GraphSettings:
    return GraphSettings()


def reset_graph_settings() -> None:
    get_graph_settings.cache_clear()
