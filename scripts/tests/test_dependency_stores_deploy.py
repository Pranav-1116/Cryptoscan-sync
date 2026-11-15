"""The dependency-graph plane is declared in the deploy surface.

Three stores over one authoritative inventory: Neo4j (graph traversal),
Cassandra (dependency-edge history), Elasticsearch (dependency search).
PostgreSQL stays the source of truth — the stores are rebuildable
projections, disabled by default, and never hold authoritative-only data.

These tests pin the deploy side of that contract: the stack declares the
trio with healthchecks and loopback-bound host ports, the platform table
names their roles, and the environment examples carry the settings with
empty defaults (a store is never silently on).
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
STACK = ROOT / "deploy" / "stack"


class _ComposeLoader(yaml.SafeLoader):
    pass


def _override(loader, node):
    # Compose >=2.24 replaces root lists instead of appending host publishes.
    return loader.construct_sequence(node)


_ComposeLoader.add_constructor("!override", _override)


def _compose():
    return yaml.load((STACK / "docker-compose.stack.yml").read_text(),
                     Loader=_ComposeLoader)


def test_the_stack_declares_the_dependency_graph_trio():
    services = _compose()["services"]
    for name in ("neo4j", "cassandra", "elasticsearch"):
        assert name in services, f"dependency-graph store {name} missing from the stack"


def test_the_trio_is_stateful_pinned_and_healthchecked():
    services = _compose()["services"]
    images = {
        "neo4j": "neo4j:",
        "cassandra": "cassandra:",
        "elasticsearch": "elasticsearch:",
    }
    for name, prefix in images.items():
        service = services[name]
        image = service.get("image", "")
        assert image.startswith(prefix) and len(image) > len(prefix), \
            f"{name} image is not a pinned {prefix}* tag: {image!r}"
        assert "healthcheck" in service, f"{name} has no healthcheck"
        volumes = [str(v) for v in service.get("volumes", [])]
        assert any(v.split(":")[0].endswith("_data") for v in volumes), \
            f"{name} does not persist into a named volume"


def test_host_ports_are_loopback_bound():
    services = _compose()["services"]
    for name in ("cassandra", "elasticsearch"):
        ports = [str(p) for p in services[name].get("ports", [])]
        assert ports, f"{name} publishes no host port"
        for port in ports:
            assert port.startswith("127.0.0.1:"), \
                f"{name} host port escapes the laptop: {port}"


def test_the_platform_table_names_the_stores_roles():
    from shared_config.stack_settings import BACKENDS

    table = {(name, role): var for name, role, var in BACKENDS}
    assert table[("Neo4j", "GRAPH")] == "NEO4J_URI"
    assert table[("Cassandra", "HISTORY")] == "CASSANDRA_CONTACT_POINTS"
    assert table[("Elasticsearch", "SEARCH")] == "ELASTICSEARCH_URL"


def test_env_examples_carry_the_settings_with_disabled_defaults():
    for name in (".env.example", ".env.production.example"):
        text = (ROOT / name).read_text()
        for key in ("CASSANDRA_CONTACT_POINTS=", "CASSANDRA_KEYSPACE=",
                    "ELASTICSEARCH_URL=", "ELASTICSEARCH_INDEX="):
            assert key in text, f"{name} lacks {key}"
        # A store is never silently on: the connection defaults are empty.
        for line in text.splitlines():
            if line.startswith(("CASSANDRA_CONTACT_POINTS=", "ELASTICSEARCH_URL=")):
                assert line.rstrip().endswith("="), \
                    f"{name} enables a dependency store by default: {line!r}"


def test_settings_default_to_stores_disabled():
    from graph_engine.config.settings import GraphSettings

    settings = GraphSettings(_env_file=None)
    assert not settings.cassandra_enabled and not settings.elastic_enabled
    assert settings.CASSANDRA_REQUIRED is False
    assert settings.ELASTICSEARCH_REQUIRED is False
    assert settings.CASSANDRA_KEYSPACE == "cryptoscan_graph"
    assert settings.ELASTICSEARCH_INDEX == "cryptoscan-dependency-graph"
