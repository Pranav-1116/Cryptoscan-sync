"""Graph credentials can be read from a protected file without environment secrets."""
from __future__ import annotations

import pytest

from graph_engine.config.settings import GraphSettings


def test_file_backed_auth_uses_neo4j_username_prefix(tmp_path):
    file = tmp_path / "graph-auth"
    file.write_text("neo4j/test-only-long-graph-password\n")
    settings = GraphSettings(NEO4J_URI="bolt://127.0.0.1:7687", NEO4J_USER="neo4j",
                             NEO4J_PASSWORD_FILE=str(file))
    assert settings.auth == ("neo4j", "test-only-long-graph-password")


def test_missing_linked_or_malformed_graph_file_refuses(tmp_path):
    missing = tmp_path / "missing"
    with pytest.raises(RuntimeError, match="absent"):
        GraphSettings(NEO4J_PASSWORD_FILE=str(missing)).auth
    file = tmp_path / "graph-auth"
    file.write_text("\n")
    with pytest.raises(RuntimeError, match="empty"):
        GraphSettings(NEO4J_PASSWORD_FILE=str(file)).auth
    file.write_text("neo4j/test-only-secret\n")
    link = tmp_path / "link"
    link.symlink_to(file)
    with pytest.raises(RuntimeError, match="linked"):
        GraphSettings(NEO4J_PASSWORD_FILE=str(link)).auth
