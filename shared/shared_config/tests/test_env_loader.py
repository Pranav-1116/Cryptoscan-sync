"""Tests for shared_config.env_loader — .env discovery and CRYPTOSCAN_ROOT."""

from __future__ import annotations

import os

import pytest

from shared_config.env_loader import find_env_file, load_env, repo_root


def test_find_env_file_from_cwd(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("FOO=bar\n")
    monkeypatch.chdir(tmp_path)
    assert find_env_file() == env_file


def test_find_env_file_none_when_absent(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CRYPTOSCAN_ROOT", raising=False)
    # Neither cwd nor repo root nor /app has a .env in this environment.
    result = find_env_file()
    if result is not None:
        pytest.skip("host environment provides a .env; nothing to assert")
    assert result is None


def test_load_env_sets_values_without_overriding(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("LOAD_ENV_TEST_A=from_file\nLOAD_ENV_TEST_B=from_file\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LOAD_ENV_TEST_A", "from_env")
    monkeypatch.delenv("CRYPTOSCAN_ROOT", raising=False)
    monkeypatch.delenv("LOAD_ENV_TEST_B", raising=False)

    loaded = load_env()
    assert loaded == env_file
    # Existing environment wins (override=False)…
    assert os.environ["LOAD_ENV_TEST_A"] == "from_env"
    # …but values missing from the environment are loaded.
    assert os.environ["LOAD_ENV_TEST_B"] == "from_file"
    assert os.environ["CRYPTOSCAN_ROOT"] == str(tmp_path)


def test_repo_root_prefers_env_var(monkeypatch, tmp_path):
    monkeypatch.setenv("CRYPTOSCAN_ROOT", str(tmp_path))
    assert repo_root() == tmp_path


def test_repo_root_falls_back_to_package_location(monkeypatch):
    monkeypatch.delenv("CRYPTOSCAN_ROOT", raising=False)
    root = repo_root()
    assert (root / "services" / "scanner").is_dir()
    assert (root / "Makefile").is_file()
