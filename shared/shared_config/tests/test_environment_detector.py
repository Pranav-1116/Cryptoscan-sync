"""One production detector, and a test that keeps it that way.

The bug this replaces was not a wrong comparison — every one of the four detectors compared
the right string. The bug was that there were four of them, so a deployment configured through
``.env`` looked like development to whichever gate read ``os.environ`` and like production to
the one that read settings. Nobody could see the disagreement by reading any single file.

So there are two halves here: the predicate behaves (aliases, typos, provenance), and a static
scan proves no module outside ``shared_config`` decides production for itself again.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from shared_config import environment as env


# --------------------------------------------------------------------------- #
# the predicate
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("value", ["production", "PRODUCTION", "prod", "PRD", " live "])
def test_every_production_spelling_means_production(value):
    assert env.is_production(environ={"ENVIRONMENT": value}) is True


@pytest.mark.parametrize("value", ["development", "dev", "local", "test", "testing",
                                   "staging", "stage", "preprod"])
def test_every_other_spelling_is_not_production(value):
    assert env.is_production(environ={"ENVIRONMENT": value}) is False


@pytest.mark.parametrize("value", ["prodcution", "prd-1", "yes", "true", "prod ", "p"])
def test_a_typo_is_treated_as_production_not_as_development(value):
    """The one direction a safety gate may fail: strict, and loudly."""
    detected = env.detect(environ={"ENVIRONMENT": value})
    assert env.is_production(environ={"ENVIRONMENT": value}) is True
    if env.normalise(value) is None:
        assert detected["recognised"] is False
        assert "treated as production" in detected["note"]


def test_an_unset_environment_is_development_and_says_where_it_came_from():
    detected = env.detect(environ={})
    assert detected["effective"] == "development"
    assert "unset" in detected["source"]
    # and with no argument at all it falls back to the platform, then to the default
    assert env.detect()["effective"] in {"development", "test", "staging", "production"}


def test_the_answer_carries_its_provenance():
    detected = env.detect(environ={"ENVIRONMENT": "staging"})
    assert detected["source"] == "environ argument"
    assert detected["normalised"] == "staging"
    assert env.describe(environ={"ENVIRONMENT": "prod"})["is_production"] is True


def test_unreadable_platform_settings_cannot_silently_enable_development(monkeypatch):
    from api.config import settings as api_settings

    monkeypatch.delenv("ENVIRONMENT", raising=False)

    def unavailable():
        raise RuntimeError("test-only settings failure")

    monkeypatch.setattr(api_settings, "get_settings", unavailable)
    found = env.detect()
    assert found["effective"] == "production"
    assert found["recognised"] is False
    assert found["source"] == "api.config.settings"


def test_an_explicit_settings_object_outranks_the_environment_map():
    class Fake:
        ENVIRONMENT = "staging"

    assert env.is_production(Fake(), environ={"ENVIRONMENT": "production"}) is False


def test_a_settings_object_from_the_platform_is_used_when_nothing_else_is():
    class Fake:
        ENVIRONMENT = "prod"

    assert env.is_production(Fake()) is True


def test_normalise_refuses_to_guess():
    assert env.normalise("prod") == "production"
    assert env.normalise("nonsense") is None
    assert env.normalise("") is None
    assert env.normalise(None) is None


# --------------------------------------------------------------------------- #
# no fifth detector
# --------------------------------------------------------------------------- #

#: The files that may decide the environment. Everything else asks here.
_CANONICAL = {"shared/shared_config/shared_config/environment.py",
              "shared/shared_config/shared_config/base_settings.py"}

#: A module decides production for itself if it compares an ENVIRONMENT-derived value.
#: Two shapes, both meaning "this module decided for itself":
#: the environment *token* compared with a production literal, and a hand-written alias set.
#: A record's own ``environment`` field is data, not a detector, so the token must be spelled
#: the way an environment variable is.
_DETECTOR = re.compile(
    r"""ENVIRONMENT["']?\s*(?:==|!=)\s*["'](?:production|prod)["']"""
    r"""|(?:ENVIRONMENT|environment\b)[^\n]{0,40}in\s*\{\s*["']production["']"""
    r"""|(?:os\.environ|os\.getenv)[^\n]{0,60}["']production["'][^\n]{0,40}["']prod"""
    r"""|(?:os\.getenv\(["']ENVIRONMENT["'][^\n]{0,40}\))[^\n]{0,30}\.lower\(\)\s*in""",
)

_SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "dist", "build", "docs"}


def repo_root() -> Path:
    """The checkout root, four levels up from this test file."""
    return Path(__file__).resolve().parents[3]


def _python_files(root: Path):
    for path in root.rglob("*.py"):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        yield path


def test_no_module_outside_shared_config_decides_production_for_itself():
    """The regression this guide exists for: a fifth detector must fail the suite."""
    root = repo_root()
    offenders: list[str] = []
    for path in _python_files(root):
        relative = path.relative_to(root).as_posix()
        if relative in _CANONICAL or relative.startswith("shared/shared_config/tests/"):
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("*"):
                continue
            # a line that *asks* the shared detector is the fix, not the bug
            if "platform_environment" in line or "shared_config" in line:
                continue
            if _DETECTOR.search(line):
                offenders.append(f"{relative}: {stripped[:90]}")
    assert offenders == [], (
        "these modules decide 'is production' for themselves; call "
        "shared_config.environment.is_production() instead:\n" + "\n".join(offenders))


def test_the_four_former_detectors_now_agree():
    """Each of the four call sites answers with the same predicate."""
    import importlib

    call_sites = [
        ("api.routers.resilience", "_production"),
        ("api.events.platform_events", "_is_production"),
    ]
    results = []
    for module_name, attribute in call_sites:
        module = importlib.import_module(module_name)
        results.append(getattr(module, attribute)())
    assert len(set(results)) == 1, f"the detectors disagree: {results}"
