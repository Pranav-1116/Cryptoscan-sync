"""One answer to "is this production?", for every service and every safety gate.

Why this module exists
----------------------

The platform had **four** independent production detectors, and they did not agree:

===========================  ==================================================
where                        how it decided
===========================  ==================================================
``api/routers/resilience``   ``os.environ["ENVIRONMENT"] == "production"``
``api/events/platform_events`` same, with a different alias set
``worker/config/settings``   ``self.ENVIRONMENT.lower() == "production"``
``cbom/signing/key_manager`` ``self._environment.strip().lower() == "production"``
===========================  ==================================================

Each was defensible alone and wrong in company. The first two ignored ``.env`` — which
``BaseSettings`` reads — so a deployment configured through a file looked like development to
the router whose whole job is refusing unsafe restore targets. None of them knew what to do
with ``prod``, ``PRD``, ``staging`` or a typo: three silently answered "not production", which
turns a safety gate off rather than on.

The rule this module applies is the one a gate needs: **an unrecognised environment is not
development.** A value nobody can classify is treated as production, so the strict checks
engage, and :func:`describe` says exactly which value was unrecognised and where it came from.
That is the difference between a gate failing closed and a gate failing quiet.

Resolution order
----------------

1. an explicit settings object the caller holds (highest — it has already merged ``.env``,
   container env and defaults);
2. the platform settings, imported lazily so this module works in the worker, in a script, and
   in a test that has none;
3. ``os.environ["ENVIRONMENT"]``;
4. ``"development"``.

Nothing here raises. A configuration module that throws from inside a safety check turns a
refusal into a traceback, and callers route around tracebacks — which is how the four detectors
came to exist.
"""

from __future__ import annotations

import os
from typing import Any, Mapping

#: every accepted spelling, normalised. Kept identical to
#: :data:`shared_config.base_settings.VALID_ENVIRONMENTS` plus the aliases that were already
#: in use across the four detectors.
ENVIRONMENT_ALIASES: dict[str, str] = {
    "dev": "development",
    "local": "development",
    "development": "development",
    "testing": "test",
    "test": "test",
    "stage": "staging",
    "staging": "staging",
    "preprod": "staging",
    "pre-production": "staging",
    "prod": "production",
    "prd": "production",
    "production": "production",
    "live": "production",
}

PRODUCTION = "production"
STAGING = "staging"
TEST = "test"
DEVELOPMENT = "development"

#: what an unclassifiable value is treated as. Not "development": a typo must not unlock a
#: production estate, so the strict branch is the safe branch.
UNRECOGNISED_TREATMENT = PRODUCTION


def normalise(value: Any) -> str | None:
    """The canonical environment for a value, or ``None`` when it cannot be classified."""
    text = str(value or "").strip().lower()
    if not text:
        return None
    return ENVIRONMENT_ALIASES.get(text)


def _from_settings(settings: Any) -> tuple[str | None, str]:
    raw = getattr(settings, "ENVIRONMENT", None)
    if raw in (None, ""):
        return None, ""
    return str(raw), f"{type(settings).__module__}.{type(settings).__name__}.ENVIRONMENT"


def detect(settings: Any = None, *, environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Where the environment came from, what it is, and whether it could be classified.

    ``detect`` returns the *evidence* for the answer, which is what a health endpoint, an audit
    row and a test all need: not just ``True``, but "production, from
    ``api.config.settings.Settings.ENVIRONMENT``, value ``prod``".
    """
    if settings is not None:
        raw, source = _from_settings(settings)
        if raw is not None:
            return _result(raw, normalise(raw), source)

    if environ is not None:
        # an explicit mapping is the caller asserting the environment (a test, a worker with
        # its own settings object, a script): it outranks anything we would look up.
        raw = environ.get("ENVIRONMENT")
        if raw:
            return _result(str(raw), normalise(raw), "environ argument")
        return _result("development", DEVELOPMENT, "environ argument (unset)")

    try:  # the platform settings have already merged .env, container env and defaults
        from api.config.settings import get_settings

        raw, source = _from_settings(get_settings())
        if raw is not None:
            canonical = normalise(raw)
            return _result(raw, canonical, source)
    except Exception:  # noqa: BLE001 — a worker, a script or a test may have no API settings
        pass

    raw = os.environ.get("ENVIRONMENT")
    if raw:
        return _result(str(raw), normalise(raw), "os.environ.ENVIRONMENT")

    return _result("development", DEVELOPMENT, "default")


def _result(raw: str, canonical: str | None, source: str) -> dict[str, Any]:
    recognised = canonical is not None
    effective = canonical or UNRECOGNISED_TREATMENT
    return {
        "value": str(raw),
        "normalised": canonical,
        "effective": effective,
        "source": source,
        "recognised": recognised,
        "note": (
            f"{raw!r} is not a recognised environment; it is treated as "
            f"{UNRECOGNISED_TREATMENT} so the strict checks engage rather than switching off"
            if not recognised else f"{raw!r} → {effective}"
        ),
    }


def environment_name(settings: Any = None, *,
                     environ: Mapping[str, str] | None = None) -> str:
    """The effective environment: one of ``production``, ``staging``, ``test``, ``development``.

    Named ``environment_name`` rather than ``environment`` on purpose: a function re-exported
    from the package under the module's own name shadows
    ``shared_config.environment`` at the import site, so the call ``from shared_config import
    environment`` returns a function on one machine and a module on another depending on
    import order. That is exactly the class of bug this module exists to end.
    """
    return detect(settings, environ=environ)["effective"]


def is_production(settings: Any = None, *, environ: Mapping[str, str] | None = None) -> bool:
    """The only production predicate a safety gate in this repository should call."""
    return environment_name(settings, environ=environ) == PRODUCTION


def is_staging(settings: Any = None, *, environ: Mapping[str, str] | None = None) -> bool:
    return environment_name(settings, environ=environ) == STAGING


def is_test(settings: Any = None, *, environ: Mapping[str, str] | None = None) -> bool:
    return environment_name(settings, environ=environ) == TEST


def is_development(settings: Any = None, *, environ: Mapping[str, str] | None = None) -> bool:
    return environment_name(settings, environ=environ) == DEVELOPMENT


def describe(settings: Any = None, *, environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    """The answer plus its provenance, for a health row or an audit record."""
    found = detect(settings, environ=environ)
    return {
        "schema": "cryptoscan.environment/1",
        **found,
        "is_production": found["effective"] == PRODUCTION,
        "valid_spellings": sorted(ENVIRONMENT_ALIASES),
        "unrecognised_treatment": UNRECOGNISED_TREATMENT,
    }
