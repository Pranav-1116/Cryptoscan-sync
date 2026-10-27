#!/usr/bin/env python3
"""Verify the API's fails-closed production configuration guard.

Used by CI (workflow: ci / job: prod-config-guard) and by operators before a
production deploy, so the guarantee "the API refuses to boot with demo secrets,
SQLite, or CORS_ORIGINS=* in production" is exercised — not assumed.

Modes:
  python scripts/check_prod_guard.py                  # must PASS validation
  python scripts/check_prod_guard.py --expect-reject  # must FAIL validation

Exit codes: 0 = expected outcome, 1 = guard did NOT behave as required,
2 = invalid usage / import failure.
"""
from __future__ import annotations

import argparse
import sys

EXIT_OK = 0
EXIT_GUARD_BROKEN = 1
EXIT_USAGE = 2


def _validate() -> list[str]:
    """Return the list of production configuration errors (empty = valid)."""
    from api.config.settings import APISettings, validate_runtime_settings

    settings = APISettings()  # pydantic-settings reads the process env
    try:
        validate_runtime_settings(settings)
    except RuntimeError as exc:
        return [str(exc)]
    return []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--expect-reject",
        action="store_true",
        help="succeed only when the production configuration is REJECTED",
    )
    args = parser.parse_args()

    try:
        errors = _validate()
    except Exception as exc:  # noqa: BLE001 — report import/config problems clearly
        print(f"prod-guard: could not run validation: {exc}", file=sys.stderr)
        return EXIT_USAGE

    if args.expect_reject:
        if errors:
            print("prod-guard: OK — invalid production config rejected as required")
            print(f"  rejection: {errors[0]}")
            return EXIT_OK
        print(
            "prod-guard: BROKEN — demo/invalid production configuration was accepted "
            "(the API would boot with demo secrets)",
            file=sys.stderr,
        )
        return EXIT_GUARD_BROKEN

    if not errors:
        print("prod-guard: OK — production configuration is valid")
        return EXIT_OK
    print("prod-guard: configuration rejected (expected acceptance)", file=sys.stderr)
    print(f"  {errors[0]}", file=sys.stderr)
    return EXIT_GUARD_BROKEN


if __name__ == "__main__":
    raise SystemExit(main())
