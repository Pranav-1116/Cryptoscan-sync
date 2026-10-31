"""The list of operations that declare no response model, kept as a ratchet.

Guide 100 §5 (a): the API has 1251 operations and only a handful declare what they
return. Everything else hands back ``dict``, which means FastAPI validates nothing
and the console's TypeScript interface is a hand-written claim rather than a checked
contract. Closing that gap is `response_model=` on the routers, one at a time.

"One at a time" needs a list and a floor, otherwise the gap is invisible:

* ``--write`` records every operation whose 2xx response has no JSON schema;
* ``scripts/tests/test_response_typing.py`` requires the recorded list to equal the
  live one, so a **new** untyped route fails the build (adding it to the list is a
  decision, and shows up in review);
* the same test keeps the typed count above a floor, so removing a model fails.

The artifact is JSON rather than prose because it is compared exactly; the audit
document quotes the counts.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "docs" / "bank-environment" / "103-untyped-response-operations.json"

METHODS = ("get", "post", "put", "patch", "delete")


def _declares_json(spec: dict, path: str, method: str) -> bool:
    """True when the operation promises a JSON body for a 2xx status."""
    operation = (spec.get("paths") or {}).get(path, {}).get(method.lower()) or {}
    for status, response in (operation.get("responses") or {}).items():
        if not str(status).startswith("2"):
            continue
        # A PDF or CSV export declares a schema too, but it is not a JSON contract
        # a caller can validate and it is not what the console renders. Matches
        # `_declared_json` in the live sweep so the two counts agree.
        content = (response or {}).get("content") or {}
        media = content.get("application/json") or {}
        if isinstance(media, dict) and media.get("schema"):
            return True
    return False


def operations() -> list[tuple[str, str]]:
    import api_contract

    return sorted(
        (method.upper(), path)
        for path, methods in api_contract.served_operations().items()
        for method in methods
    )


def untyped() -> list[str]:
    """``"METHOD path"`` for every operation with no declared response schema."""
    import api_contract

    spec = api_contract.openapi_spec()
    return [
        f"{method} {path}"
        for method, path in operations()
        if not _declares_json(spec, path, method)
    ]


def typed() -> list[str]:
    import api_contract

    spec = api_contract.openapi_spec()
    return [
        f"{method} {path}"
        for method, path in operations()
        if _declares_json(spec, path, method)
    ]


def load() -> list[str]:
    if not INVENTORY.is_file():
        return []
    return list(json.loads(INVENTORY.read_text()).get("operations") or [])


def write(rows: list[str] | None = None) -> Path:
    rows = untyped() if rows is None else rows
    INVENTORY.parent.mkdir(parents=True, exist_ok=True)
    INVENTORY.write_text(
        json.dumps(
            {
                "schema": "cryptoscan.untyped-response-operations/1",
                "why": (
                    "Operations whose 2xx response declares no schema, so FastAPI validates "
                    "nothing and only the console's hand-written interface describes the "
                    "payload. Regenerate with `python scripts/response_typing.py --write` after "
                    "typing a route; the list may only shrink."
                ),
                "operations": rows,
            },
            indent=2,
        )
        + "\n"
    )
    return INVENTORY


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="rewrite the inventory")
    args = parser.parse_args(argv)
    rows = untyped()
    if args.write:
        print(f"wrote {write(rows)} ({len(rows)} untyped of {len(operations())} operations)")
        return 0
    print(json.dumps({"operations": len(operations()), "typed": len(typed()), "untyped": len(rows)}, indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI
    raise SystemExit(main())
