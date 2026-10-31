#!/usr/bin/env python3
"""Rotate a deployment secret without logging anyone out mid-shift.

Rotating ``SECRET_KEY`` is not a text edit: sessions are HMAC-signed with it, so
replacing the value invalidates every live session at once. The supported
sequence keeps the old key in ``SECRET_KEY_PREVIOUS`` (accepted for verification,
never used for signing) until the longest session has expired, then removes it.

    # 1. rotate: new key signs, old key still verifies
    python scripts/rotate_secrets.py --env-file /etc/cryptoscan/api.env

    # 2. after SESSION_EXPIRE_HOURS, end the overlap
    python scripts/rotate_secrets.py --env-file /etc/cryptoscan/api.env --retire-previous

    # 3. prove the deployment still passes the production gate
    python scripts/config_audit.py --env-file /etc/cryptoscan/api.env

What it will not do:

* print a secret value (only a length + SHA-256 fingerprint, so an operator can
  confirm *which* value was written without it landing in a shell log);
* touch a file it cannot back up first (a timestamped ``.bak`` is always written
  beside the original, mode 0600);
* rotate a secret that other components hold a copy of without saying so.

``CBOM_SIGNING_SECRET`` and the other HMAC secrets are listed with their blast
radius: rotating one invalidates every signature/key minted with it, which is a
different (and much larger) operational event than expiring sessions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

KEY = "SECRET_KEY"
PREVIOUS = "SECRET_KEY_PREVIOUS"
MAX_OVERLAP = 3  # the production gate refuses more

#: secrets whose rotation has a consequence beyond this process
BLAST_RADIUS = {
    "SECRET_KEY": "invalidates every signed session (previous-key overlap keeps them alive)",
    "CBOM_SIGNING_SECRET": "invalidates every CBOM HMAC signature already issued or exchanged",
    "REGISTRY_WEBHOOK_SECRET": "invalidates the registry webhook peer's configuration until it is updated too",
    "AUDITOR_API_KEY": "invalidates auditor API clients until they are re-issued",
    "STREAM_SECRET": "invalidates live stream grants issued before the rotation",
}


def fingerprint(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    return f"sha256:{digest} len={len(value)}"


def read_env(path: Path) -> tuple[list[str], dict[str, str]]:
    """Keep the file's lines so comments and ordering survive a rewrite."""
    lines = path.read_text(encoding="utf-8").splitlines()
    values: dict[str, str] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        name, _, raw = stripped.partition("=")
        values[name.strip().removeprefix("export ").strip()] = raw.strip().strip("'\"")
    return lines, values


def set_value(lines: list[str], name: str, value: str | None) -> list[str]:
    """Replace the assignment in place; append it when absent; drop it when None."""
    pattern = re.compile(rf"^\s*(export\s+)?{re.escape(name)}\s*=")
    out: list[str] = []
    written = False
    for line in lines:
        if pattern.match(line):
            if value is None:
                continue
            if not written:
                out.append(f"{name}={value}")
                written = True
            continue
        out.append(line)
    if value is not None and not written:
        out.append(f"{name}={value}")
    return out


def write_atomic(path: Path, lines: list[str]) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = path.with_suffix(path.suffix + f".bak.{stamp}")
    shutil.copy2(path, backup)
    os.chmod(backup, 0o600)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(path)
    return backup


def rotate(path: Path, *, key: str, length: int, dry_run: bool) -> dict:
    lines, values = read_env(path)
    current = values.get(key, "")
    if not current:
        raise SystemExit(f"{key} is not set in {path}; nothing to rotate (add it first)")
    new_value = secrets.token_urlsafe(length)
    previous = [part.strip() for part in values.get(PREVIOUS, "").split(",") if part.strip()]
    previous = [part for part in previous if part != current]
    previous = [current, *previous][:MAX_OVERLAP]
    if key != KEY:
        # Blast radius differs per secret; never pretend one rotation is another.
        raise SystemExit(
            f"{key}: {BLAST_RADIUS.get(key, 'rotating this secret invalidates its past use')}. "
            "Rotate it with the owning component in the same change window; this tool only "
            "automates SECRET_KEY, where the previous-key overlap makes it safe."
        )
    updated = set_value(lines, PREVIOUS, ",".join(previous))
    updated = set_value(updated, key, new_value)
    report = {
        "schema": "cryptoscan.secret-rotation/1",
        "file": str(path),
        "secret": key,
        "rotated_at": datetime.now(timezone.utc).isoformat(),
        "new": fingerprint(new_value),
        "retired_into_overlap": fingerprint(current),
        "overlap_entries": len(previous),
        "dry_run": dry_run,
        "blast_radius": BLAST_RADIUS[key],
        "next_steps": [
            "restart every API instance so all of them read the new key",
            f"after SESSION_EXPIRE_HOURS, run: {Path(sys.argv[0]).name} --env-file {path} --retire-previous",
            f"then confirm the deployment still passes: python scripts/config_audit.py --env-file {path}",
        ],
    }
    if not dry_run:
        report["backup"] = str(write_atomic(path, updated))
    return report


def retire_previous(path: Path, *, dry_run: bool) -> dict:
    lines, values = read_env(path)
    previous = [part.strip() for part in values.get(PREVIOUS, "").split(",") if part.strip()]
    report = {
        "schema": "cryptoscan.secret-rotation/1",
        "file": str(path),
        "action": "retire-previous",
        "retired": len(previous),
        "dry_run": dry_run,
        "note": "every session signed before the rotation stops validating now — intended",
    }
    if previous and not dry_run:
        report["backup"] = str(write_atomic(path, set_value(lines, PREVIOUS, None)))
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--env-file", type=Path, required=True, help="env file holding SECRET_KEY")
    parser.add_argument("--key", default=KEY, help="which secret to rotate (default: SECRET_KEY)")
    parser.add_argument("--length", type=int, default=48, help="bytes of entropy (default 48)")
    parser.add_argument("--retire-previous", action="store_true", help="end the overlap window")
    parser.add_argument("--dry-run", action="store_true", help="report what would change")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    path: Path = args.env_file
    if not path.is_file():
        raise SystemExit(f"no such env file: {path}")
    if args.length < 32:
        raise SystemExit("--length must be at least 32 (the production gate refuses shorter keys)")

    report = (
        retire_previous(path, dry_run=args.dry_run)
        if args.retire_previous
        else rotate(path, key=args.key, length=args.length, dry_run=args.dry_run)
    )
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for name, value in report.items():
            if isinstance(value, list):
                print(f"{name}:")
                for item in value:
                    print(f"  - {item}")
            else:
                print(f"{name}: {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
