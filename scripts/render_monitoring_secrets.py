#!/usr/bin/env python3
"""Render the two monitoring token files the compose overlay mounts.

Prompting an operator to copy a 64-character secret by hand into two files is how
the token in Alertmanager's `credentials_file` and the token the API validates
drift apart — and the failure mode is not an error message, it is a 401 that
Alertmanager retries silently while the pager stays quiet. So both files are
written from one place, from the same environment the API reads.

    ALERTMANAGER_WEBHOOK_TOKEN=... METRICS_TOKEN=... \
        python3 scripts/render_monitoring_secrets.py --dir infra/monitoring/secrets

Writes ``webhook_token`` and ``metrics_token`` mode ``0400``. Refuses a token
shorter than 32 characters (the API refuses to boot with one), a token equal to
another, and a directory that is world-writable. Prints lengths and a short
fingerprint — never the secret.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DIR = REPO_ROOT / "infra" / "monitoring" / "secrets"

#: file name -> environment variable the API reads
TOKENS = {
    "webhook_token": "ALERTMANAGER_WEBHOOK_TOKEN",
    "metrics_token": "METRICS_TOKEN",
}

MIN_LENGTH = 32


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:12]


def render(directory: Path, environ: dict[str, str] | None = None) -> list[dict[str, object]]:
    env = os.environ if environ is None else environ
    values: dict[str, str] = {}
    problems: list[str] = []
    for name, variable in TOKENS.items():
        value = (env.get(variable) or "").strip()
        if len(value) < MIN_LENGTH:
            problems.append(
                f"{variable} is {len(value)} character(s); the API refuses to boot "
                f"below {MIN_LENGTH} — generate one with `openssl rand -hex 32`"
            )
        values[name] = value
    distinct = [value for value in values.values() if value]
    if len(distinct) == len(values) and len(set(distinct)) != len(distinct):
        problems.append(
            "METRICS_TOKEN and ALERTMANAGER_WEBHOOK_TOKEN must differ: one is a "
            "read-only scrape credential and the other authorises an inbound write"
        )
    if problems:
        for problem in problems:
            print(f"refused: {problem}", file=sys.stderr)
        raise SystemExit(2)

    directory.mkdir(parents=True, exist_ok=True)
    mode = directory.stat().st_mode
    if mode & stat.S_IWOTH:
        raise SystemExit(
            f"refused: {directory} is world-writable; secrets must not be writable "
            "by another local user"
        )
    os.chmod(directory, 0o700)

    written = []
    for name, value in values.items():
        path = directory / name
        # 0600 then truncate, so an existing file is never briefly world-readable
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, value.encode())
            os.write(fd, b"\n")
        finally:
            os.close(fd)
        os.chmod(path, 0o400)
        written.append({"file": str(path), "variable": TOKENS[name],
                        "length": len(value), "sha256_prefix": fingerprint(value)})
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dir", default=str(DEFAULT_DIR),
                        help="where the token files are written")
    args = parser.parse_args(argv)
    for record in render(Path(args.dir)):
        print(f"wrote {record['file']} ({record['variable']}, "
              f"{record['length']} chars, sha256:{record['sha256_prefix']}…)")
    print("Alertmanager and Prometheus mount these; the API reads the same values "
          "from its environment.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
