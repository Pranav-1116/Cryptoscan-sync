"""Fail closed before starting the development-only stack overlay.

The overlay deliberately uses plaintext internal endpoints, disabled OpenSearch
security and Vault dev mode. It must never be mistaken for a production profile.
No certificate/key bytes are read or printed here.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from dotenv import dotenv_values


def check(environment: dict[str, str]) -> list[str]:
    errors: list[str] = []
    if environment.get("STACK_DEV_ACK") != "development-only":
        errors.append("STACK_DEV_ACK must equal development-only")
    if environment.get("ENVIRONMENT", "development").strip().lower() not in {
        "development", "test", "testing",
    }:
        errors.append("ENVIRONMENT must be development/test; the stack overlay is not production")

    raw_cert_dir = environment.get("GATEWAY_TLS_CERT_DIR", "").strip()
    if not raw_cert_dir or not Path(raw_cert_dir).is_absolute():
        errors.append("GATEWAY_TLS_CERT_DIR must be an absolute path outside the repository")
    else:
        cert_dir = Path(raw_cert_dir).resolve()
        repo_root = Path(__file__).resolve().parents[1]
        if cert_dir == repo_root or repo_root in cert_dir.parents:
            errors.append("GATEWAY_TLS_CERT_DIR must be outside the repository")
        for filename in ("tls.crt", "tls.key"):
            if not (cert_dir / filename).is_file():
                errors.append(f"GATEWAY_TLS_CERT_DIR must contain {filename}")
    return errors


def main() -> int:
    # Match Docker Compose's default .env plus process-environment override.
    # Parse only the three non-secret control fields; never print the .env.
    repo_root = Path(__file__).resolve().parents[1]
    dotenv = dotenv_values(repo_root / ".env")
    controls = ("STACK_DEV_ACK", "ENVIRONMENT", "GATEWAY_TLS_CERT_DIR")
    environment = {k: str(dotenv[k]) for k in controls if dotenv.get(k) is not None}
    environment.update({k: os.environ[k] for k in controls if k in os.environ})
    errors = check(environment)
    if errors:
        for error in errors:
            print(f"development stack refused: {error}", file=sys.stderr)
        return 2
    print("development stack preflight passed (not production-qualified)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
