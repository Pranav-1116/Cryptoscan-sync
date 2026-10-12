#!/usr/bin/env python3
"""Serve the API with ENFORCED mutual TLS (advanced/82, round 38).

    python scripts/serve_mtls.py --host 0.0.0.0 --port 8443

Reads TLS_CERT_FILE / TLS_KEY_FILE / TLS_CA_BUNDLE / TLS_MIN_VERSION
(same settings the posture surface inspects) and hands uvicorn an
SSLContext with ``verify_mode=CERT_REQUIRED`` — clients without a
site-CA-signed certificate are rejected at the TLS layer, before a
single line of application code runs. Deployment owns the certificates;
this script refuses to serve without them (fail-loud, never plaintext).
"""

from __future__ import annotations

import argparse
import os
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=os.environ.get("HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int,
                        default=int(os.environ.get("PORT", "8443")))
    parser.add_argument("--workers", type=int, default=1)
    args = parser.parse_args()

    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..",
                                    "services", "api"))

    from api.security.mtls import MtlsError, build_mtls_context

    try:
        context = build_mtls_context(
            os.environ.get("TLS_CERT_FILE", ""),
            os.environ.get("TLS_KEY_FILE", ""),
            os.environ.get("TLS_CA_BUNDLE", ""),
            min_version=os.environ.get("TLS_MIN_VERSION", "1.2"),
        )
    except MtlsError as exc:
        print(f"refusing to serve: {exc}", file=sys.stderr)
        return 2

    import uvicorn

    uvicorn.run("api.main:app", host=args.host, port=args.port,
                workers=args.workers, ssl=context)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
