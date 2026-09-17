#!/usr/bin/env python3
"""Registry webhook burn: signed end-to-end verification against the LIVE api.

Proves, over real HTTP against a running server:
  1. a signed registry push event (X-ZELNX-Signature HMAC) is accepted and
     triggers a REAL container filesystem scan (real package discovery, real
     vulnerability lookup — counts come from the detector, never invented);
  2. a tampered signature is rejected 401 (fail-closed when a secret is
     configured — always, in every environment);
  3. the GitHub-style alternate header (X-Hub-Signature-256) interoperates;
  4. a signed event pointing at a missing image root is rejected 404 by the
     scan-target validation (no silent success);
  5. the platform's own observability surface (/ops/metrics) is live and
     counting the burn's own requests.

The "image root" used here is a harness fixture under data/burn/ (a minimal
unpacked container filesystem with a pinned requirements.txt and one planted
secret marker) — it exists to give the real scanner something true to find.
It is never shipped as product data.

Usage:
    python scripts/registry_webhook_burn.py --api http://127.0.0.1:8010 \
        --username admin --password ... --secret <REGISTRY_WEBHOOK_SECRET> \
        [--out docs/registry-webhook-burn.md]
"""
from __future__ import annotations

import argparse
import hashlib
import hmac as hmac_mod
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
IMAGE_ROOT = REPO / "data" / "burn" / "registry-image-root"

REQUIREMENTS = "requests==2.31.0\ncryptography==42.0.5\nurllib3==2.2.1\n"
# Planted marker for the REAL secret scanner (harness fixture, not product data).
PLANTED_SECRET = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7BURNEXAMPLE\n"


def build_image_root() -> Path:
    app = IMAGE_ROOT / "app"
    app.mkdir(parents=True, exist_ok=True)
    (app / "requirements.txt").write_text(REQUIREMENTS, encoding="utf-8")
    (app / ".env.burn").write_text(PLANTED_SECRET, encoding="utf-8")
    (IMAGE_ROOT / "bin").mkdir(exist_ok=True)
    return IMAGE_ROOT


class Client:
    def __init__(self, base: str, timeout: float = 30.0):
        self.base = base.rstrip("/")
        self.timeout = timeout

    def request(self, method: str, path: str, *, body: bytes | None = None,
                headers: dict | None = None) -> tuple[int, dict | str]:
        req = urllib.request.Request(self.base + path, method=method,
                                     data=body, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode()
                return resp.status, (json.loads(raw) if raw.strip().startswith(("{", "[")) else raw)
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode()
            try:
                return exc.code, json.loads(raw)
            except Exception:
                return exc.code, raw

    def post_json(self, path: str, payload: dict, *, headers: dict | None = None) -> tuple[int, dict | str]:
        body = json.dumps(payload).encode()
        h = {"Content-Type": "application/json"}
        h.update(headers or {})
        return self.request("POST", path, body=body, headers=h)


def sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac_mod.new(secret.encode(), body, hashlib.sha256).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default="http://127.0.0.1:8010")
    ap.add_argument("--username", default="admin")
    ap.add_argument("--password", required=True)
    ap.add_argument("--secret", required=True,
                    help="Must equal the server's REGISTRY_WEBHOOK_SECRET")
    ap.add_argument("--out", default="docs/registry-webhook-burn.md")
    args = ap.parse_args()

    client = Client(args.api)
    results: list[dict] = []

    def record(step: str, ok: bool, detail: str) -> None:
        results.append({"step": step, "verdict": "PASS" if ok else "FAIL",
                        "detail": detail})
        print(f"[{'PASS' if ok else 'FAIL'}] {step}: {detail}")

    # 0. liveness + auth
    status, body = client.request("GET", "/api/v1/health/live")
    if status == 404:
        status, body = client.request("GET", "/api/v1/health")
    alive = status in (200, 401)  # 401 = alive behind auth
    record("liveness", alive, f"GET /health -> {status} (server responding)")
    status, body = client.post_json("/api/v1/auth/login",
                                    {"username": args.username, "password": args.password})
    token = body.get("token") if isinstance(body, dict) else None
    record("login", status == 200 and bool(token), f"POST /auth/login -> {status}")
    auth = {"Authorization": f"Bearer {token}"}

    # 1. build the harness image root
    root = build_image_root()
    record("image-root", root.exists(),
           f"harness image root at {root.relative_to(REPO)} (requirements.txt + planted secret marker)")

    # 2. SIGNED registry push -> real scan
    push_body = json.dumps({
        "image": "burn-registry.local/cryptoscan-burn:ledger",
        "path": str(root),
        "event": "PUSH",
    }).encode()
    status, body = client.post_json("/api/v1/webhooks/container",
                                    json.loads(push_body),
                                    headers={"X-ZELNX-Signature": sign(args.secret, push_body)})
    ok = (status == 200 and isinstance(body, dict) and body.get("scanned") is True
          and (body.get("packages") or 0) >= 2)
    record("signed-push-scan", ok,
           f"signed PUSH -> {status}; scanned={body.get('scanned') if isinstance(body, dict) else '?'} "
           f"packages={body.get('packages') if isinstance(body, dict) else '?'} "
           f"libraries={body.get('libraries') if isinstance(body, dict) else '?'} "
           f"vulnerabilities={body.get('vulnerabilities') if isinstance(body, dict) else '?'}")

    # 3. TAMPERED signature -> 401 fail-closed
    bad_sig = "sha256=" + ("0" * 64)
    status, body = client.post_json("/api/v1/webhooks/container",
                                    json.loads(push_body),
                                    headers={"X-ZELNX-Signature": bad_sig})
    record("tampered-signature-401", status == 401,
           f"forged signature -> {status} ({(body or {}).get('detail') if isinstance(body, dict) else body})")

    # 4. alternate GitHub-style header interop
    status, body = client.post_json("/api/v1/webhooks/container",
                                    json.loads(push_body),
                                    headers={"X-Hub-Signature-256": sign(args.secret, push_body)})
    record("alt-header-interop", status == 200,
           f"X-Hub-Signature-256 signed PUSH -> {status}")

    # 5. signed event, missing image root -> 404 (target validation, no silent ok)
    missing = {"image": "burn-registry.local/ghost:v0", "path": str(REPO / "data" / "burn" / "does-not-exist")}
    missing_body = json.dumps(missing).encode()
    status, body = client.post_json("/api/v1/webhooks/container", missing,
                                    headers={"X-ZELNX-Signature": sign(args.secret, missing_body)})
    record("missing-root-404", status == 404,
           f"signed event for absent root -> {status} ({(body or {}).get('detail') if isinstance(body, dict) else body})")

    # 6. observability surface live during the burn
    status, body = client.request("GET", "/api/v1/ops/metrics", headers=auth)
    text = body if isinstance(body, str) else ""
    ok = status == 200 and "http_requests_total" in text
    record("ops-metrics-live", ok,
           f"GET /ops/metrics -> {status}; prometheus exposition {'contains' if ok else 'MISSING'} http_requests_total")

    # 7. SLO snapshot live
    status, body = client.request("GET", "/api/v1/ops/slo", headers=auth)
    ok = status == 200 and isinstance(body, dict) and body.get("window_requests", 0) >= 5
    record("slo-live", ok,
           f"GET /ops/slo -> {status}; window_requests={body.get('window_requests') if isinstance(body, dict) else '?'}")

    passed = sum(1 for r in results if r["verdict"] == "PASS")
    total = len(results)
    verdict = "PASS" if passed == total else "FAIL"

    out = Path(args.out)
    if not out.is_absolute():
        out = REPO / out
    out.parent.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    lines = [
        "# Registry webhook burn — signed E2E over live HTTP",
        "",
        f"*Run:* `{ts}` against `{args.api}`  |  *Verdict:* **{verdict}** "
        f"({passed}/{total} checks)",
        "",
        "Every count below is produced by the real container detector running",
        "inside the live API process. The scan target is a harness fixture",
        "(`data/burn/registry-image-root/`) with pinned real packages so the",
        "detector has something true to find — never shipped as product data.",
        "",
        "| # | Check | Verdict | Evidence |",
        "|---|-------|---------|----------|",
    ]
    for i, r in enumerate(results, 1):
        lines.append(f"| {i} | {r['step']} | {r['verdict']} | {r['detail']} |")
    lines += [
        "",
        "## Signature scheme",
        "",
        "`X-ZELNX-Signature: sha256=HMAC_SHA256(REGISTRY_WEBHOOK_SECRET, raw_body)`",
        "(the GitHub-style `X-Hub-Signature-256` is accepted interchangeably).",
        "With a secret configured, a bad signature is a 401 in EVERY environment",
        "(fail-closed); without any signature, production always rejects (401).",
        "",
        f"**Burn verdict: {verdict}**",
        "",
    ]
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n{verdict}: {passed}/{total} -> {out}")
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
