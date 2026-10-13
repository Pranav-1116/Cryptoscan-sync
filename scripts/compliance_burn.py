#!/usr/bin/env python3
"""Compliance burn: evidence pack, attestation signing/verification, WORM
retention gate and the auditor API — end-to-end against the LIVE api.

Everything asserted here comes from real system state: the evidence pack
checks the live signed audit chain, the schema actually deployed, the rate
limits actually configured; the attestation is a real JWS (HS256) over the
pack snapshot and is verified back with the platform's own verifier.

Usage:
    python scripts/compliance_burn.py --api http://127.0.0.1:8010 \
        --username admin --password ... [--out docs/compliance-burn.md]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


class Client:
    def __init__(self, base: str, timeout: float = 30.0):
        self.base = base.rstrip("/")
        self.timeout = timeout

    def request(
        self, method: str, path: str, *, body: bytes | None = None, headers: dict | None = None
    ) -> tuple[int, dict | str]:
        req = urllib.request.Request(self.base + path, method=method, data=body, headers=headers or {})
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
        h = {"Content-Type": "application/json"}
        h.update(headers or {})
        return self.request("POST", path, body=json.dumps(payload).encode(), headers=h)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default="http://127.0.0.1:8010")
    ap.add_argument("--username", default="admin")
    ap.add_argument("--password", required=True)
    ap.add_argument("--out", default="docs/compliance-burn.md")
    args = ap.parse_args()

    client = Client(args.api)
    results: list[dict] = []

    def record(step: str, ok: bool, detail: str) -> None:
        results.append({"step": step, "verdict": "PASS" if ok else "FAIL", "detail": detail})
        print(f"[{'PASS' if ok else 'FAIL'}] {step}: {detail}")

    status, body = client.post_json("/api/v1/auth/login", {"username": args.username, "password": args.password})
    token = body.get("token") if isinstance(body, dict) else None
    record("login", status == 200 and bool(token), f"POST /auth/login -> {status}")
    auth = {"Authorization": f"Bearer {token}"}

    # 1. evidence pack from live state
    status, pack = client.request("GET", "/api/v1/compliance/evidence", headers=auth)
    controls = {c["control"]: c["status"] for c in pack.get("controls", [])} if isinstance(pack, dict) else {}
    ok = (
        status == 200
        and isinstance(pack, dict)
        and controls.get("audit.chain_integrity") == "pass"
        and pack.get("summary", {}).get("fail", 1) == 0
        and "pack_sha256" in pack
    )
    record(
        "evidence-pack",
        ok,
        f"GET /compliance/evidence -> {status}; controls={controls} "
        f"sha256={str(pack.get('pack_sha256'))[:16] if isinstance(pack, dict) else '?'}…",
    )

    # 2. non-admin is refused (RBAC on compliance surface)
    status2, _ = client.request("GET", "/api/v1/compliance/evidence")
    record("evidence-rbac", status2 == 401, f"unauthenticated GET /compliance/evidence -> {status2}")

    # 3. pin the evidence pack, then sign THAT exact pack (real JWS) —
    #    durable sign-off references a persisted, content-addressed pack
    status, snap = client.post_json("/api/v1/compliance/evidence/packs", {}, headers=auth)
    pack_sha = snap.get("pack_sha256") if isinstance(snap, dict) else None
    record(
        "evidence-pin",
        status == 200 and bool(pack_sha),
        f"POST /compliance/evidence/packs -> {status}; "
        f"created={snap.get('created') if isinstance(snap, dict) else '?'}; "
        f"sha256={str(pack_sha)[:16] if pack_sha else '?'}…",
    )

    status, att = client.post_json(
        "/api/v1/compliance/attestations",
        {"scope": "burn-quarterly", "signed_by": "platform-burn", "pack_sha256": pack_sha},
        headers=auth,
    )
    ok = status == 200 and isinstance(att, dict) and att.get("jws", "").count(".") == 2
    record(
        "attestation-sign",
        ok,
        f"POST /compliance/attestations -> {status}; jws_segments="
        f"{att.get('jws', '').count('.') if isinstance(att, dict) else '?'}+1",
    )

    # 4. verification round-trip
    status, verdict = client.post_json(
        "/api/v1/compliance/attestations/verify", {"jws": att.get("jws"), "snapshot": att.get("snapshot")}, headers=auth
    )
    ok = status == 200 and isinstance(verdict, dict) and verdict.get("valid") is True
    record(
        "attestation-verify",
        ok,
        f"POST /compliance/attestations/verify -> {status}; valid={verdict.get('valid') if isinstance(verdict, dict) else '?'}",
    )

    # 5. tampered attestation rejected
    jws = att.get("jws", "")
    if jws:
        head, pay, sig = jws.split(".")
        tampered = f"{head}.{pay[:-4]}AAAA.{sig}"
        status, verdict = client.post_json("/api/v1/compliance/attestations/verify", {"jws": tampered}, headers=auth)
        ok = status == 200 and isinstance(verdict, dict) and verdict.get("valid") is False
        record(
            "attestation-tamper-rejected",
            ok,
            f"tampered JWS -> valid={verdict.get('valid') if isinstance(verdict, dict) else '?'}",
        )
    else:
        record("attestation-tamper-rejected", False, "no jws from step 3")

    # 6. WORM retention gate
    status, ret = client.request("GET", "/api/v1/compliance/retention", headers=auth)
    ok = (
        status == 200
        and isinstance(ret, dict)
        and ret.get("policy", {}).get("audit_log_years") == 7
        and ret.get("delete_allowed_now") is False
    )
    record(
        "worm-retention",
        ok,
        f"GET /compliance/retention -> {status}; audit_log_years="
        f"{ret.get('policy', {}).get('audit_log_years') if isinstance(ret, dict) else '?'} "
        f"delete_allowed_now={ret.get('delete_allowed_now') if isinstance(ret, dict) else '?'}",
    )

    # 7. auditor API (read-only scope, separate credential or admin session)
    status, _ = client.request("GET", "/api/v1/compliance/audit/evidence", headers={"X-Auditor-Key": "wrong-key"})
    record("auditor-wrong-key-401", status == 401, f"X-Auditor-Key wrong -> {status}")
    status, a_evidence = client.request("GET", "/api/v1/compliance/audit/evidence", headers=auth)
    record("auditor-admin-session", status == 200, f"admin session on /compliance/audit/evidence -> {status}")

    # 8. self-monitoring sweep live
    status, alerts = client.request("GET", "/api/v1/ops/alerts", headers=auth)
    ok = status == 200 and isinstance(alerts, dict) and "alerts" in alerts and "slo" in alerts
    record(
        "self-alerts-live",
        ok,
        f"GET /ops/alerts -> {status}; fired={len(alerts.get('alerts', [])) if isinstance(alerts, dict) else '?'} "
        f"(quiet platform = empty list)",
    )

    # 9. capacity forecast from the metering trail (fresh estate = honest empty)
    status, fc = client.request("GET", "/api/v1/ops/capacity/forecast", headers=auth)
    ok = status == 200 and isinstance(fc, dict) and "plans" in fc
    record(
        "capacity-forecast",
        ok,
        f"GET /ops/capacity/forecast -> {status}; months_of_data="
        f"{fc.get('estate_usage_by_month') if isinstance(fc, dict) else '?'} "
        f"(empty estate reports no trend, never invents one)",
    )

    passed = sum(1 for r in results if r["verdict"] == "PASS")
    total = len(results)
    verdict = "PASS" if passed == total else "FAIL"

    out = Path(args.out)
    if not out.is_absolute():
        out = REPO / out
    out.parent.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    lines = [
        "# Compliance burn — evidence, attestation, WORM, auditor API over live HTTP",
        "",
        f"*Run:* `{ts}` against `{args.api}`  |  *Verdict:* **{verdict}** ({passed}/{total} checks)",
        "",
        "The evidence pack is collected from live state at request time (signed",
        "audit chain re-verified, deployed schema inspected, rate limits read",
        "from the running policy) — no canned evidence. Attestations are real",
        "JWS compact signatures (HS256) over the pack snapshot and fail closed",
        "on any mutation.",
        "",
        "| # | Check | Verdict | Evidence |",
        "|---|-------|---------|----------|",
    ]
    for i, r in enumerate(results, 1):
        lines.append(f"| {i} | {r['step']} | {r['verdict']} | {r['detail']} |")
    lines += ["", f"**Burn verdict: {verdict}**", ""]
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n{verdict}: {passed}/{total} -> {out}")
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
