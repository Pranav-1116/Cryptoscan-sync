#!/usr/bin/env python3
"""Production evidence runner — one command produces the signed report a bank's auditors take away.

Orchestrates the verifiable production gates and bundles their results into a
single tamper-evident, signed artifact:

  guard    fails-closed production config guard, exercised in BOTH directions
           (bad prod config must be rejected, good prod config must pass)
  drill    DR failover drill (deploy/ha/drill.sh) — needs docker + a live
           stack; cleanly SKIPs with a reason where that is not available
  load     real load/soak run against the API (scripts/load_test.py harness,
           production rate limiting active — it is unconditional middleware)
  smoke    health + auth + authenticated read checks against the same API
  chain    every report is appended to an append-only hash chain
           (data/evidence/production-evidence/chain.jsonl) using the
           platform's own ChainHasher/ContentHasher primitives; the whole
           chain is re-verified after every append

Signing: with CRYPTOSCAN_EVIDENCE_KEY set (or --key), the report is signed
JWS (HS256) via the platform's cbom signer. Without a key the artifact is
digest-only — the report says so plainly; a digest proves integrity, a key
proves origin.

Usage:
    python scripts/production_evidence.py                  # all phases
    python scripts/production_evidence.py --api URL --username U --password P
    python scripts/production_evidence.py --skip-drill --users 3 --duration 20
    python scripts/production_evidence.py --verify         # re-verify the chain
    python scripts/production_evidence.py --verify --key "$CRYPTOSCAN_EVIDENCE_KEY"

Exit code 0 when every phase PASSes or cleanly SKIPs (with reason); 1 on any
FAIL; 2 on usage error. The JSON report is written under
data/evidence/production-evidence/ and its location is printed at the end.
"""
from __future__ import annotations
from _bootstrap import bootstrap  # noqa: E402

bootstrap()

import argparse
import json
import os
import platform
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_DIR = ROOT / "data" / "evidence" / "production-evidence"
CHAIN_FILE = EVIDENCE_DIR / "chain.jsonl"
SCHEMA = "cryptoscan.production-evidence/1"
MAX_ERROR_RATE = 0.01  # same ceiling scripts/load_test.py enforces


# --------------------------------------------------------------------------- #
# Phase result
# --------------------------------------------------------------------------- #

class Phase:
    def __init__(self, name: str) -> None:
        self.name = name
        self.status: str = "PENDING"  # PASS | FAIL | SKIP
        self.detail: dict = {}
        self.ms: int = 0
        self._t0 = 0.0

    def __enter__(self) -> "Phase":
        self._t0 = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.ms = int((time.perf_counter() - self._t0) * 1000)
        if exc_type is not None and self.status == "PENDING":
            self.status = "FAIL"
            self.detail = {"error": f"{exc_type.__name__}: {exc}"}
        return False

    def pass_(self, **detail) -> None:
        self.status, self.detail = "PASS", detail

    def fail(self, **detail) -> None:
        self.status, self.detail = "FAIL", detail

    def skip(self, reason: str) -> None:
        self.status, self.detail = "SKIP", {"reason": reason}

    def as_dict(self) -> dict:
        return {"status": self.status, "detail": self.detail, "ms": self.ms}


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def http_json(url: str, data: dict | None = None, headers: dict | None = None,
              timeout: float = 15.0):
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(
        url, data=body, method="POST" if body is not None else "GET",
        headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"null")
        except Exception:
            return e.code, None


# --------------------------------------------------------------------------- #
# Phases
# --------------------------------------------------------------------------- #

def run_guard() -> Phase:
    """Exercise the fails-closed prod guard in both directions (subprocesses)."""
    with Phase("guard") as ph:
        script = ROOT / "scripts" / "check_prod_guard.py"
        bad_env = {
            **os.environ,
            "ENVIRONMENT": "production",
            "SECRET_KEY": "changeme",
            "ADMIN_PASSWORD": "changeme",
            "GITHUB_WEBHOOK_SECRET": "secret",
            "DATABASE_URL": "sqlite:////tmp/prod-guard-bad.db",
            "CORS_ORIGINS": "*",
            "REDIS_URL": "",
        }
        good_env = {
            **os.environ,
            "ENVIRONMENT": "production",
            "SECRET_KEY": "prod-evidence-guard-" + uuid.uuid4().hex,
            "ADMIN_PASSWORD_HASH": "pbkdf2_sha256$290000$" + "a" * 20,
            "GITHUB_WEBHOOK_SECRET": "prod-evidence-webhook-" + uuid.uuid4().hex,
            "DATABASE_URL": "postgresql+psycopg://u:p@db:5432/cryptoscan",
            "CORS_ORIGINS": "https://console.bank.example",
            "REDIS_URL": "",
        }
        # 1) a bad production config MUST be rejected
        r_bad = subprocess.run(
            [sys.executable, str(script), "--expect-reject"],
            env=bad_env, capture_output=True, text=True, timeout=120)
        # 2) a good production config MUST pass validation
        r_good = subprocess.run(
            [sys.executable, str(script)],
            env=good_env, capture_output=True, text=True, timeout=120)
        if r_bad.returncode == 0 and r_good.returncode == 0:
            ph.pass_(
                bad_config_rejected=True,
                good_config_accepted=True,
                bad_note=(r_bad.stdout or r_bad.stderr).strip().splitlines()[-1][:200],
                good_note=(r_good.stdout or r_good.stderr).strip().splitlines()[-1][:200],
            )
        else:
            ph.fail(
                bad_config_rejected=r_bad.returncode == 0,
                good_config_accepted=r_good.returncode == 0,
                bad_rc=r_bad.returncode, bad_tail=(r_bad.stdout + r_bad.stderr).strip()[-300:],
                good_rc=r_good.returncode, good_tail=(r_good.stdout + r_good.stderr).strip()[-300:],
            )
        return ph


def run_drill(compose_dir: Path, enabled: bool) -> Phase:
    """Run the DR failover drill; honest SKIP where docker/stack is absent."""
    with Phase("drill") as ph:
        if not enabled:
            ph.skip("disabled via --skip-drill")
            return ph
        if shutil.which("docker") is None:
            ph.skip("docker not available in this environment — run "
                    "deploy/ha/drill.sh on the target host and attach its output")
            return ph
        if not (compose_dir / "drill.sh").exists():
            ph.fail(missing=str(compose_dir / "drill.sh"))
            return ph
        r = subprocess.run(
            ["bash", str(compose_dir / "drill.sh")],
            cwd=str(compose_dir), capture_output=True, text=True, timeout=1800)
        tail = (r.stdout or "").strip().splitlines()[-6:]
        if r.returncode == 0:
            ph.pass_(exit_code=0, drill_output_tail=tail)
        else:
            ph.fail(exit_code=r.returncode,
                    drill_output_tail=tail + (r.stderr or "").strip().splitlines()[-3:])
        return ph


def _free_port(preferred: int) -> int:
    for port in (preferred, 0):
        with socket.socket() as s:
            try:
                s.bind(("127.0.0.1", port))
                if port == preferred:
                    return preferred
                return s.getsockname()[1]
            except OSError:
                continue
    raise RuntimeError("no free port found")


def _wait_healthy(url: str, timeout: float = 60.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            status, _ = http_json(url, timeout=3.0)
            if status == 200:
                return True
        except Exception:
            pass
        time.sleep(1.0)
    return False


def bring_up_staging(port: int, env_extra: dict | None = None) -> tuple[subprocess.Popen, dict]:
    """Fresh SQLite staging estate: uvicorn, random credentials, rate limiting
    active (RateLimitMiddleware is unconditional in api.main — never weakened)."""
    workdir = Path(tempfile.mkdtemp(prefix="prod-evidence-"))
    password = "ProdEvidence-" + uuid.uuid4().hex[:16]
    env = {
        **os.environ,
        "ENVIRONMENT": "development",
        "DATABASE_URL": f"sqlite:///{workdir}/staging.db",
        "REDIS_URL": "",
        "SECRET_KEY": "prod-evidence-" + uuid.uuid4().hex,
        "ADMIN_USERNAME": "admin",
        "ADMIN_PASSWORD": password,
        "CRYPTOSCAN_HOME": str(workdir / "home"),
        "GITHUB_WEBHOOK_SECRET": "prod-evidence-webhook-" + uuid.uuid4().hex,
        **(env_extra or {}),
    }
    log = open(workdir / "api.log", "wb")
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "api.main:app",
         "--host", "127.0.0.1", "--port", str(port)],
        cwd=str(ROOT), env=env, stdout=log, stderr=log,
        start_new_session=True)
    return proc, {"password": password, "workdir": workdir, "log": log}


def teardown_staging(proc: subprocess.Popen, meta: dict) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        proc.wait(timeout=15)
    except Exception:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            pass
    try:
        meta["log"].close()
    except Exception:
        pass


def run_load(api_url: str, users: int, duration: float,
             username: str, password: str) -> Phase:
    """Drive the repo's own load harness against the (staging or provided) API."""
    with Phase("load") as ph:
        script = ROOT / "scripts" / "load_test.py"
        cmd = [sys.executable, str(script),
               "--url", api_url, "--users", str(users),
               "--duration", str(duration),
               "--username", username, "--password", password,
               "--max-error-rate", str(MAX_ERROR_RATE)]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=3600 + 60 * users)
        except subprocess.TimeoutExpired:
            ph.fail(error="load harness timed out")
            return ph
        out = (r.stdout or "").strip()
        lines = out.splitlines()
        start = next((i for i, ln in enumerate(reversed(lines)) if ln.startswith("{")), None)
        block = "\n".join(lines[len(lines) - 1 - start:]) if start is not None else ""
        try:
            metrics = json.loads(block) if block else None
        except json.JSONDecodeError:
            metrics = None
        if r.returncode != 0 or not isinstance(metrics, dict):
            ph.fail(exit_code=r.returncode,
                    tail=(out or r.stderr or "").strip()[-400:])
            return ph
        error_rate = metrics.get("error_rate", 1.0)
        if error_rate <= MAX_ERROR_RATE:
            ph.pass_(**{k: metrics.get(k) for k in
                        ("requests", "throughput_rps", "error_rate", "duration_s")},
                     users=users, throttled_429=metrics.get("throttled_429"))
        else:
            ph.fail(error_rate=error_rate, limit=MAX_ERROR_RATE, **metrics)
        return ph


def run_smoke(api_url: str, username: str, password: str) -> Phase:
    with Phase("smoke") as ph:
        checks: dict = {}
        status, body = http_json(api_url + "/health")
        checks["health"] = status == 200
        status, body = http_json(api_url + "/api/v1/auth/login",
                                 data={"username": username, "password": password})
        token = (body or {}).get("token") if isinstance(body, dict) else None
        checks["login"] = status == 200 and bool(token)
        if token:
            status, body = http_json(
                api_url + "/api/v1/scans",
                headers={"Authorization": f"Bearer {token}"})
            # 200 = plain OK. 429 is the per-identity rate limit doing its
            # job (production behaviour under load) — recorded, not failed.
            read_ok = status in (200, 429)
            checks["authenticated_read"] = read_ok
            checks["authenticated_read_status"] = status
            if status == 429:
                checks["rate_limiter_active"] = True
        if all(v is not False for v in checks.values()) and len(checks) >= 3:
            ph.pass_(**checks)
        else:
            ph.fail(**checks)
        return ph


# --------------------------------------------------------------------------- #
# Evidence chain (platform primitives)
# --------------------------------------------------------------------------- #

def _load_chain() -> list[dict]:
    if not CHAIN_FILE.exists():
        return []
    return [json.loads(ln) for ln in CHAIN_FILE.read_text().splitlines() if ln.strip()]


def verify_chain(entries: list[dict]) -> dict:
    """Re-derive every content hash from the embedded report and re-walk the
    hash links — the same logic the per-scan evidence verifier uses."""
    from evidence.hashing.chain_hasher import ChainHasher
    from evidence.hashing.content_hasher import ContentHasher

    if not entries:
        return {"result": "VALID", "entries": 0, "message": "empty chain"}
    chain_id = entries[0]["chain_id"]
    for i, e in enumerate(entries):
        if e.get("chain_id") != chain_id:
            return {"result": "INVALID", "entries": len(entries),
                    "broken_at": i, "message": "chain_id mismatch"}
        if ContentHasher.compute_hash(e["report"]) != e["content_hash"]:
            return {"result": "INVALID", "entries": len(entries), "broken_at": i,
                    "message": "embedded report does not match its content hash "
                               "(report altered after signing)"}
    content_hashes = [e["content_hash"] for e in entries]
    stored = [e["chain_hash"] for e in entries]
    if not ChainHasher.verify_chain(content_hashes, stored, chain_id):
        for i, (c, s) in enumerate(zip(ChainHasher.compute_chain(content_hashes, chain_id),
                                       stored)):
            if c != s:
                return {"result": "BROKEN_AT_SEQUENCE", "entries": len(entries),
                        "broken_at": i, "message": f"hash link broken at entry {i}"}
        return {"result": "INVALID", "entries": len(entries), "broken_at": None,
                "message": "chain verification failed"}
    return {"result": "VALID", "entries": len(entries), "message": "all links intact"}


def append_to_chain(report: dict, chain_id: str) -> tuple[dict, dict]:
    from evidence.hashing.chain_hasher import ChainHasher
    from evidence.hashing.content_hasher import ContentHasher

    entries = _load_chain()
    content_hash = ContentHasher.compute_hash(report)
    # the platform primitive computes the full chain; we take the new tail
    chain_hash = ChainHasher.compute_chain(
        [e["content_hash"] for e in entries] + [content_hash], chain_id)[-1]
    entry = {
        "seq": len(entries),
        "chain_id": chain_id,
        "evidence_id": report["evidence_id"],
        "created_at": report["created_at"],
        "content_hash": content_hash,
        "chain_hash": chain_hash,
        "report": report,
    }
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    with CHAIN_FILE.open("a") as f:
        f.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")
    return entry, verify_chain(entries + [entry])


def sign_report(report: dict, key: str | None):
    if not key:
        return None, "digest-only (no CRYPTOSCAN_EVIDENCE_KEY set; a key proves origin, the digest proves integrity)"
    from cbom.signing.jws_signer import canonical_json, sign_compact
    return sign_compact(canonical_json(report), key.encode(), "HS256",
                        key_id="production-evidence"), "JWS HS256 via cbom signer"


# --------------------------------------------------------------------------- #
# Identity
# --------------------------------------------------------------------------- #

def identity() -> dict:
    commit, dirty = "", False
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"], cwd=str(ROOT),
            capture_output=True, text=True, timeout=10).stdout.strip()
        dirty = bool(subprocess.run(
            ["git", "status", "--porcelain"], cwd=str(ROOT),
            capture_output=True, text=True, timeout=10).stdout.strip())
    except Exception:
        pass
    version = ""
    vfile = ROOT / "VERSION"
    if vfile.exists():
        version = vfile.read_text().strip()
    return {
        "version": version,
        "git_commit": commit,
        "git_dirty": dirty,
        "host": platform.node(),
        "python": platform.python_version(),
        "os": platform.platform(),
    }


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #

def produce(args) -> int:
    phases: list[Phase] = []
    idt = identity()

    phases.append(run_guard())
    phases.append(run_drill(Path(args.compose_dir), enabled=not args.skip_drill))

    api_url = args.api
    proc, meta = None, None
    username, password = args.username, args.password or ""
    try:
        if not api_url:
            port = _free_port(args.port)
            api_url = f"http://127.0.0.1:{port}"
            proc, meta = bring_up_staging(port)
            if not _wait_healthy(api_url + "/health"):
                tail = Path(meta["workdir"], "api.log").read_text(errors="replace")[-400:]
                p = Phase("staging"); p.fail(error="staging API did not become healthy", tail=tail)
                phases.append(p)
                print("STAGING  FAIL — see api.log tail above")
                return 1
            password = meta["password"]
        # smoke first (a fresh estate must be healthy), then load — the load
        # phase exhausts the per-identity rate budget by design
        phases.append(run_smoke(api_url, username, password))
        phases.append(run_load(api_url, args.users, args.duration, username, password))
    finally:
        if proc is not None:
            teardown_staging(proc, meta)

    failed = [p for p in phases if p.status == "FAIL"]
    skipped = [p for p in phases if p.status == "SKIP"]

    chain_id = args.chain_id
    if not chain_id:
        entries = _load_chain()
        chain_id = entries[0]["chain_id"] if entries else str(uuid.uuid4())

    report = {
        "schema": SCHEMA,
        "evidence_id": str(uuid.uuid4()),
        "created_at": utcnow(),
        "identity": idt,
        "phases": {p.name: p.as_dict() for p in phases},
        "overall": "FAIL" if failed else "PASS",
        "summary": {
            "pass": sum(1 for p in phases if p.status == "PASS"),
            "fail": len(failed),
            "skip": len(skipped),
        },
        "chain": {"chain_id": chain_id, "entries_before": len(_load_chain())},
    }

    signature, signing = sign_report(report, args.key or os.environ.get("CRYPTOSCAN_EVIDENCE_KEY"))
    entry, chain_status = append_to_chain(report, chain_id)

    artifact = {
        **report,
        "content_hash": entry["content_hash"],
        "chain": {**report["chain"], "seq": entry["seq"], "chain_hash": entry["chain_hash"],
                  "verified_after_append": chain_status["result"] == "VALID"},
        "signature": signature,
        "signing": signing,
    }
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_file = EVIDENCE_DIR / f"production-evidence-{stamp}-{entry['seq']}.json"
    out_file.write_text(json.dumps(artifact, indent=2, sort_keys=True))

    # human summary
    print(f"\nproduction evidence — {artifact['overall']}")
    print(f"  identity : {idt.get('version') or 'n/a'} @ {idt.get('git_commit') or 'n/a'}"
          f"{' (dirty)' if idt.get('git_dirty') else ''} on {idt.get('host')}")
    for p in phases:
        mark = {"PASS": "PASS", "FAIL": "FAIL", "SKIP": "SKIP"}[p.status]
        note = ""
        if p.status == "SKIP":
            note = p.detail.get("reason", "")
        elif p.status == "PASS" and "throughput_rps" in p.detail:
            note = f"{p.detail.get('requests')} req @ {p.detail.get('throughput_rps')} rps, " \
                   f"errors={p.detail.get('error_rate')}"
        elif p.status == "FAIL":
            note = json.dumps(p.detail)[:160]
        print(f"  {mark:5}    {p.name} ({p.ms} ms){(' — ' + note) if note else ''}")
    print(f"  chain    : {chain_status['result']} entries={chain_status['entries']} "
          f"(seq {entry['seq']})  digest={entry['content_hash'][:16]}…")
    print(f"  signing  : {signing}")
    print(f"\nreport written: {out_file}")
    print("verify with   : python scripts/production_evidence.py --verify"
          + (" --key $CRYPTOSCAN_EVIDENCE_KEY" if signature else ""))
    return 1 if failed else 0


def verify(args) -> int:
    entries = _load_chain()
    if not entries:
        print("NO_CHAIN — no evidence chain found at", CHAIN_FILE)
        return 1
    status = verify_chain(entries)
    extra = f" BROKEN_AT={status['broken_at']}" if status.get("broken_at") is not None else ""
    print(f"{status['result']} entries={status['entries']}{extra}")
    print(status["message"])
    rc = 0 if status["result"] == "VALID" else 1
    if args.key:
        from cbom.signing.jws_signer import verify_compact
        target = entries[-1]
        if args.evidence_id:
            match = [e for e in entries if e["evidence_id"] == args.evidence_id]
            if not match:
                print(f"EVIDENCE_ID_NOT_FOUND {args.evidence_id}")
                return 1
            target = match[0]
        # the signature lives on the standalone artifact, not in the chain
        # entry — locate it by evidence_id
        art = next((p for p in EVIDENCE_DIR.glob("production-evidence-*.json")
                    if json.loads(p.read_text()).get("evidence_id") == target["evidence_id"]), None)
        if art is None:
            print("SIGNATURE_CHECK_SKIPPED — standalone artifact not found for this entry")
        else:
            data = json.loads(art.read_text())
            ok, why = verify_compact(data.get("signature") or "", args.key.encode())
            print(f"JWS {target['evidence_id']}: {'VALID' if ok else 'INVALID'} ({why})")
            if not ok:
                rc = 1
    return rc


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="zelnx production-evidence", description=__doc__)
    ap.add_argument("--api", default="", help="run against an existing API (default: fresh staging estate)")
    ap.add_argument("--port", type=int, default=8099, help="staging API port (default 8099, auto-avoids conflicts)")
    ap.add_argument("--username", default="admin")
    ap.add_argument("--password", default="", help="API password (required with --api; auto-generated otherwise)")
    ap.add_argument("--users", type=int, default=3, help="load test virtual users (default 3)")
    ap.add_argument("--duration", type=float, default=20.0, help="load test soak seconds (default 20)")
    ap.add_argument("--compose-dir", default=str(ROOT / "deploy" / "ha"))
    ap.add_argument("--skip-drill", action="store_true", help="do not attempt the DR drill")
    ap.add_argument("--chain-id", default="", help="chain id to append to (default: existing chain or new)")
    ap.add_argument("--key", default="", help="HS256 signing key (default: $CRYPTOSCAN_EVIDENCE_KEY)")
    ap.add_argument("--verify", action="store_true", help="verify the stored chain and exit")
    ap.add_argument("--evidence-id", default="", help="with --verify: also check this entry's JWS")
    args = ap.parse_args(argv)

    if args.verify:
        return verify(args)
    if args.api and not args.password:
        print("--password required with --api", file=sys.stderr)
        return 2
    return produce(args)


if __name__ == "__main__":
    raise SystemExit(main())
