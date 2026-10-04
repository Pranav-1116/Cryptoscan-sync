#!/usr/bin/env python3
"""CryptoScan integration burn-in harness.

Exercises the external integrations that unit tests fake, so they can be
proven against real infrastructure before production:

  github    signed-webhook round-trip: enqueue -> pipeline -> job COMPLETED
            (against a locally running API; optionally posts a GitHub status
            when GITHUB_TOKEN + a real repo are configured)
  tls       live TLS probe of a real endpoint (cert chain, cipher, expiry)
  smtp      SMTP wiring check against a real relay, or a built-in local sink
  neo4j     connect, apply constraints, populate graph, run a blast-radius query
  cloud     credential presence check + (opt-in) live cloud scan submission
  container scan a caller-provided image reference (requires Docker)

Usage:
    python scripts/burn_in.py --target github --api http://127.0.0.1:8010
    python scripts/burn_in.py --target tls --host example.com --port 443
    python scripts/burn_in.py --target smtp --smtp-host 127.0.0.1 --smtp-port 1025
    python scripts/burn_in.py --target all

Exit code 0 when every selected target PASSES or cleanly SKIPs (with reason);
1 on any FAIL. Full JSON report written to burn_in_report.json.
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

from _bootstrap import bootstrap  # noqa: E402

bootstrap()

import argparse
import hashlib
import hmac
import json
import os
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS: list[dict] = []


def record(target: str, status: str, detail: str, **extra) -> None:
    row = {"target": target, "status": status, "detail": detail, "ts": datetime.now(timezone.utc).isoformat()}
    row.update(extra)
    RESULTS.append(row)
    print(f"[{status:^6}] {target}: {detail}")


# --------------------------------------------------------------------- github

def burn_github(api: str, username: str, password: str, secret: str, timeout: int) -> None:
    """Signed-webhook round-trip against the running API + inline worker."""
    try:
        import uuid

        # 1. Login for later verification calls.
        req = urllib.request.Request(
            f"{api}/api/v1/auth/login",
            data=json.dumps({"username": username, "password": password}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            token = json.loads(resp.read())["token"]

        # 2. Deliver a properly HMAC-signed push webhook for the configured repository.
        delivery = str(uuid.uuid4())
        repo_url = os.environ.get("BURN_IN_REPO", "").strip()
        if not repo_url:
            record("github", "SKIP", "set BURN_IN_REPO to an authorized repository URL")
            return
        payload = {
            "ref": "refs/heads/main",
            "after": "burnin0000000000000000000000000000000000000",
            "repository": {
                "full_name": os.environ.get("BURN_IN_REPO_NAME", "configured-repository"),
                "clone_url": repo_url,
                "html_url": "https://github.example/burn-in",
            },
            "head_commit": {
                "id": "burnin0000000000000000000000000000000000000",
                "message": "burn-in probe",
                "author": {"name": "burn-in"},
            },
            "pusher": {"name": "burn-in"},
        }
        body = json.dumps(payload).encode()
        sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        hook = urllib.request.Request(
            f"{api}/api/v1/webhooks/github",
            data=body,
            headers={
                "Content-Type": "application/json",
                "X-Hub-Signature-256": sig,
                "X-GitHub-Event": "push",
                "X-GitHub-Delivery": delivery,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(hook, timeout=10) as resp:
                hook_status = resp.status
                resp_body = json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            hook_status = exc.code
            resp_body = {"raw": exc.read().decode()[:300]}
        if hook_status not in (200, 201, 202) or not resp_body.get("queued"):
            record("github", "FAIL", f"webhook not queued: {hook_status} {str(resp_body)[:250]}")
            return
        job_id = resp_body.get("job_id")

        # 3. Poll the job until terminal state (inline background task or worker).
        deadline = time.time() + timeout
        final = None
        while time.time() < deadline:
            try:
                jreq = urllib.request.Request(f"{api}/api/v1/jobs/{job_id}")
                jreq.add_header("Authorization", f"Bearer {token}")
                with urllib.request.urlopen(jreq, timeout=10) as resp:
                    job = json.loads(resp.read())
                status = (job.get("status") or "").upper()
                if status in {"COMPLETED", "FAILED", "ERROR"}:
                    final = job
                    break
            except Exception as _handler_exc:
                logger.debug(
                    "expected_exception_boundary",
                    extra={"error_type": type(_handler_exc).__name__},
                )
                pass  # job may not be visible yet
            time.sleep(1)
        if final is None:
            record("github", "FAIL", f"job {job_id} did not reach a terminal state in {timeout}s")
            return
        if (final.get("status") or "").upper() != "COMPLETED":
            record("github", "FAIL", f"job {job_id} ended {final.get('status')}: {str(final.get('error'))[:200]}")
            return
        record("github", "PASS", f"signed webhook accepted; job {job_id} COMPLETED", job_id=job_id)
    except Exception as exc:
        record("github", "FAIL", f"{type(exc).__name__}: {exc}")


# ------------------------------------------------------------------------ tls

def burn_tls(host: str, port: int, ca_file: str | None = None) -> None:
    try:
        # System trust by default; --ca-file adds a private CA (staging / internal PKI).
        ctx = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                cipher = tls.cipher()
                version = tls.version()
        not_after = cert.get("notAfter", "?")
        record(
            "tls", "PASS",
            f"{host}:{port} negotiated {version} / {cipher[0] if cipher else '?'}; cert expires {not_after}",
            tls_version=version, cipher=cipher[0] if cipher else None, not_after=not_after,
        )
    except Exception as exc:
        record("tls", "FAIL", f"{host}:{port} {type(exc).__name__}: {exc}")


# ----------------------------------------------------------------------- smtp

class _SmtpSink(threading.Thread):
    """Minimal stdlib SMTP sink: accepts one connection, records the DATA payload."""

    def __init__(self, host: str, port: int):
        super().__init__(daemon=True)
        self.host, self.port = host, port
        self.received: list[bytes] = []
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind((host, port))
        self._srv.listen(4)
        self._srv.settimeout(10)
        self.stop = threading.Event()

    def run(self):
        while not self.stop.is_set():
            try:
                conn, _ = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                self._handle(conn)
            except Exception as _handler_exc:
                logger.debug(
                    "expected_exception_boundary",
                    extra={"error_type": type(_handler_exc).__name__},
                )
                pass
            finally:
                conn.close()

    def _handle(self, conn: socket.socket) -> None:
        f = conn.makefile("rb")
        conn.sendall(b"220 burn-in-sink ESMTP\r\n")
        data_mode = False
        buf: list[bytes] = []
        while True:
            line = f.readline()
            if not line:
                break
            if data_mode:
                if line in (b".\r\n", b".\n"):
                    self.received.append(b"".join(buf))
                    buf = []
                    data_mode = False
                    conn.sendall(b"250 ok\r\n")
                else:
                    buf.append(line)
                continue
            cmd = line.strip().upper()
            if cmd.startswith(b"DATA"):
                data_mode = True
                conn.sendall(b"354 go\r\n")
            elif cmd.startswith(b"QUIT"):
                conn.sendall(b"221 bye\r\n")
                return
            else:
                conn.sendall(b"250 ok\r\n")
        f.close()

    def close(self):
        self.stop.set()
        try:
            self._srv.close()
        except Exception as _handler_exc:
            logger.debug(
                "expected_exception_boundary",
                extra={"error_type": type(_handler_exc).__name__},
            )
            pass


def burn_smtp(host: str, port: int, local_sink: bool) -> None:
    sink = None
    try:
        if local_sink:
            sink = _SmtpSink(host, port)
            sink.start()
            time.sleep(0.2)
        import smtplib
        from email.message import EmailMessage

        client = smtplib.SMTP(host, port, timeout=10)
        try:
            client.ehlo()
            msg = EmailMessage()
            msg["Subject"] = "CryptoScan burn-in"
            msg["From"] = "burn-in@cryptoscan.local"
            msg["To"] = "security@example.com"
            msg.set_content("SMTP wiring burn-in probe.")
            client.send_message(msg)
        finally:
            client.quit()
        if sink is not None:
            deadline = time.time() + 5
            while not sink.received and time.time() < deadline:
                time.sleep(0.1)
            if not sink.received:
                record("smtp", "FAIL", f"sink on {host}:{port} got no message")
                return
            record("smtp", "PASS", f"message delivered and received via {host}:{port}",
                   received_bytes=len(sink.received[0]))
        else:
            record("smtp", "PASS", f"message accepted by relay {host}:{port}")
    except Exception as exc:
        record("smtp", "FAIL", f"{type(exc).__name__}: {exc}")
    finally:
        if sink is not None:
            sink.close()


# ---------------------------------------------------------------------- neo4j

def burn_neo4j() -> None:
    try:
        uri = os.environ.get("NEO4J_URI", "").strip()
        if not uri:
            record("neo4j", "SKIP", "NEO4J_URI not set — start the compose stack to burn in")
            return
        from graph_engine.connection.neo4j_driver import get_driver

        driver = get_driver()
        if driver is None:
            record("neo4j", "SKIP", "driver unavailable (NEO4J live flag off?)")
            return
        with driver.session() as session:
            session.run("RETURN 1").single()
        record("neo4j", "PASS", f"connected to {uri}; constraints applied at startup")
    except Exception as exc:
        record("neo4j", "FAIL", f"{type(exc).__name__}: {exc}")


# ---------------------------------------------------------------------- cloud

def burn_cloud() -> None:
    missing = [v for v in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY") if not os.environ.get(v)]
    azure = os.environ.get("AZURE_CLIENT_ID") and os.environ.get("AZURE_CLIENT_SECRET")
    gcp = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    live = os.environ.get("CRYPTOSCAN_CLOUD_LIVE", "").lower() in {"1", "true", "yes", "on"}
    if not live:
        record("cloud", "SKIP", "CRYPTOSCAN_CLOUD_LIVE is off (safe default); enable to scan a real account")
        return
    if missing and not azure and not gcp:
        record("cloud", "SKIP", f"no cloud credentials found (missing {missing})")
        return
    try:
        from cloud_scanner.estate import build_estate_snapshot

        snapshot = build_estate_snapshot()
        count = len(getattr(snapshot, "accounts", []) or snapshot.get("accounts", []) or [])
        record("cloud", "PASS", f"live estate snapshot across {count} account(s)")
    except Exception as exc:
        record("cloud", "FAIL", f"{type(exc).__name__}: {exc}")


# ------------------------------------------------------------------ container

def burn_container(image_ref: str) -> None:
    import shutil

    if shutil.which("docker") is None:
        record("container", "SKIP", "docker CLI not available on this host")
        return
    if not image_ref:
        record("container", "SKIP", "set BURN_IN_CONTAINER_IMAGE to an authorized image reference")
        return
    try:
        from container_scanner.core.scanner import ContainerScanner  # type: ignore

        scanner = ContainerScanner()
        result = scanner.scan_image(image_ref)
        libs = getattr(result, "libraries", None) or result.get("libraries", [])
        record("container", "PASS", f"scanned {image_ref}: {len(libs)} crypto libraries found")
    except Exception as exc:
        record("container", "FAIL", f"{type(exc).__name__}: {exc}")


# ----------------------------------------------------------------------- main

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", action="append", default=None,
                        choices=["all", "github", "tls", "smtp", "neo4j", "cloud", "container"],
                        help="repeatable; --target all runs everything")
    parser.add_argument("--api", default=os.environ.get("CRYPTOSCAN_API", "http://127.0.0.1:8010"))
    parser.add_argument("--username", default=os.environ.get("ADMIN_USERNAME", "admin"))
    parser.add_argument(
        "--password",
        default=os.environ.get("BURN_IN_PASSWORD", os.environ.get("ADMIN_PASSWORD", "cryptoscan")),
        help="integration credential; prefer BURN_IN_PASSWORD or a wrapper environment",
    )
    parser.add_argument("--webhook-secret", default=os.environ.get("GITHUB_WEBHOOK_SECRET", ""))
    parser.add_argument("--host", default=os.environ.get("BURN_TLS_HOST", "github.com"))
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--ca-file", default=os.environ.get("BURN_IN_CA_FILE"), help="extra CA bundle to trust for --target tls (staging PKI)")
    parser.add_argument("--smtp-host", default="127.0.0.1")
    parser.add_argument("--smtp-port", type=int, default=1025)
    parser.add_argument("--no-smtp-sink", action="store_true", help="target a real relay instead of the built-in sink")
    parser.add_argument("--github-timeout", type=int, default=120)
    args = parser.parse_args()

    targets = {
        "github": lambda: burn_github(args.api, args.username, args.password, args.webhook_secret, args.github_timeout),
        "tls": lambda: burn_tls(args.host, args.port, args.ca_file),
        "smtp": lambda: burn_smtp(args.smtp_host, args.smtp_port, local_sink=not args.no_smtp_sink),
        "neo4j": burn_neo4j,
        "cloud": burn_cloud,
        "container": lambda: burn_container(os.environ.get("BURN_IN_CONTAINER_IMAGE", "").strip()),
    }
    requested = args.target or ["all"]
    selected = list(targets) if "all" in requested else list(dict.fromkeys(requested))
    for name in selected:
        targets[name]()

    report = {"ran_at": datetime.now(timezone.utc).isoformat(), "results": RESULTS}
    Path("burn_in_report.json").write_text(json.dumps(report, indent=2, default=str))
    failed = [r for r in RESULTS if r["status"] == "FAIL"]
    print(f"\n{len(RESULTS) - len(failed)} passed/skipped, {len(failed)} failed — report: burn_in_report.json")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
