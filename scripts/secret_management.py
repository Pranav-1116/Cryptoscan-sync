"""Secrets: in the source, in the logs, in the errors, in the browser.

Five claims a bank asks about, each turned into a probe that either holds or does
not:

* no credential is committed to the tree;
* a secret in a **structured log field** is redacted;
* a secret in an **error message** never reaches the client;
* a token is not written to an **access log**;
* the console does not keep a session in `localStorage` or carry it in a URL.

The honest part is the third and the "free text" half of the second: redaction by
key name cannot save a secret that a developer interpolated into a message
string, and this drill says so instead of scoring it as a pass. A **canary** is
written into each path; the canary is the evidence, and a canary that comes back
out is a finding.

Run::

    python scripts/secret_management.py \\
        --json docs/bank-environment/123-secret-management.json \\
        --md   docs/bank-environment/123-secret-management.md
"""

from __future__ import annotations

import contextlib
import io
import json
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = "cryptoscan.secret-management/1"
VERSION = "secret-management/1.0"

REPO_ROOT = Path(__file__).resolve().parents[1]

PASS, PARTIAL, FAIL = "PASS", "PARTIAL", "FAIL"

#: A value that must never appear in output. Random enough that a hit is real.
CANARY = "CANARY-7f3c9e1a-4b2d-4e88-9c1f-DO-NOT-LOG"

PATTERNS: dict[str, re.Pattern[str]] = {
    "private_key_block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "openai_key": re.compile(r"\bsk-[A-Za-z0-9]{32,}\b"),
    "jwt_literal": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "credential_literal": re.compile(
        r"""(?:password|passwd|secret|api_key|token)\s*[:=]\s*["'][^"'\s{}$]{12,}["']""",
        re.IGNORECASE),
}

#: Hits that are not credentials, with the reason. Every entry is a decision a
#: reviewer can argue with, which is why the reason is printed in the artifact
#: rather than the hit being silently dropped.
ALLOWED: dict[str, str] = {
    "scripts/secret_management.py":
        "this drill: the allow-list reasons quote the example key they excuse",
    "services/devsecops/devsecops/yara_rules.py":
        "YARA detector: these are the strings the rule *looks for*, not key material",
    "services/cryptava/cryptava/signing.py":
        "the Cryptava agent writes ITS OWN freshly generated Ed25519 key to its 0600 state "
        "file; the string is the PEM header it writes, no key material is in source",
    "scripts/golden_path.py":
        "the AWS documentation example key AKIAIOSFODNN7EXAMPLE, used by a local harness",
    "services/eventstream/eventstream/bus.py":
        "development stream key; the constructor raises in production when "
        "STREAM_SECRET is unset or still this value",
    "scripts/coverage.sh":
        "test-only environment values, exported under ENVIRONMENT=test",
    "services/eventstream/eventstream/livecbom.py":
        "development CBOM signing key; the constructor raises in production when "
        "CBOM_SIGNING_SECRET is unset or still this value",
}

SCAN_ROOTS = ("services", "scripts", "shared", "integrations", "infra", "frontend/src")

#: Roots that ship to a customer. A hit here grades the row; a hit in ``scripts/``
#: is a drill fixture and is listed but does not grade — the difference is stated
#: in the artifact so the split is auditable rather than a convenient exclusion.
PRODUCT_ROOTS = ("services/", "shared/", "integrations/", "infra/", "frontend/src/")


def _source_files() -> list[Path]:
    files: list[Path] = []
    for base in SCAN_ROOTS:
        root = REPO_ROOT / base
        if not root.exists():
            continue
        for path in root.rglob("*"):
            text = str(path)
            if not path.is_file():
                continue
            if "node_modules" in text or "__pycache__" in text or "/tests/" in text:
                continue
            if path.name.startswith("test_") or path.name.endswith(".map"):
                continue
            if ".test." in path.name or ".spec." in path.name:
                continue
            files.append(path)
    return sorted(files)


def scan_source() -> dict[str, Any]:
    hits: list[dict[str, Any]] = []
    allowed: list[dict[str, Any]] = []
    for path in _source_files():
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        relative = str(path.relative_to(REPO_ROOT))
        for name, pattern in PATTERNS.items():
            for match in pattern.finditer(text):
                line = text[: match.start()].count("\n") + 1
                entry = {"rule": name, "path": relative, "line": line,
                         "excerpt": match.group(0)[:60],
                         "surface": "product" if relative.startswith(PRODUCT_ROOTS)
                         else "harness"}
                reason = ALLOWED.get(relative)
                if reason:
                    entry["reason"] = reason
                    allowed.append(entry)
                else:
                    hits.append(entry)
    return {"findings": [hit for hit in hits if hit["surface"] == "product"],
            "harness": [hit for hit in hits if hit["surface"] == "harness"],
            "allowed": allowed}


# ------------------------------------------------------------------- probes
def probe_log_redaction() -> list[dict[str, Any]]:
    """Structured keys, free text, and a control with redaction switched off."""
    from shared_logging.logger_factory import configure_logging

    probes: list[dict[str, Any]] = []

    def capture(free_text: bool, **kwargs) -> str:
        # Go through the configured pipeline rather than attaching a private
        # handler: a handler this drill installs itself would bypass the
        # ProcessorFormatter that performs the redaction, and the probe would
        # measure the drill instead of the product. The redirect must start
        # *before* configuration, because the factory binds sys.stdout.
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            configure_logging("INFO", json_output=True, force=True, **kwargs)
            logger = logging.getLogger("secret-drill")
            if free_text:
                logger.warning("auth failed for password=%s", CANARY)
            else:
                logger.warning("auth failed",
                               extra={"password": CANARY, "api_token": CANARY,
                                      "context": {"private_key": CANARY}})
        return buffer.getvalue()

    structured = capture(False, redact=True)
    free_text = capture(True, redact=True)
    probes.append({
        "probe": "structured-field",
        "expected": "a secret in a password/token/private_key field is masked",
        "ok": CANARY not in structured,
        "observed": "canary absent: password/api_token/private_key were masked"
        if CANARY not in structured
        else "canary present: structured redaction did not apply",
    })
    probes.append({
        "probe": "free-text-message",
        "expected": "a secret interpolated into the message string is masked",
        "ok": CANARY not in free_text,
        "observed": "canary absent" if CANARY not in free_text else
        "canary present: redaction is key-based, so a secret written into the "
        "message text is not scrubbed",
    })

    # The control: with redaction off the canary must appear, or the probe is blind.
    unredacted = capture(False, redact=False)
    probes.append({
        "probe": "control-redaction-off",
        "expected": "with redact=False the canary appears, proving the probe can see it",
        "ok": CANARY in unredacted,
        "observed": "canary visible" if CANARY in unredacted else
        "the canary never reached the sink — the probe would pass vacuously",
    })
    return probes


def probe_error_message() -> list[dict[str, Any]]:
    """A failure carrying a credential in its text must not reach the client."""
    for relative in ("services/api", "services/database", "shared/shared_models",
                     "shared/shared_config", "services/devsecops", "services/observability"):
        candidate = str(REPO_ROOT / relative)
        if candidate not in sys.path:
            sys.path.insert(0, candidate)

    import os

    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "secret-management-drill-key-32-characters")

    from fastapi import FastAPI, HTTPException
    from fastapi.testclient import TestClient

    app = FastAPI()

    @app.get("/probe/leak")
    def leak() -> dict:
        # The shape that leaks in real systems: a driver error, quoted into detail.
        raise RuntimeError(f"postgresql://svc:{CANARY}@db.internal:5432/prod")

    @app.get("/probe/missing")
    def missing() -> dict:
        raise HTTPException(status_code=500, detail=f"login failed for svc/{CANARY}")

    client = TestClient(app, raise_server_exceptions=False)
    runtime = client.get("/probe/leak")
    explicit = client.get("/probe/missing")
    probes = [
        {
            "probe": "unhandled-exception-body",
            "expected": "a driver error's text does not appear in the response",
            "ok": CANARY not in runtime.text,
            "observed": "canary absent from the 500 body" if CANARY not in runtime.text
            else "canary present in the 500 body",
        },
        {
            "probe": "explicit-detail",
            "expected": "this drill's own deliberate detail carries the canary",
            "ok": CANARY in explicit.text,
            "observed": "control: a hand-written detail is returned verbatim, so the "
                        "check above is not passing because responses are empty",
        },
    ]
    return probes


def probe_access_log() -> list[dict[str, Any]]:
    """Authorization and API-key headers must not be logged by the access line."""
    for relative in ("services/api", "services/database", "shared/shared_models",
                     "shared/shared_config", "services/observability", "services/devsecops"):
        candidate = str(REPO_ROOT / relative)
        if candidate not in sys.path:
            sys.path.insert(0, candidate)

    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from api.middleware.logging_middleware import LoggingMiddleware

    from shared_logging.logger_factory import configure_logging

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        configure_logging("INFO", json_output=True, force=True)
        app = FastAPI()
        app.add_middleware(LoggingMiddleware)

        # Not an /api path: this app is built by the drill, so a route here
        # proves nothing about the product, and naming a product-shaped path
        # would put a phantom endpoint in the route-contract census.
        @app.get("/__drill/access-line")
        def probe() -> dict:
            return {"ok": True}

        client = TestClient(app)
        client.get("/__drill/access-line",
                   headers={"Authorization": f"Bearer {CANARY}", "X-API-Key": CANARY,
                            "Cookie": f"cryptoscan_session={CANARY}"})
    text = buffer.getvalue()

    emitted = "http_request" in text
    return [
        {
            "probe": "access-line-has-no-credential",
            "expected": "no bearer token, API key or cookie value in the access line",
            "ok": CANARY not in text and emitted,
            "observed": "the access line was written and carries none of the three"
            if emitted and CANARY not in text else
            ("the access line was not written — nothing to inspect" if not emitted else
             "a credential appears in the access line"),
        },
    ]


def _strip_comments(text: str) -> str:
    """Drop comments before scanning.

    A comment is not code. The first version of this probe flagged an invite
    page that reads its token from the URL *fragment*, because a comment in the
    same file mentioned `?token=` — a false positive that would have hidden a
    real one beside it.
    """
    without_block = re.sub(r"/\*[\s\S]*?\*/", "", text)
    return re.sub(r"(?m)^\s*//.*$|\s//\s.*$", "", without_block)


def probe_frontend() -> list[dict[str, Any]]:
    """The console must not store a session where script or history can read it."""
    root = REPO_ROOT / "frontend" / "src"
    storage: list[str] = []
    url_tokens: list[str] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix not in {".ts", ".tsx"}:
            continue
        if ".test." in path.name:
            continue
        text = _strip_comments(path.read_text(encoding="utf-8", errors="ignore"))
        relative = str(path.relative_to(REPO_ROOT))
        for match in re.finditer(r"(?:localStorage|sessionStorage)\.\w+\(\s*[\"']([^\"']+)", text):
            key = match.group(1)
            if re.search(r"token|secret|session|auth|key", key, re.IGNORECASE):
                storage.append(f"{relative}: {key}")
        # A credential in the *query string* reaches servers and Referer headers.
        # A credential in the *fragment* (`#/invite?token=…`) never leaves the
        # browser, which is why only `?…=`/`&…=` inside string literals counts.
        for match in re.finditer(r"[\"'][^\"']*[?&](token|api_key|access_token)=[^\"']*[\"']", text):
            url_tokens.append(f"{relative}: {match.group(0)[:40]}")

    # Negative control: the same detector over a file that does the wrong thing
    # must report it, or a clean result above means the regexes never matched
    # anything at all.
    planted = _strip_comments(
        'localStorage.setItem("zelinx_token", token);\n'
        'const url = "/api/v1/export?token=" + token;\n')
    control_hits = (
        bool(re.search(r"(?:localStorage|sessionStorage)\.\w+\(\s*[\"']([^\"']+)", planted))
        and bool(re.search(r"[\"'][^\"']*[?&](token|api_key|access_token)=[^\"']*[\"']", planted))
    )

    return [
        {
            "probe": "control-planted-store-and-url",
            "expected": "the detector reports a planted localStorage token and a token in a "
                        "query string",
            "ok": control_hits,
            "observed": "both planted patterns detected" if control_hits else
            "the detector is blind — a clean result above would be meaningless",
        },
        {
            "probe": "no-token-in-web-storage",
            "expected": "no session token, secret or API key written to localStorage",
            "ok": not storage,
            "observed": f"{len(storage)} storage write(s) of a credential-shaped key"
            if storage else "no credential-shaped key is written to browser storage",
        },
        {
            "probe": "no-token-in-url",
            "expected": "no token carried in a query string",
            "ok": not url_tokens,
            "observed": f"{len(url_tokens)} query-string credential(s)"
            if url_tokens else "no token in a URL",
        },
    ], {"storage": storage[:10], "urls": url_tokens[:10]}


# ----------------------------------------------------------------------- rows
def measure() -> dict[str, Any]:
    rows: list[dict[str, Any]] = []

    source = scan_source()
    rows.append({
        "id": "source_scan",
        "question": "is a credential committed to the tree?",
        "verdict": PASS if not source["findings"] else FAIL,
        "probes": [{
            "probe": "no-live-credential",
            "expected": "no un-allowlisted secret pattern in non-test source",
            "ok": not source["findings"],
            "observed": f"{len(source['findings'])} finding(s) across "
                        f"{len(PATTERNS)} patterns; {len(source['allowed'])} "
                        f"allow-listed with a stated reason",
        }],
        "unproven": ["a secret that matches no pattern (a bare high-entropy string) is "
                     "not found by this scan; entropy scanning produces enough noise here "
                     "to be switched off rather than tuned to pass"],
        "limits": [],
        "findings": source["findings"][:20],
        "allowed": source["allowed"][:20],
    })

    log_probes = probe_log_redaction()
    free_text_ok = next((probe["ok"] for probe in log_probes
                         if probe["probe"] == "free-text-message"), True)
    structured_ok = next((probe["ok"] for probe in log_probes
                          if probe["probe"] == "structured-field"), True)
    control_ok = next((probe["ok"] for probe in log_probes
                       if probe["probe"] == "control-redaction-off"), True)
    log_verdict = FAIL if not (structured_ok and control_ok) else (
        PASS if free_text_ok else PARTIAL)
    rows.append({
        "id": "log_redaction",
        "question": "does a secret written to a log come back out?",
        "verdict": log_verdict,
        "probes": log_probes,
        "unproven": [] if free_text_ok else
        ["redaction is key-based: a secret interpolated into the message text is "
         "written verbatim. The mitigation is a rule (never interpolate a credential) "
         "and a log-side pattern scrub, neither of which is in place yet"],
        "limits": ["measured through the configured handler in-process; the behaviour of "
                   "a collector agent's own log shipper is its own"],
    })

    error_probes = probe_error_message()
    error_ok = next((probe["ok"] for probe in error_probes
                     if probe["probe"] == "unhandled-exception-body"), False)
    control = next((probe["ok"] for probe in error_probes
                    if probe["probe"] == "explicit-detail"), False)
    rows.append({
        "id": "error_messages",
        "question": "can a failing call return a credential to the caller?",
        "verdict": PASS if error_ok and control else (PARTIAL if control else FAIL),
        "probes": error_probes,
        "unproven": [],
        "limits": ["the application's own handlers are the subject of guide 120's rows; "
                   "this row asks what an unhandled driver error and a hand-written detail "
                   "put on the wire"],
    })

    access_probes = probe_access_log()
    rows.append({
        "id": "access_log",
        "question": "does the request log record the credential it was given?",
        "verdict": PASS if all(probe["ok"] for probe in access_probes) else FAIL,
        "probes": access_probes,
        "unproven": ["an upstream proxy's own access log is outside this drill"],
        "limits": [],
    })

    frontend_probes, frontend_detail = probe_frontend()
    storage_probe = next(probe for probe in frontend_probes
                         if probe["probe"] == "no-token-in-web-storage")
    url_probe = next(probe for probe in frontend_probes if probe["probe"] == "no-token-in-url")
    control_probe = next(probe for probe in frontend_probes
                         if probe["probe"] == "control-planted-store-and-url")

    rows.append({
        "id": "frontend_storage",
        "question": "does the console keep a session where a script on the page can read it?",
        "verdict": PASS if storage_probe["ok"] and control_probe["ok"] else FAIL,
        "probes": [storage_probe, control_probe],
        "unproven": ["the built bundle is not scanned: this reads `frontend/src`, and a "
                     "vendored dependency could still write to storage at runtime"],
        "limits": [
            "The backend also sets an httpOnly `cryptoscan_session` cookie and verifies the "
            "session with GET /api/v1/auth/me, so the localStorage copy is redundant as "
            "well as exposed. Removing it means making lib/api.ts hold the token in memory "
            "and letting the cookie carry the session across a reload.",
        ],
        "storage": frontend_detail["storage"],
        "urls": [],
    })
    rows.append({
        "id": "url_token",
        "question": "does a credential travel in a query string?",
        "verdict": PASS if url_probe["ok"] else PARTIAL,
        "probes": [url_probe],
        "unproven": [],
        "limits": [
            "The hit is `/?token=` on the invite-acceptance page: a one-time `csi_…` "
            "invitation token is read from the URL by design. It lands in browser history "
            "and in any Referer header sent from that page, and the token is single-use and "
            "server-revocable, which is why this is PARTIAL and not FAIL. A POST body would "
            "remove the exposure.",
        ],
        "storage": [],
        "urls": frontend_detail["urls"],
    })

    counts = {verdict: sum(1 for row in rows if row["verdict"] == verdict)
              for verdict in (PASS, PARTIAL, FAIL)}
    return {
        "schema": SCHEMA,
        "version": VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": counts,
        "rows": rows,
        "limits": [
            "The canary proves a specific path does not echo a specific string. It cannot "
            "prove that some other path — a queue payload, a crash dump, a support bundle — "
            "does not.",
            "Source scanning is pattern-based; a credential with no recognisable shape is "
            "invisible to it.",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    lines = [
        "# Secret management — canaries through four paths",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[PASS]} pass · {counts[PARTIAL]} partial · {counts[FAIL]} fail**",
        "",
        "| Question | Verdict | Evidence |",
        "|---|---|---|",
    ]
    for row in report["rows"]:
        evidence = row["probes"][0]["observed"] if row["probes"] else ""
        lines.append(f"| **{row['question']}** | **{row['verdict']}** | {evidence} |")

    lines += ["", "## Row by row", ""]
    for row in report["rows"]:
        lines.append(f"### `{row['id']}` — {row['verdict']}")
        lines.append("")
        lines.append(f"*{row['question']}*")
        lines.append("")
        for probe in row["probes"]:
            mark = "PASS" if probe["ok"] else "NOT MET"
            lines.append(f"- **{mark}** `{probe['probe']}` — {probe['observed']}")
        for finding in row.get("findings", []) or []:
            lines.append(f"- **Finding:** `{finding['rule']}` at "
                         f"`{finding['path']}:{finding['line']}`")
        for entry in row.get("allowed", []) or []:
            lines.append(f"- **Allow-listed:** `{entry['path']}:{entry['line']}` "
                         f"({entry['rule']}) — {entry['reason']}")
        for name in row.get("storage", []) or []:
            lines.append(f"- **Storage write:** `{name}`")
        for name in row.get("urls", []) or []:
            lines.append(f"- **URL credential:** `{name}`")
        for gap in row.get("unproven", []):
            lines.append(f"- **Not proven:** {gap}")
        for limit in row.get("limits", []):
            lines.append(f"- **Limit:** {limit}")
        lines.append("")

    lines += ["## What this does not prove", ""]
    for limit in report["limits"]:
        lines.append(f"- {limit}")
    lines.append("")
    closed = [row["question"] for row in report["rows"] if row["verdict"] == PASS]
    open_rows = [row for row in report["rows"] if row["verdict"] != PASS]
    lines.append("**What this drill supports:**")
    lines.append("")
    for question in closed:
        lines.append(f"- {question} — answered, evidence above.")
    lines.append("")
    if open_rows:
        lines.append("**What it does not support (and should not be quoted as if it did):**")
        lines.append("")
        for row in open_rows:
            first_gap = ([probe["observed"] for probe in row["probes"] if not probe["ok"]]
                         or row.get("unproven") or row.get("limits") or ["see the row"])
            lines.append(f"- **{row['verdict']}** — {row['question']} {first_gap[0]}")
        lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Secret-management drill.")
    parser.add_argument("--json", help="write the report JSON here")
    parser.add_argument("--md", help="write the markdown report here")
    parser.add_argument("--max-fail", type=int, default=99,
                        help="exit non-zero when more than this many rows fail")
    args = parser.parse_args(argv)

    report = measure()
    if args.json:
        path = Path(args.json)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2) + "\n")
    if args.md:
        path = Path(args.md)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render_md(report))

    if args.md or args.json:
        print(render_md(report))
    else:
        for row in report["rows"]:
            print(f"{row['verdict']:<8} {row['id']:<18} "
                  f"{row['probes'][0]['observed'][:100] if row['probes'] else ''}")
        print(f"\n{report['counts']}")
    return 0 if report["counts"][FAIL] <= args.max_fail else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
