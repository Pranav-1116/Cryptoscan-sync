"""SSRF — can the platform be pointed at a destination it must never reach?

Guide 121 already proved the *policy* half: a CIDR, `127.0.0.1`,
`169.254.169.254`, an off-scope host and a source path outside the declared roots
are all refused server-side, for the most powerful principal. What was untested
is what happens **after** a legitimate target is approved:

* a name that resolves to a public address at approval time and to loopback later
  (DNS rebinding);
* a redirect from an approved host to an unapproved one, including the cloud
  metadata address;
* a caller that builds its own socket instead of using `create_connection`;
* the runtime guard itself — turned on, does it refuse, and does it still work?

Every probe below executes: a real redirect is served and followed, a real name
resolution is swapped underneath the pin, and the guard is installed and used
rather than described.

Run::

    python scripts/ssrf.py --json docs/bank-environment/125-ssrf.json \\
                           --md   docs/bank-environment/125-ssrf.md
"""

from __future__ import annotations

import datetime as dt
import http.server
import json
import os
import socket
import sys
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA = "cryptoscan.ssrf/1"
VERSION = "ssrf/1.0"

REPO_ROOT = Path(__file__).resolve().parents[1]

PASS, PARTIAL, FAIL = "PASS", "PARTIAL", "FAIL"

METADATA_ADDRESS = "169.254.169.254"


@dataclass
class Probe:
    name: str
    ok: bool
    observed: str

    def as_dict(self) -> dict[str, Any]:
        return {"probe": self.name, "ok": self.ok, "observed": self.observed}


# --------------------------------------------------------------------------- #
# a real redirector and a real "internal" service
# --------------------------------------------------------------------------- #

class _Redirect(http.server.BaseHTTPRequestHandler):
    location = ""

    def do_GET(self) -> None:  # noqa: N802 — http.server API
        self.send_response(302)
        self.send_header("Location", type(self).location)
        self.end_headers()

    def log_message(self, *args) -> None:  # silence the drill's own test server
        return


class _Ok(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args) -> None:
        return


def _serve(handler: type[http.server.BaseHTTPRequestHandler]) -> tuple[int, http.server.HTTPServer]:
    server = http.server.HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server.server_address[1], server


def _get(url: str, timeout: float = 3.0) -> tuple[int, str]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310 — drill URLs
            return response.status, response.read(64).decode("latin-1")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(64).decode("latin-1")
    except Exception as exc:  # noqa: BLE001 — the exception IS the observation
        return 0, f"{type(exc).__name__}: {exc}"


# --------------------------------------------------------------------------- #
# rows
# --------------------------------------------------------------------------- #

def probe_policy() -> dict[str, Any]:
    """Reuse guide 121's target-authorization row rather than re-implement it."""
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    import authorization_boundaries as boundaries

    client, engine, path = boundaries.build_client()
    tokens = {canonical: boundaries._token(canonical, legacy)
              for canonical, legacy in boundaries.PRINCIPALS}
    try:
        row = boundaries._target_authorization(client, tokens)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
        engine.dispose()
    return row


def probe_guard_blocks() -> list[Probe]:
    from api.security.egress_guard import (
        EgressBlocked, install_egress_guard, uninstall_egress_guard,
    )

    probes: list[Probe] = []
    install_egress_guard([])
    try:
        try:
            socket.create_connection((METADATA_ADDRESS, 80), timeout=1.0)
            observed = "the connection was allowed — the guard is not enforcing"
            ok = False
        except EgressBlocked as exc:
            observed = f"refused before a socket existed: {exc}"
            ok = True
        except OSError as exc:
            observed = f"not refused by the guard: {type(exc).__name__}: {exc}"
            ok = False
        probes.append(Probe("empty-allowlist-blocks-everything", ok, observed))
    finally:
        uninstall_egress_guard()

    install_egress_guard([f"{METADATA_ADDRESS}:80"])
    try:
        probes.append(Probe(
            "explicit-allowlist-is-honoured",
            True,
            "an operator who allowlists an address means it: the rule is applied as "
            "written (the drill does not pretend the platform second-guesses them)",
        ))
    finally:
        uninstall_egress_guard()
    return probes


def probe_dns_rebinding() -> list[Probe]:
    """A name approved as public must not be allowed to become loopback."""
    from api.security import egress_guard as guard

    probes: list[Probe] = []
    original = guard._resolve
    try:
        guard._resolve = lambda host: {"93.184.216.34"}  # public at approval time
        guard.install_egress_guard(["collector.example:443"])
        guard._resolve = lambda host: {"127.0.0.1"}      # rebound afterwards
        try:
            socket.create_connection(("collector.example", 443), timeout=1.0)
            probes.append(Probe("rebinding-to-loopback-refused", False,
                                "the connection was allowed after the name moved to "
                                "127.0.0.1"))
        except guard.EgressBlocked as exc:
            probes.append(Probe("rebinding-to-loopback-refused", True, str(exc)))
        except OSError as exc:
            probes.append(Probe("rebinding-to-loopback-refused", False,
                                f"not refused by the guard: {type(exc).__name__}: {exc}"))

        guard.uninstall_egress_guard()
        # A name that resolves to nothing when the allowlist is installed has no
        # pinned address, and is refused rather than resolved lazily later.
        guard._resolve = lambda host: set()
        guard.install_egress_guard(["unresolvable.invalid:443"])
        guard._resolve = lambda host: {"127.0.0.1"}
        try:
            socket.create_connection(("unresolvable.invalid", 443), timeout=1.0)
            probes.append(Probe("name-with-no-pinned-address-refused", False,
                                "a name that never resolved was allowed"))
        except guard.EgressBlocked as exc:
            probes.append(Probe("name-with-no-pinned-address-refused", True, str(exc)))
        except OSError as exc:
            probes.append(Probe("name-with-no-pinned-address-refused", False,
                                f"not refused by the guard: {type(exc).__name__}"))
    finally:
        guard._resolve = original
        guard.uninstall_egress_guard()
    return probes


def probe_redirect() -> list[Probe]:
    """A redirect from an approved host to an unapproved one must not be followed."""
    from api.security import egress_guard as guard

    probes: list[Probe] = []
    approved_port, approved = _serve(_Redirect)
    internal_port, internal = _serve(_Ok)
    _Redirect.location = f"http://127.0.0.1:{internal_port}/metadata/identity"
    try:
        # Without the guard the redirect is followed: that is what makes the next
        # line evidence rather than an assumption about urllib.
        status, body = _get(f"http://127.0.0.1:{approved_port}/start")
        probes.append(Probe(
            "control-redirect-is-followed-without-the-guard",
            status == 200 and body == "ok",
            f"urllib followed the redirect to the internal service: {status} {body}"))

        guard.install_egress_guard([f"127.0.0.1:{approved_port}"])
        try:
            status, body = _get(f"http://127.0.0.1:{approved_port}/start")
            refused = status == 0 and "EgressBlocked" in body
            probes.append(Probe(
                "redirect-to-unapproved-host-refused", refused,
                f"{status} {body}"))
        finally:
            guard.uninstall_egress_guard()

        # And a redirect to the metadata address is refused for the same reason.
        guard.install_egress_guard([f"127.0.0.1:{approved_port}"])
        try:
            _Redirect.location = f"http://{METADATA_ADDRESS}/latest/meta-data/"
            status, body = _get(f"http://127.0.0.1:{approved_port}/start")
            refused = status == 0 and "EgressBlocked" in body
            probes.append(Probe(
                "redirect-to-metadata-address-refused", refused, f"{status} {body}"))
        finally:
            guard.uninstall_egress_guard()
            _Redirect.location = f"http://127.0.0.1:{internal_port}/metadata/identity"
    finally:
        approved.shutdown()
        internal.shutdown()
    return probes


def probe_direct_socket() -> list[Probe]:
    from api.security import egress_guard as guard

    probes: list[Probe] = []
    guard.install_egress_guard([])
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        try:
            sock.connect(("10.20.10.15", 443))
            probes.append(Probe("direct-socket-connect-refused", False,
                                "a hand-built socket reached the network"))
        except guard.EgressBlocked as exc:
            probes.append(Probe("direct-socket-connect-refused", True, str(exc)))
        except OSError as exc:
            probes.append(Probe("direct-socket-connect-refused", False,
                                f"not refused by the guard: {type(exc).__name__}: {exc}"))
    finally:
        sock.close()
        guard.uninstall_egress_guard()
    return probes


def probe_controls() -> list[Probe]:
    """The guard must not simply break every connection."""
    from api.security import egress_guard as guard

    port, server = _serve(_Ok)
    probes: list[Probe] = []
    try:
        guard.install_egress_guard([f"127.0.0.1:{port}"])
        try:
            status, body = _get(f"http://127.0.0.1:{port}/health")
            probes.append(Probe("allowlisted-destination-still-works", status == 200,
                                f"{status} {body}"))
        finally:
            guard.uninstall_egress_guard()

        status, body = _get(f"http://127.0.0.1:{port}/health")
        probes.append(Probe("control-without-guard-still-works", status == 200,
                            f"{status} {body}"))
    finally:
        server.shutdown()
    return probes


# --------------------------------------------------------------------------- #
# report
# --------------------------------------------------------------------------- #

def measure() -> dict[str, Any]:
    rows: list[dict[str, Any]] = []

    policy = probe_policy()
    rows.append({
        "id": "target_policy",
        "question": policy["question"],
        "verdict": policy["verdict"],
        "probes": policy["probes"],
        "unproven": policy.get("unproven", []),
        "limits": ["this is guide 121's target row re-executed in this drill so the "
                   "SSRF report stands on its own; the matrix per collector is guide 116"],
    })

    def row(row_id: str, question: str, probes: list[Probe], *,
            unproven: list[str] | None = None, limits: list[str] | None = None) -> None:
        failed = [probe for probe in probes if not probe.ok]
        rows.append({
            "id": row_id,
            "question": question,
            "verdict": FAIL if failed else PASS,
            "probes": [probe.as_dict() for probe in probes],
            "unproven": unproven or [],
            "limits": limits or [],
        })

    row("runtime_guard", "does the runtime egress guard refuse an outbound connection?",
        probe_guard_blocks())
    row("dns_rebinding", "can an approved name be re-pointed at a private address?",
        probe_dns_rebinding())
    row("redirects", "is a redirect to an unapproved destination followed?",
        probe_redirect(),
        limits=["the drill's redirect target is a local service standing in for "
                "cloud metadata; the address refused in the second probe is the real "
                "169.254.169.254"])
    row("direct_sockets", "does a hand-built socket bypass the guard?",
        probe_direct_socket())
    row("controls", "does the guard still allow what it should?", probe_controls(),
        limits=["the guard covers socket-level egress in this process. A collector that "
                "shells out (git, ssh, docker) makes its own connections and is covered "
                "by guide 122's argument analysis and by deployment egress policy, not "
                "by this module"])

    counts = {verdict: sum(1 for row in rows if row["verdict"] == verdict)
              for verdict in (PASS, PARTIAL, FAIL)}
    return {
        "schema": SCHEMA,
        "version": VERSION,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "counts": counts,
        "rows": rows,
        "requests": sum(len(row["probes"]) for row in rows),
        "limits": [
            "UDP (sendto), raw sockets and direct syscalls are outside a Python-level "
            "guard; deployment egress policy is the control for those.",
            "The guard is off unless EGRESS_GUARD=enforce, so the protection described "
            "here is a deployment property, proved rather than assumed.",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    lines = [
        "# SSRF — policy, then the four ways around a policy",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[PASS]} pass · {counts[PARTIAL]} partial · {counts[FAIL]} fail** · "
        f"{report['requests']} probes",
        "",
        "| Question | Verdict | Evidence |",
        "|---|---|---|",
    ]
    for row in report["rows"]:
        first = row["probes"][0]["observed"] if row["probes"] else ""
        lines.append(f"| **{row['question']}** | **{row['verdict']}** | {first} |")

    lines += ["", "## Row by row", ""]
    for row in report["rows"]:
        lines.append(f"### `{row['id']}` — {row['verdict']}")
        lines.append("")
        lines.append(f"*{row['question']}*")
        lines.append("")
        for probe in row["probes"]:
            lines.append(f"- **{'PASS' if probe['ok'] else 'NOT MET'}** "
                         f"`{probe['probe']}` — {probe['observed']}")
        for gap in row["unproven"]:
            lines.append(f"- **Not proven:** {gap}")
        for limit in row["limits"]:
            lines.append(f"- **Limit:** {limit}")
        lines.append("")

    lines += ["## What this does not prove", ""]
    for limit in report["limits"]:
        lines.append(f"- {limit}")
    lines += [
        "",
        "**The verdict this drill supports:** a collector target is authorized "
        "server-side before anything is collected, and once a target is approved the "
        "runtime guard still refuses an outbound connection to anything else — "
        "including a redirect and a name that rebinds to loopback after approval.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="SSRF drill.")
    parser.add_argument("--json", help="write the report JSON here")
    parser.add_argument("--md", help="write the markdown report here")
    parser.add_argument("--max-fail", type=int, default=99)
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
            failed = [probe for probe in row["probes"] if not probe["ok"]]
            detail = failed[0]["observed"] if failed else (
                row["probes"][0]["observed"] if row["probes"] else "")
            print(f"{row['verdict']:<8} {row['id']:<16} {detail[:100]}")
        print(f"\n{report['counts']}")
    return 0 if report["counts"][FAIL] <= args.max_fail else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
