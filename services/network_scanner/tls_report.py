#!/usr/bin/env python3
"""Read a network TLS scan JSON payload from stdin and print a one-screen
verdict (endpoint, negotiated TLS/cipher, cert expiry, version floor, weak
ciphers, chain/renegotiation). Used by scan-host.sh; stdlib only."""

from __future__ import annotations

import json
import sys


def _short(name: str | None, n: int = 46) -> str:
    if not name:
        return "?"
    return name if len(name) <= n else name[: n - 1] + "…"


def _names(items) -> list[str]:
    """Normalize cipher entries that are dicts {'cipher':...} or plain strings."""
    out = []
    for it in items or []:
        out.append(it.get("cipher") if isinstance(it, dict) else str(it))
    return out


def _cipher_verdict(c: dict) -> str:
    """Derive a clear verdict from the negotiated parameters (the registry can
    return UNKNOWN for TLS 1.3 codepoint names even when they are strong)."""
    suite = (c.get("cipher_suite") or "").upper()
    mode = (c.get("encryption_mode") or "").upper()
    tls = (c.get("tls_version") or "").upper()
    reg = (c.get("status") or "").upper()
    weak_tokens = ("RC4", "3DES", "DES-", "NULL", "EXPORT", "MD5", "ANON")
    if any(t in suite for t in weak_tokens):
        return "WEAK (disallowed cipher)"
    if "CHACHA20" in suite or mode == "GCM" or "GCM" in suite:
        if tls >= "TLSV1.3":
            return "STRONG (TLS 1.3 AEAD)"
        return "OK (AEAD)"
    if mode == "CBC" or "CBC" in suite:
        return "REVIEW (CBC / Lucky13 hardening)"
    if reg and reg not in ("UNKNOWN",):
        return reg
    return "REVIEW"


def report(f: dict) -> None:
    endpoint = f.get("endpoint", "?")
    status = f.get("status", "?")
    c = f.get("crypto") or {}
    print(f"● {endpoint}  —  {status}")

    if status != "OK":
        print(f"    error: {f.get('error') or 'no TLS result (DNS/timeout/refused/plain-HTTP)'}")
        return

    enc_algo = c.get("encryption_algorithm") or ""
    enc_mode = c.get("encryption_mode") or ""
    kx = c.get("key_exchange_algorithm") or ""
    alpn = c.get("alpn") or ""
    cipher_desc = f"{enc_algo}-{enc_mode}" if enc_algo and enc_mode else c.get("cipher_suite")
    print(
        f"    negotiated : {c.get('tls_version')} | {c.get('cipher_suite')} "
        f"| {cipher_desc} key={c.get('key_size')} kx={kx or '-'}"
        + (f" alpn={alpn}" if alpn else "")
        + f" | verdict={_cipher_verdict(c)}"
    )

    vf = f.get("version_floor") or {}
    if vf:
        print(
            f"    versions   : accepts {', '.join(vf.get('accepted') or []) or '-'} "
            f"| weakest={vf.get('weakest_accepted')} "
            f"| WEAK ACCEPTED={vf.get('weak_accepted') or 'none'}"
        )

    wc = f.get("weak_cipher_probe") or {}
    if wc:
        dis = _names(wc.get("disallowed_accepted"))
        cbc = _names(wc.get("cbc_accepted"))
        print(f"    ciphers    : disallowed accepted={dis or 'none'}")
        print(f"                 CBC accepted (Lucky13 hardening risk)={cbc or 'none'}")
        refused = _names(wc.get("refused"))
        print(f"                 refused={refused or []}")

    certs = f.get("certificates") or []
    if certs:
        leaf = certs[0]
        print(
            f"    leaf cert  : {_short(leaf.get('subject'))} "
            f"| {leaf.get('expiry_status')} ({leaf.get('days_until_expiry')}d) "
            f"| {leaf.get('public_key_algorithm')} {leaf.get('public_key_size')}"
        )

    chain = f.get("chain_validation") or {}
    if chain:
        print(
            f"    chain      : valid={chain.get('is_valid')} length={chain.get('chain_length')} "
            f"errors={chain.get('errors') or 'none'}"
        )

    rev = f.get("revocation_status") or {}
    if rev:
        print(f"    revocation : {rev.get('method')} -> {rev.get('status')} ({rev.get('reason', '')})")

    rn = f.get("renegotiation") or {}
    if rn:
        tls = (c.get("tls_version") or "").upper()
        if tls >= "TLSV1.3":
            print("    renegotiatn: n/a (renegotiation removed in TLS 1.3)")
        else:
            print(
                f"    renegotiatn: secure={rn.get('secure_renegotiation')} "
                f"client-initiated={rn.get('client_renegotiation')}"
            )

    issues = f.get("policy_issues") or []
    if issues:
        print(f"    ⚠ POLICY   : {', '.join(issues)}  ({f.get('compliance_issue')})")


def main() -> int:
    try:
        d = json.load(sys.stdin)
    except (ValueError, OSError) as exc:  # noqa: BLE001
        print(f"error: could not read scan JSON: {exc}", file=sys.stderr)
        return 1

    # discovery mode
    if "cidr" in d:
        if d.get("error"):
            print(f"discovery error: {d['error']}")
            return 1
        reachable = d.get("hosts_reachable")
        silent = d.get("hosts_silent")
        probes = d.get("tcp_probes") or {}
        print(f"subnet {d.get('cidr')} ports {d.get('ports')}: "
              f"{d.get('open_count')} open of {d.get('candidates')} candidates "
              f"({d.get('hosts_checked')} hosts)")
        if reachable is not None:
            print(f"    hosts     : {reachable} answered (open/closed), {silent} silent/filtered")
            print(f"    TCP probes: open={probes.get('open', 0)} "
                  f"closed={probes.get('closed', 0)} "
                  f"filtered/timeout={probes.get('filtered_timeout', 0)}")
        for ep in d.get("endpoints") or []:
            print(f"  open: {ep}")
        if not d.get("endpoints"):
            if reachable is not None and reachable > 0:
                print("  hosts ARE reachable but none listen on these ports — "
                      "widen --ports or the services use plain HTTP / other ports")
            else:
                print("  NO hosts answered a single TCP probe — likely Wi-Fi "
                      "AP/client isolation, a drop-all firewall, or wrong subnet.")
                print("  check: is your gateway reachable? try the IP from 'ip route | grep default'")
        return 0

    findings = d.get("findings") or []
    tel = d.get("probe_telemetry") or {}
    for f in findings:
        report(f)
        print()
    if tel:
        print(
            f"telemetry: {tel.get('status')} ok={tel.get('ok', 0)}/{tel.get('probed', 0)} "
            f"weak_tls={tel.get('weak_tls_versions', 0)} weak_ciphers={tel.get('weak_cipher_suites', 0)} "
            f"insecure_reneg={tel.get('insecure_renegotiation', 0)} revoked={tel.get('revoked_certificates', 0)}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
