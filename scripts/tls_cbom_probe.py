#!/usr/bin/env python
"""Live TLS handshake → CycloneDX NBOM probe (round 53).

The bank-sandbox execution pattern, implemented for real:

1. point at one or more ``host:port`` TLS endpoints,
2. perform the handshake and capture the negotiated TLS version, the
   cipher suite, the certificate chain and (optionally) the supported
   version floor / weak-cipher surface,
3. map every probe to an NBOM endpoint and assemble the CycloneDX 1.5
   Network BOM with its dependency graph, and
4. write the JSON document (``--out`` or stdout).

Honesty rules, same as the scanners:

* an endpoint that cannot be reached is reported as such and lands in the
  BOM with ``observed: false`` — never fabricated, never silently
  dropped;
* ``--self-test`` runs the entire flow against LOCAL mock-bank TLS
  servers (``network_scanner.probing.mock_bank_tls``) — self-signed
  certificates, pinned versions and cipher lists, zero keys, zero
  network — so the pipeline can be verified deterministically;
* this script proves the tool path, not field coverage of any real bank:
  the bank sandboxes (Plaid, Open Bank Project, QNB, Emirates NBD,
  Neotek, …) need their own registrations, credentials and network
  access, and remain operator-side qualification.

Usage::

    PYTHONPATH=services/network_scanner:services/cbom:... python \\
        scripts/tls_cbom_probe.py api.github.com:443 --out nbom.json
    python scripts/tls_cbom_probe.py --self-test
"""

from __future__ import annotations

import argparse
import json
import sys


def _probe(endpoint: str, *, scan_ciphers: bool, scan_versions: bool) -> dict:
    from network_scanner.probing.active_prober import probe_endpoint

    return probe_endpoint(
        endpoint,
        timeout=10.0,
        scan_ciphers=scan_ciphers,
        scan_versions=scan_versions,
    )


def run(endpoints: list[str], *, estate: str, scan_ciphers: bool, scan_versions: bool) -> dict:
    """Probe every endpoint and assemble the NBOM document."""
    from cbom.nbom import build_nbom, probe_to_endpoint

    probes = [_probe(ep, scan_ciphers=scan_ciphers, scan_versions=scan_versions) for ep in endpoints]
    mapped = [probe_to_endpoint(p) for p in probes]
    mapped = [m for m in mapped if m]  # probes without an endpoint string are skipped, not invented
    document = build_nbom(mapped, estate=estate)
    return {"probes": probes, "nbom": document}


def _summary(result: dict) -> str:
    from cbom.nbom import summarise

    lines = []
    for probe in result["probes"]:
        status = probe.get("status")
        line = f"  {probe.get('endpoint')}: {status}"
        if status == "OK":
            crypto = probe.get("crypto") or {}  # the raw prober nests facts here
            line += (f" · {crypto.get('tls_version')} · {crypto.get('cipher_suite')}"
                     f" · alpn={crypto.get('alpn')}")
            certs = probe.get("certificates") or []
            if certs:
                leaf = certs[0]
                line += (f" · cert {leaf.get('public_key_algorithm')}"
                         f"-{leaf.get('public_key_size')}"
                         f"{' (self-signed)' if leaf.get('is_self_signed') else ''}")
        elif probe.get("error"):
            line += f" · {probe['error']}"
        lines.append(line)
    summary = summarise(result["nbom"])
    lines.append(f"  NBOM: {summary.get('components', '?')} components, "
                 f"{summary.get('findings', '?')} findings "
                 f"(specVersion {result['nbom'].get('specVersion')})")
    return "\n".join(lines)


def _self_test() -> dict:
    """End-to-end against local mock banks — deterministic, zero network."""
    from network_scanner.probing.mock_bank_tls import MockBankTLS

    results = []
    with MockBankTLS(min_tls_version="1.2", max_tls_version="1.2",
                     ciphers="ECDHE-RSA-AES128-GCM-SHA256",
                     common_name="mock-bank-emirates.local") as bank12:
        results.append(run([bank12.endpoint], estate="self-test-mock-banks",
                           scan_ciphers=False, scan_versions=False))
    with MockBankTLS(min_tls_version="1.3", max_tls_version="1.3",
                     common_name="mock-bank-qnb.local") as bank13:
        results.append(run([bank13.endpoint], estate="self-test-mock-banks",
                           scan_ciphers=False, scan_versions=False))
    # one document per bank; return both, caller prints/uses the first
    for result in results:
        ok = all(p.get("status") == "OK" for p in result["probes"])
        if not ok:
            return result
    return results[0]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Live TLS handshake → CycloneDX NBOM probe")
    parser.add_argument("endpoints", nargs="*", help="host:port TLS endpoints to probe")
    parser.add_argument("--self-test", action="store_true",
                        help="probe LOCAL mock-bank TLS servers (no network, no keys)")
    parser.add_argument("--estate", default="live-probe", help="estate name in the BOM metadata")
    parser.add_argument("--out", help="write the CycloneDX JSON here (default: stdout)")
    parser.add_argument("--scan-ciphers", action="store_true", help="also probe weak-cipher surface")
    parser.add_argument("--scan-versions", action="store_true", help="also probe version floor")
    args = parser.parse_args(argv)

    if args.self_test:
        result = _self_test()
    elif args.endpoints:
        result = run(args.endpoints, estate=args.estate,
                     scan_ciphers=args.scan_ciphers, scan_versions=args.scan_versions)
    else:
        parser.error("give endpoints or --self-test")

    print(_summary(result), file=sys.stderr)
    document = json.dumps(result["nbom"], indent=2)
    if args.out:
        with open(args.out, "w") as fh:
            fh.write(document + "\n")
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        print(document)
    failed = [p for p in result["probes"] if p.get("status") != "OK"]
    return 1 if (args.self_test and failed) else 0


if __name__ == "__main__":
    raise SystemExit(main())
