#!/usr/bin/env python3
"""Read a `runtime.main processes` JSON payload from stdin and print a
human-readable crypto audit. Used by scan-laptop.sh; stdlib only."""

from __future__ import annotations

import json
import sys


def main() -> int:
    try:
        d = json.load(sys.stdin)
    except (ValueError, OSError) as exc:  # noqa: BLE001
        print(f"error: could not read scan JSON: {exc}", file=sys.stderr)
        return 1

    procs = d.get("processes", [])
    findings = d.get("findings", [])
    tls_procs = [p for p in procs if p.get("tls_libraries") or p.get("listening_ports")]

    print(f"host: {d.get('host', '?')}")
    kskip = d.get("kernel_threads_skipped") or 0
    scanned = d.get("total_processes_scanned", d.get("process_count"))
    print(
        f"crypto-relevant processes: {d.get('process_count')} (of {scanned} user processes scanned"
        + (f", {kskip} kernel threads skipped" if kskip else "") + ")"
        f"  |  TLS/crypto libs in: {d.get('processes_with_tls_libraries')}"
        f"  |  listening: {d.get('listening_processes')}"
    )
    print()

    # 1. confirmed risks -------------------------------------------------- #
    print(f"CONFIRMED RISKS (version verified via dpkg/rpm): {len(findings)}")
    if not findings:
        print("  none - no EOL/weak TLS library with a resolvable package version.")
    for f in findings:
        ports = f.get("listening_ports") or []
        print(
            f"  [{f.get('status','?'):11}] {f.get('library_name','')} ver={f.get('version')} "
            f"pkg={f.get('package') or 'unmanaged'}  process={f.get('process_name')} "
            f"pid={f.get('pid')} ports={ports or '-'}"
        )
        if f.get("notes"):
            print(f"               {f['notes']}")
    print()

    # 2. library inventory (every resolved verdict) ----------------------- #
    print("LIBRARY INVENTORY (unique library@version / verdict / package):")
    seen: set = set()
    rows = []
    for p in tls_procs:
        for lib in p.get("library_details", []):
            key = (lib.get("library"), lib.get("version"), lib.get("status"), lib.get("package"))
            if key in seen:
                continue
            seen.add(key)
            rows.append(lib)

    order = {"DISALLOWED": 0, "DEPRECATED": 1, "RESTRICTED": 2, "UNKNOWN": 3, "ALLOWED": 4}
    rows.sort(key=lambda l: order.get(l.get("status"), 9))
    for lib in rows:
        ver = lib.get("version") or "?"
        pkg = lib.get("package") or "unmanaged/bundled"
        src = lib.get("version_source") or "?"
        print(f"  {lib.get('status','?'):11} {lib.get('library','?'):9} {ver:9} via {pkg} ({src})")

    unknown = [l for l in rows if l.get("status") == "UNKNOWN"]
    if unknown:
        print()
        print(f"NOTE: {len(unknown)} library(ies) could not be versioned by the package manager")
        print("      (venv/pyenv/static builds or bundled browser copies) - check by hand:")
        for l in unknown:
            print(f"        - {l.get('library')}: {l.get('notes')}")
    print()

    # 3. listening endpoints ---------------------------------------------- #
    print("LISTENING TCP PORTS (potential TLS endpoints):")
    listeners = [p for p in tls_procs if p.get("listening_ports")]
    if not listeners:
        print("  none detected")
    for p in sorted(listeners, key=lambda x: x["pid"]):
        print(
            f"  pid={p['pid']:<7} {p['process_name']:18} ports={p['listening_ports']} "
            f"libs={','.join(p.get('tls_libraries') or []) or '-'}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
