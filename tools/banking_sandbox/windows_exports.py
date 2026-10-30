#!/usr/bin/env python3
"""Windows host exports for the bank sandbox — the input a Windows collector needs.

The Windows collector in CryptoScan does not run on Windows. It reads what a
Windows host already produced, in the formats Windows actually writes them:

* ``reg export "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL"``
  (a ``.reg`` text file),
* ``Get-TlsCipherSuite | ConvertTo-Json``,
* ``Get-ChildItem Cert:\\LocalMachine\\My | ConvertTo-Json``.

Without a Windows machine in the lab there was nothing to point the collector at,
so the ``windows`` maturity gap could not be exercised end to end. This module
writes a synthetic, clearly-labelled bundle in those three formats, derived from
the bank's own declared assets and certificates, so the collector parses real
format shapes and reports **configuration** — never an observation.

Everything produced here is synthetic: the host name, the thumbprints and the
policy values are lab values. The collector's own labels (``CONFIGURED``,
``ARTEFACT_EXPORT``) are what keep that honest in the console.

Usage::

    python -m tools.banking_sandbox.windows_exports --estate ~/.cache/bank-lab \\
        --out ~/.cache/bank-lab/public/windows/BANK-WIN-01
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

HOST = "BANK-WIN-01"
SCHEMA = "cryptoscan.bank-windows-exports/1"

#: what a bank's Windows server tier is configured with. Lab values, stated once.
POLICY: tuple[dict[str, Any], ...] = (
    {"protocol": "SSL 2.0", "enabled": False, "disabled_by_default": True},
    {"protocol": "SSL 3.0", "enabled": False, "disabled_by_default": True},
    {"protocol": "TLS 1.0", "enabled": False, "disabled_by_default": True},
    {"protocol": "TLS 1.1", "enabled": False, "disabled_by_default": True},
    {"protocol": "TLS 1.2", "enabled": True, "disabled_by_default": False},
    {"protocol": "TLS 1.3", "enabled": True, "disabled_by_default": False},
)

#: suite names Windows lists, kept to the ones a bank server tier enables
SUITES: tuple[str, ...] = (
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_CBC_SHA256",
)

SYNTHETIC_MARKER = "SYNTHETIC-BANK-LAB"


def _rows(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _thumbprint(seed: str) -> str:
    return hashlib.sha1(seed.encode("utf-8")).hexdigest().upper()


def schannel_registry() -> str:
    """A ``reg export`` shaped file: version header, blank line, then key blocks."""
    lines = ["Windows Registry Editor Version 5.00", "", f"; {SYNTHETIC_MARKER}: lab host, not a real machine", ""]
    for row in POLICY:
        protocol = row["protocol"]
        for scope, suffix in (("global", ""), ("client", "\\Client"), ("server", "\\Server")):
            key = (
                "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders"
                f"\\SCHANNEL\\Protocols\\{protocol}{suffix}"
            )
            lines.append(f"[{key}]")
            lines.append(f'"DisabledByDefault"=dword:{int(row["disabled_by_default"]):08x}')
            lines.append(f'"Enabled"=dword:{int(row["enabled"]):08x}')
            lines.append("")
    return "\n".join(lines)


def cipher_suites() -> str:
    """``Get-TlsCipherSuite | ConvertTo-Json`` output."""
    payload = [
        {
            "Name": suite,
            "Protocol": "TLS 1.3" if suite.startswith("TLS_AES") else "TLS 1.2",
            "Cipher": suite,
            "KeyType": 0,
            "Certificate": None,
        }
        for suite in SUITES
    ]
    return json.dumps(payload, indent=2)


def machine_certificates(certificates: Iterable[dict[str, Any]]) -> str:
    """``Get-ChildItem Cert:\\LocalMachine\\My | ConvertTo-Json`` output."""
    payload = []
    for index, cert in enumerate(certificates):
        cert_id = str(cert.get("certificate_id") or f"cert-{index}")
        payload.append({
            "Subject": f"CN={cert.get('app_id') or cert_id}, O={SYNTHETIC_MARKER}",
            "Issuer": f"CN={cert.get('issuer_ref') or 'BANK-LAB-ISSUING-CA'}, O={SYNTHETIC_MARKER}",
            "Thumbprint": _thumbprint(cert_id),
            "NotBefore": f"/Date({int(_epoch(cert.get('not_before')) * 1000)})/",
            "NotAfter": f"/Date({int(_epoch(cert.get('not_after')) * 1000)})/",
            "HasPrivateKey": bool(cert.get("private_key_persisted")),
            "PublicKeyAlgorithm": str(cert.get("public_key_algorithm") or "RSA"),
            "SignatureAlgorithm": (
                "sha256RSA" if "RSA" in str(cert.get("public_key_algorithm") or "RSA") else "sha256ECDSA"
            ),
            "DnsNameList": [str(cert.get("endpoint_id") or cert_id)],
        })
    return json.dumps(payload, indent=2)


def _epoch(value: Any) -> float:
    from datetime import datetime

    text = str(value or "").replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return 1798761600.0  # 2027-01-01, a stated fallback for a synthetic lab value


def build_exports(estate: Path, out: Path, host: str = HOST) -> dict[str, Any]:
    """Write the three export files and describe what was written and why."""
    public = Path(estate) / "public"
    bank = (public / "banks").glob("*.json")
    bank_id = next((path.stem for path in bank), "bank-0001")
    certificates = _rows(public / "certificates" / f"{bank_id}.jsonl")[:12]
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)

    written = {
        "SCHANNEL.reg": schannel_registry(),
        "tls-cipher-suites.json": cipher_suites(),
        "machine-certificates.json": machine_certificates(certificates),
    }
    for name, text in written.items():
        (out / name).write_text(text + ("" if text.endswith("\n") else "\n"), encoding="utf-8")

    return {
        "schema": SCHEMA,
        "synthetic": True,
        "host": host,
        "bank_id": bank_id,
        "directory": str(out),
        "files": sorted(written),
        "policy_protocols": [row["protocol"] for row in POLICY],
        "cipher_suites": len(SUITES),
        "certificates": len(certificates),
        "establishes": "CONFIGURATION",
        "note": (
            "these files have the shape Windows writes; the values inside them are lab values. "
            "The collector labels every fact CONFIGURED, so nothing here can be read as a "
            "negotiated or executed cryptographic operation"
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--estate", type=Path, required=True, help="generated bank estate root")
    parser.add_argument("--out", type=Path, required=True, help="directory to write the exports into")
    parser.add_argument("--host", default=HOST, help="host name to put on the exports")
    args = parser.parse_args(argv)

    summary = build_exports(args.estate, args.out, host=args.host)
    print(json.dumps(summary, indent=2))
    print(
        "\nNow hand them to the collector:\n"
        f"  POST /api/v1/estate/evidence/collect  collectors=[\"windows\"]  artifacts={summary['directory']}/*",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
