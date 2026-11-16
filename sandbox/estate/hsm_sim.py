"""Minimal TLS endpoint posing as a bank service (HSM administration).

Speaks a tiny JSON protocol over TLS so CryptoScan network scanners observe a
real certificate chain, cipher suite and protocol version — the evidence the
product collects in the field. Never expose this to a real network; it is a
sandbox stand-in with throwaway crypto.
"""
from __future__ import annotations

import json
import os
import socket
import ssl

CERT = os.environ.get("TLS_CERT", "/certs/hsm-sim.crt")
KEY = os.environ.get("TLS_KEY", "/certs/hsm-sim.key")
PORT = int(os.environ.get("PORT", "8443"))

INVENTORY = {
    "device": "payShield-10K-sim",
    "firmware": "v3.4.1-sandbox",
    "slots": [
        {"slot": 0, "label": "ZPK-PROD-A", "algorithm": "AES-256", "usage": "PIN block translation"},
        {"slot": 1, "label": "CVK-LEGACY", "algorithm": "3DES-112", "usage": "card verification (RETIRE)"},
        {"slot": 2, "label": "MK-ACQ-1", "algorithm": "AES-256", "usage": "acquirer master key"},
        {"slot": 3, "label": "TPK-TERM-42", "algorithm": "3DES-168", "usage": "terminal PIN key (migrate)"},
    ],
    "compliance": {"fips_mode": False, "pci_pts": "3.x"},
}


def main() -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", PORT))
    sock.listen(16)
    print(f"hsm-sim listening on :{PORT} tls", flush=True)
    while True:
        conn, addr = sock.accept()
        try:
            tls = ctx.wrap_socket(conn, server_side=True)
            banner = json.dumps({"service": "hsm-sim", "inventory": INVENTORY}).encode() + b"\n"
            tls.sendall(banner)
            tls.close()
        except ssl.SSLError as exc:
            print(f"tls error from {addr}: {exc}", flush=True)
        except Exception as exc:  # noqa: BLE001 - sandbox service, log and continue
            print(f"conn error from {addr}: {exc}", flush=True)


if __name__ == "__main__":
    main()
