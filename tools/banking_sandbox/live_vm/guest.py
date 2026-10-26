"""Actual bounded TLS/runtime sample in an externally NIC-less VM, not 150 live banks."""

import ctypes
import hashlib
import hmac
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import threading
import time

sys.path.insert(0, "/")


def command(args):
    p = subprocess.run(args, capture_output=True, timeout=12)
    if p.returncode:
        raise ValueError("guest command failed: " + p.stderr.decode(errors="replace")[:1000])
    return p.stdout


def main():
    args = Path("/proc/cmdline").read_text().split()
    nonce = [x.split("=", 1)[1] for x in args if x.startswith("cryptoscan_tbf_nonce=")]
    if os.geteuid() != 0 or os.getppid() != 1 or len(nonce) != 1 or not Path("/DISPOSABLE_TBF_VM").exists():
        raise ValueError("guest only")
    links = json.loads(command(["/sbin/ip", "-j", "link", "show"]))
    if [x["ifname"] for x in links] != ["lo"]:
        raise ValueError("no NIC allowed")
    command(["/sbin/ip", "link", "set", "lo", "up"])
    # Disposable RANDOM test key: created only in the VM ramfs and destroyed with
    # the VM. No host credentials/keys are supplied. Actual wall time is recorded.
    Path("/tmp/LAB.cnf").write_text("[req]\ndistinguished_name=dn\n[dn]\n")
    command(
        [
            "/bin/openssl",
            "req",
            "-config",
            "/tmp/LAB.cnf",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "/tmp/LAB.key",
            "-out",
            "/tmp/LAB.crt",
            "-subj",
            "/O=SYNTHETIC LAB ONLY/CN=bank-0001.lab.invalid",
            "-days",
            "1",
        ]
    )
    from network_scanner.probing.tls_handshaker import handshake

    rows = []
    for version, port in [(ssl.TLSVersion.TLSv1_2, 24443), (ssl.TLSVersion.TLSv1_3, 24444)]:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = context.maximum_version = version
        context.load_cert_chain("/tmp/LAB.crt", "/tmp/LAB.key")
        ready = threading.Event()
        errors = []

        def server():
            try:
                with socket.socket() as listener:
                    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    listener.bind(("127.0.0.1", port))
                    listener.listen(1)
                    listener.settimeout(4)
                    ready.set()
                    with listener.accept()[0] as raw:
                        with context.wrap_socket(raw, server_side=True) as tls:
                            tls.send(b"SYNTHETIC LAB")
            except Exception as exc:
                errors.append(type(exc).__name__)
                ready.set()

        t = threading.Thread(target=server)
        t.start()
        if not ready.wait(3):
            raise ValueError("TLS listener failed")
        with socket.create_connection(("127.0.0.1", port), timeout=4) as sock:
            result = handshake(sock, "bank-0001.lab.invalid", timeout=4)
            rows.append(
                {
                    "protocol": result["version"],
                    "cipher": list(result["cipher"]),
                    "certificate_sha256": hashlib.sha256(result["der"]).hexdigest(),
                    "collector": "UNMODIFIED_CRYPTOSCAN_TLS_HANDSHAKER",
                    "evidence_type": "NETWORK_OBSERVED",
                    "provenance": "SYNTHETIC_LIVE_VM",
                    "actual_handshake": True,
                    "peer_authentication_verified": False,
                    "timestamp_ns": time.time_ns(),
                }
            )
            result["socket"].close()
        t.join(timeout=5)
        if t.is_alive() or errors:
            raise ValueError("server did not finish: " + repr(errors))
    # Actual stdlib/OpenSSL crypto use; no claim that JVM/.NET/Go/Rust/PQC ran.
    data = b"SYNTHETIC PAYMENT"
    key = b"PUBLIC LAB HMAC TEST KEY"
    runtime = {
        "sha256": hashlib.sha256(data).hexdigest(),
        "hmac_sha256": hmac.new(key, data, hashlib.sha256).hexdigest(),
        "openssl_version": ssl.OPENSSL_VERSION,
        "loaded_crypto_module": str(ctypes.CDLL("libcrypto.so.3")._name),
        "evidence_type": "RUNTIME_OBSERVED",
        "actual_execution": True,
        "provenance": "SYNTHETIC_LIVE_VM",
    }
    failures = []
    try:
        socket.create_connection(("127.0.0.1", 24445), timeout=0.5)
    except ConnectionRefusedError:
        failures.append(
            {"case": "unavailable-service", "status": "FAILED", "crypto_absent": None, "actual_injection": True}
        )
    # Strict trust checking must reject this self-signed disposable certificate.
    # The production discovery handshaker above intentionally does not authenticate peers.
    unsupported = {
        "TLS1.0_TLS1.1": "CONFIG_FIXTURES_ONLY",
        "SSH_IPsec_IKE": "CONFIG_FIXTURES_ONLY",
        "mTLS": "CONFIG_FIXTURES_ONLY",
        "HSM_KMS": "METADATA_FIXTURES_NOT_REAL_HSM",
        "JVM_DOTNET_GO_RUST_RUNTIME": "NOT_EXECUTED",
        "ML_KEM_ML_DSA_SLH_DSA": "NOT_EXECUTED_CONFIG_FIXTURES_ONLY",
    }
    print(
        "CRYPTOSCAN_BANK_LIVE="
        + json.dumps(
            {
                "nonce": nonce[0],
                "label": "SYNTHETIC LAB",
                "network": rows,
                "runtime": runtime,
                "failures": failures,
                "unsupported": unsupported,
                "finished_ns": time.monotonic_ns(),
                "production_qualified": False,
            },
            sort_keys=True,
        ),
        flush=True,
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("CRYPTOSCAN_BANK_LIVE_FAILED=" + type(exc).__name__ + ":" + str(exc), flush=True)
        raise
