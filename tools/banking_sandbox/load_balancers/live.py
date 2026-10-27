"""Fixed TLS termination/re-encryption/passthrough witness in a NIC-less network namespace.

No configurable target, production credentials, payload inspection or plaintext proxying.
Private keys exist only on a bounded tmpfs inside a private mount namespace.
"""

import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import importlib
import json
import os
from pathlib import Path
import queue
import resource
import select
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[3]


def namespaces():
    return {k: os.stat("/proc/self/ns/" + k).st_ino for k in ("net", "mnt", "user")}


def seal_reads(work):
    """Landlock read-only allowlist, excluding control/oracle, host home and harness source."""
    import ctypes, struct

    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0):
        raise OSError("NoNewPrivs failed")
    abi = libc.syscall(444, 0, 0, 1)
    if abi < 2:
        raise RuntimeError("Landlock ABI >=2 required")
    attr = ctypes.create_string_buffer(struct.pack("Q", (1 << 14) - 1))
    rules = libc.syscall(444, attr, 8, 0)
    if rules < 0:
        raise OSError("Landlock ruleset")
    try:
        for path in [
            work,
            ROOT / ".venv",
            ROOT / "services/network_scanner/network_scanner",
            Path("/usr"),
            Path("/lib"),
            Path("/lib64"),
            Path("/dev/null"),
        ]:
            if not path.exists():
                continue
            p = path.resolve()
            fd = os.open(p, os.O_PATH | os.O_CLOEXEC)
            try:
                rule = ctypes.create_string_buffer(struct.pack("Qi", 1 | 4 | (8 if p.is_dir() else 0), fd))
                if libc.syscall(445, rules, 1, rule, 0):
                    raise OSError("Landlock path")
            finally:
                os.close(fd)
        if libc.syscall(446, rules, 0):
            raise OSError("Landlock restriction")
    finally:
        os.close(rules)
    return abi


def child(work, parent, sentinel):
    if any(namespaces()[k] == parent[k] for k in ("net", "mnt", "user")):
        raise RuntimeError("namespace isolation required")
    subprocess.run(["/usr/bin/mount", "--make-rprivate", "/"], check=True, capture_output=True)
    subprocess.run(
        ["/usr/bin/mount", "-t", "tmpfs", "-o", "size=8m,nodev,nosuid,noexec,mode=0700", "tmpfs", str(work)],
        check=True,
        capture_output=True,
    )
    subprocess.run(["/usr/bin/ip", "link", "set", "lo", "up"], check=True, capture_output=True)
    links = json.loads(subprocess.check_output(["/usr/bin/ip", "-j", "link"]))
    if [r["ifname"] for r in links] != ["lo"]:
        raise RuntimeError("external interface present")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import NameOID

    ca = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SYNTHETIC LB LIVE CA")])
    material = {}
    for label, key in [
        ("frontend", ec.generate_private_key(ec.SECP256R1())),
        ("backend", rsa.generate_private_key(public_exponent=65537, key_size=2048)),
    ]:
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, label + ".lab.invalid")]))
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(label + ".lab.invalid")]), False)
            .sign(ca, hashes.SHA256())
        )
        cp = work / (label + ".pem")
        kp = work / (label + ".key")
        cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        kp.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
        )
        kp.chmod(0o600)
        material[label] = (cp, kp, cert)

    def context(label, version):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ctx.maximum_version = version
        ctx.load_cert_chain(str(material[label][0]), str(material[label][1]))
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        if version == ssl.TLSVersion.TLSv1_2:
            ctx.set_ciphers("ECDHE-RSA-AES128-GCM-SHA256")
        return ctx

    front = context("frontend", ssl.TLSVersion.TLSv1_3)
    back = context("backend", ssl.TLSVersion.TLSv1_2)
    back13 = context("backend", ssl.TLSVersion.TLSv1_3)
    sys.path.insert(0, str(ROOT / "services/network_scanner"))
    from network_scanner.probing.tls_handshaker import handshake

    # Force optional modules needed by the unchanged parser into memory before confinement.
    importlib.import_module("network_scanner.certificates.cert_parser")
    abi = seal_reads(work)
    try:
        sentinel.read_bytes()
    except PermissionError:
        oracle_denied = True
    else:
        raise RuntimeError("oracle path readable")
    resource.setrlimit(resource.RLIMIT_AS, (768 * 1024**2, 768 * 1024**2))
    resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    events = queue.Queue()
    threads = []
    listeners = []

    def listen():
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", 0))
        s.listen(4)
        s.settimeout(5)
        listeners.append(s)
        return s

    def serve(ctx, upstream=None):
        s = listen()

        def worker():
            try:
                raw, _ = s.accept()
                raw.settimeout(4)
                with ctx.wrap_socket(raw, server_side=True) as tls:
                    events.put({"kind": "server-handshake", "version": tls.version(), "cipher": tls.cipher()[0]})
                    if upstream:
                        with socket.create_connection(("127.0.0.1", upstream), timeout=3) as sock:
                            source_address = sock.getsockname()
                            result = handshake(sock, "backend.lab.invalid", timeout=3)
                            events.put(observation(result, "reencryption-internal", "backend", source_address))
                            result["socket"].close()
            except Exception as e:
                events.put({"kind": "server-error", "error": type(e).__name__})
            finally:
                s.close()

        t = threading.Thread(target=worker, daemon=True)
        threads.append(t)
        t.start()
        return s.getsockname()[1]

    def observation(result, hop, termination, source):
        der = result.get("der")
        cert = x509.load_der_x509_certificate(der)
        key = cert.public_key()
        return {
            "evidence_id": "lb-live-" + hop,
            "collector": "network_scanner.probing.tls_handshaker.handshake",
            "evidence_type": "NETWORK_OBSERVED",
            "hop_id": hop,
            "crypto_asset_id": hop + "-crypto",
            "status": "COMPLETE",
            "source": list(source),
            "destination": list(result["socket"].getpeername()),
            "protocol": "TLS",
            "version": result["version"],
            "cipher": result["cipher"][0],
            "key_exchange": "ECDHE" if result["cipher"][0].startswith("ECDHE-") else None,
            "key_exchange_group": None,
            "certificate_fingerprint_sha256": hashlib.sha256(der).hexdigest(),
            "certificate_der_base64": base64.b64encode(der).decode(),
            "certificate_public_key_spki_base64": base64.b64encode(
                key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            ).decode(),
            "certificate_chain_observation": "LEAF_ONLY_FULL_CHAIN_NOT_EXPOSED",
            "certificate_public_key_algorithm": "RSA" if isinstance(key, rsa.RSAPublicKey) else "EC",
            "certificate_key_size": key.key_size,
            "certificate_curve": getattr(getattr(key, "curve", None), "name", None),
            "certificate_signature_algorithm": cert.signature_algorithm_oid.dotted_string,
            "handshake_signature_algorithm": None,
            "sni": result["hostname"],
            "sni_source": "CLIENT_REQUEST_PARAMETER_NOT_SERVER_CAPTURE",
            "alpn": result["socket"].selected_alpn_protocol(),
            "mtls_state": "UNKNOWN",
            "peer_authentication_verified": False,
            "termination_point": termination,
            "termination_attribution_source": "CONTROLLED_LAB_TOPOLOGY_NOT_INFERRED_FROM_CERTIFICATE",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actual_handshake": True,
        }

    def probe(port, hop, termination):
        sock = socket.create_connection(("127.0.0.1", port), timeout=3)
        source = sock.getsockname()
        result = handshake(
            sock, "frontend.lab.invalid" if termination == "load-balancer" else "backend.lab.invalid", timeout=3
        )
        try:
            return observation(result, hop, termination, source)
        finally:
            result["socket"].close()

    results = []
    results.append(probe(serve(front), "termination-external", "load-balancer"))
    backend_port = serve(back)
    results.append(probe(serve(front, backend_port), "reencryption-external", "load-balancer"))
    # TCP pass-through forwards opaque TLS records; no application data is sent or inspected.
    backend_port = serve(back13)
    proxy = listen()
    proxy_port = proxy.getsockname()[1]

    def forward():
        try:
            incoming, _ = proxy.accept()
            incoming.settimeout(3)
            with incoming, socket.create_connection(("127.0.0.1", backend_port), timeout=3) as outgoing:
                deadline = time.monotonic() + 4
                while time.monotonic() < deadline:
                    readable, _, _ = select.select([incoming, outgoing], [], [], 0.2)
                    for source in readable:
                        raw = source.recv(65536)
                        if not raw:
                            return
                        (outgoing if source is incoming else incoming).sendall(raw)
        except (OSError, ssl.SSLError):
            pass
        finally:
            proxy.close()

    t = threading.Thread(target=forward, daemon=True)
    threads.append(t)
    t.start()
    results.append(probe(proxy_port, "passthrough-end-to-end", "backend"))
    # Real certificate/version/cipher drift witness, separate from configured-only estate drift.
    results.append(probe(serve(back), "drift-external", "load-balancer"))
    for t in threads:
        t.join(timeout=5)
    if any(t.is_alive() for t in threads):
        raise RuntimeError("live worker did not stop")
    captured = []
    while not events.empty():
        captured.append(events.get_nowait())
    errors = [e for e in captured if e.get("kind") == "server-error"]
    if errors:
        raise RuntimeError("server errors: " + str(errors))
    results += [e for e in captured if e.get("hop_id")]
    by = {r["hop_id"]: r for r in results}
    if (
        by["passthrough-end-to-end"]["certificate_fingerprint_sha256"]
        != material["backend"][2].fingerprint(hashes.SHA256()).hex()
    ):
        raise RuntimeError("passthrough certificate attribution")
    if by["reencryption-external"]["version"] != "TLSv1.3" or by["reencryption-internal"]["version"] != "TLSv1.2":
        raise RuntimeError("reencryption versions")
    if (
        by["reencryption-external"]["certificate_fingerprint_sha256"]
        == by["reencryption-internal"]["certificate_fingerprint_sha256"]
    ):
        raise RuntimeError("hops share certificates")
    return {
        "verdict": "MEASURED_ISOLATED_LB_SAMPLE",
        "network": results,
        "network_namespace": namespaces(),
        "interfaces": [r["ifname"] for r in links],
        "landlock_abi": abi,
        "oracle_path_read_denied": oracle_denied,
        "private_key_storage": "8MiB_PRIVATE_TMPFS_DESTROYED_WITH_MOUNT_NAMESPACE",
        "private_keys_exported": False,
        "payload_inspected": False,
        "application_data_sent": False,
        "production_qualified": False,
        "unexecuted": [
            "mTLS positive paths",
            "HSM signing",
            "PQC",
            "legacy TLS",
            "normal runtime agent",
            "full estate discovery",
        ],
        "limitations": "Termination ownership comes from controlled topology; core handshaker does not independently classify LB architecture. TLS1.3 group and mTLS state remain UNKNOWN.",
    }


def run(output):
    """Fail closed; never substitute a host listener when namespaces/mounts are unavailable."""
    from tools.banking_sandbox.common import dump, file_hash

    output = Path(output)
    if output.exists():
        raise ValueError("fresh output required")
    output.mkdir(parents=True, mode=0o700)
    before = namespaces()
    start = time.monotonic()
    failure = None
    receipt = None
    with tempfile.TemporaryDirectory(prefix="SYNTHETIC-LB-MOUNT-") as tmp:
        work = Path(tmp) / "work"
        work.mkdir()
        sentinel = Path(tmp) / "ORACLE-SENTINEL.txt"
        sentinel.write_text("BOUNDARY PROOF ONLY; NO EXPECTED RESULTS")
        command = [
            "/usr/bin/unshare",
            "--user",
            "--map-root-user",
            "--mount",
            "--net",
            "--fork",
            sys.executable,
            "-I",
            str(Path(__file__).resolve()),
            "--child-work",
            str(work),
            "--outside-sentinel",
            str(sentinel),
            "--parent",
            json.dumps(before),
        ]
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
            env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "PYTHONDONTWRITEBYTECODE": "1"},
        )
        try:
            out, err = process.communicate(timeout=40)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            out, err = process.communicate()
            failure = "TIMEOUT"
        if not failure:
            if process.returncode:
                failure = "CHILD_FAILED"
            else:
                try:
                    receipt = json.loads(out)
                except ValueError:
                    failure = "INVALID_RECEIPT"
        (output / "child.log").write_bytes(err[:65536])
    after = namespaces()
    if after != before:
        failure = "PARENT_NAMESPACE_CHANGED"
    result = {
        "failure": failure,
        "receipt": receipt,
        "wall_seconds": time.monotonic() - start,
        "parent_before": before,
        "parent_after": after,
        "synthetic": True,
        "production_qualified": False,
        "collector_source_sha256": file_hash(
            ROOT / "services/network_scanner/network_scanner/probing/tls_handshaker.py"
        ),
        "certificate_parser_source_sha256": file_hash(
            ROOT / "services/network_scanner/network_scanner/certificates/cert_parser.py"
        ),
    }
    dump(output / "result.json", result)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--child-work", type=Path, required=True)
    parser.add_argument("--parent", required=True)
    parser.add_argument("--outside-sentinel", type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(ROOT))
    print(json.dumps(child(args.child_work, json.loads(args.parent), args.outside_sentinel), sort_keys=True))
