"""SSH KEXINIT algorithm-offer probing: parse, grade, live sshd checks."""

from __future__ import annotations

import os
import socket
import struct
import subprocess
import time

import pytest

from network_scanner.probing.ssh_kex import (
    SSH_MSG_KEXINIT,
    analyze_ssh_kex_offer,
    is_marker,
    parse_kexinit_packet,
    probe_ssh_kex_offer,
)
from network_scanner.probing.ssh_keyscan import ssh_probe_telemetry

SSHD_BIN = "/usr/sbin/sshd"
LIVE_SUPPORTED = os.path.exists(SSHD_BIN)


def build_kexinit(lists: list[str]) -> bytes:
    """Build a minimal KEXINIT body (msg byte + cookie + 10 name-lists + tail)."""
    body = bytes([SSH_MSG_KEXINIT]) + b"\x00" * 16
    for name_list in lists:
        raw = name_list.encode()
        body += struct.pack(">I", len(raw)) + raw
    body += b"\x00" + struct.pack(">I", 0)  # first_kex_follows, reserved
    return body


# --------------------------------------------------------------------------- #
# pure: packet parsing
# --------------------------------------------------------------------------- #

def test_parse_kexinit_packet_roundtrip():
    lists = [
        "curve25519-sha256,kex-strict-s-v00@openssh.com",
        "ssh-ed25519",
        "aes128-ctr,chacha20-poly1305@openssh.com",
        "aes128-ctr",
        "hmac-sha2-256-etm@openssh.com",
        "hmac-sha2-256-etm@openssh.com",
        "none",
        "none",
        "",
        "",
    ]
    parsed = parse_kexinit_packet(build_kexinit(lists)[1:])
    assert parsed["kex_algorithms"] == ["curve25519-sha256"]  # marker excluded
    assert parsed["server_host_key_algorithms"] == ["ssh-ed25519"]
    assert parsed["encryption_client_to_server"][0] == "aes128-ctr"
    assert parsed["languages_client_to_server"] == []


def test_parse_kexinit_packet_rejects_garbage():
    assert parse_kexinit_packet(b"") is None
    assert parse_kexinit_packet(b"\x00" * 8) is None
    truncated = build_kexinit(["a,b"] * 10)[1:30]
    assert parse_kexinit_packet(truncated) is None


def test_is_marker():
    assert is_marker("kex-strict-s-v00@openssh.com")
    assert is_marker("ext-info-s")
    assert not is_marker("curve25519-sha256")


# --------------------------------------------------------------------------- #
# pure: offer grading
# --------------------------------------------------------------------------- #

def _offer(ciphers="", macs="", kex="", host_keys="ssh-ed25519"):
    return {
        "kex_algorithms": kex.split(",") if kex else [],
        "server_host_key_algorithms": host_keys.split(",") if host_keys else [],
        "encryption_client_to_server": ciphers.split(",") if ciphers else [],
        "encryption_server_to_client": ciphers.split(",") if ciphers else [],
        "mac_client_to_server": macs.split(",") if macs else [],
        "mac_server_to_client": macs.split(",") if macs else [],
    }


def test_analyze_clean_offer_has_no_issues():
    analysis = analyze_ssh_kex_offer(
        _offer(
            ciphers="chacha20-poly1305@openssh.com,aes256-gcm@openssh.com",
            macs="hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com",
            kex="curve25519-sha256,sntrup761x25519-sha512",
        )
    )
    assert analysis["policy_issues"] == []
    assert analysis["weak_ciphers"] == [] and analysis["weak_macs"] == []


def test_analyze_flags_weak_ciphers_macs_kex():
    analysis = analyze_ssh_kex_offer(
        _offer(
            ciphers="aes128-ctr,arcfour128,3des-cbc,aes128-cbc",
            macs="hmac-sha2-256-etm@openssh.com,hmac-md5,hmac-sha1-96",
            kex="curve25519-sha256,diffie-hellman-group1-sha1",
        )
    )
    assert analysis["weak_ciphers"] == ["arcfour128", "3des-cbc", "aes128-cbc"]
    assert analysis["weak_macs"] == ["hmac-md5", "hmac-sha1-96"]
    assert analysis["weak_kex"] == ["diffie-hellman-group1-sha1"]
    assert "SSH_WEAK_CIPHER_OFFERED" in analysis["policy_issues"]
    assert "SSH_WEAK_MAC_OFFERED" in analysis["policy_issues"]
    assert "SSH_WEAK_KEX_OFFERED" in analysis["policy_issues"]


def test_analyze_legacy_tier_only_flags_when_strict():
    offer = _offer(
        macs="hmac-sha1-etm@openssh.com,umac-64-etm@openssh.com",
        host_keys="rsa-sha2-512,ssh-rsa",
    )
    lenient = analyze_ssh_kex_offer(offer)
    assert lenient["policy_issues"] == []
    assert lenient["legacy_macs"] == ["hmac-sha1-etm@openssh.com", "umac-64-etm@openssh.com"]
    assert lenient["legacy_host_keys"] == ["ssh-rsa"]
    strict = analyze_ssh_kex_offer(offer, strict=True)
    assert strict["policy_issues"] == ["SSH_LEGACY_ALGORITHM_OFFERED"]


def test_analyze_empty_offer():
    assert analyze_ssh_kex_offer(None)["policy_issues"] == []


# --------------------------------------------------------------------------- #
# telemetry integration
# --------------------------------------------------------------------------- #

def test_telemetry_counts_weak_offers():
    rows = [
        {"status": "OK", "policy_issues": ["SSH_WEAK_CIPHER_OFFERED", "SSH_WEAK_MAC_OFFERED"]},
        {"status": "OK", "policy_issues": ["SSH_WEAK_KEX_OFFERED"]},
        {"status": "OK", "policy_issues": []},
    ]
    telemetry = ssh_probe_telemetry(rows)
    # row semantics (like the other counters): hosts with >=1 weak offer
    assert telemetry["ssh_weak_algorithm_offers"] == 2
    assert telemetry["status"] == "PARTIAL"


# --------------------------------------------------------------------------- #
# live sshd
# --------------------------------------------------------------------------- #

class KexSshd:
    """sshd with an explicitly configured (weak) algorithm set."""

    def __init__(self, tmp_path, extra_config=""):
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(tmp_path / "hk")],
            check=True, capture_output=True,
        )
        config = tmp_path / "sshd_config"
        config.write_text(
            f"Port 0\nHostKey {tmp_path}/hk\nUsePAM no\nPasswordAuthentication no\n"
            f"PidFile {tmp_path}/pid\n{extra_config}"
        )
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.close()
        self.proc = subprocess.Popen(
            [SSHD_BIN, "-D", "-e", "-f", str(config), "-p", str(self.port)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.5):
                    return
            except OSError:
                time.sleep(0.1)
        raise AssertionError("sshd did not start")

    def close(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


WEAK_CONFIG = (
    "Ciphers aes128-ctr,aes128-cbc,3des-cbc\n"
    "MACs hmac-sha2-256-etm@openssh.com,hmac-md5,hmac-sha1-96\n"
    "KexAlgorithms curve25519-sha256,diffie-hellman-group1-sha1\n"
)


@pytest.mark.skipif(not LIVE_SUPPORTED, reason="sshd not available")
def test_probe_stock_sshd_defaults(tmp_path):
    server = KexSshd(tmp_path)
    try:
        finding = probe_ssh_kex_offer("127.0.0.1", server.port, timeout=6.0)
        assert finding["status"] == "OK"
        assert finding["server_banner"].startswith("SSH-2.0-OpenSSH")
        assert "curve25519-sha256" in finding["kex_algorithms"]
        assert "aes128-ctr" in finding["ciphers"]
        # stock defaults: no weak ciphers/macs/kex, but legacy hmac-sha1 present
        assert finding["policy_issues"] == []
        assert any("sha1" in name or "umac-64" in name for name in finding["legacy"]["legacy_macs"])
    finally:
        server.close()


@pytest.mark.skipif(not LIVE_SUPPORTED, reason="sshd not available")
def test_probe_weak_sshd_all_three_categories(tmp_path):
    server = KexSshd(tmp_path, WEAK_CONFIG)
    try:
        finding = probe_ssh_kex_offer("127.0.0.1", server.port, timeout=6.0)
        assert finding["status"] == "OK"
        assert finding["weak"]["weak_ciphers"] == ["aes128-cbc", "3des-cbc"]
        assert finding["weak"]["weak_macs"] == ["hmac-md5", "hmac-sha1-96"]
        assert finding["weak"]["weak_kex"] == ["diffie-hellman-group1-sha1"]
        assert set(finding["policy_issues"]) == {
            "SSH_WEAK_CIPHER_OFFERED",
            "SSH_WEAK_MAC_OFFERED",
            "SSH_WEAK_KEX_OFFERED",
        }
    finally:
        server.close()


@pytest.mark.skipif(not LIVE_SUPPORTED, reason="sshd not available")
def test_probe_strict_mode_flags_legacy(tmp_path):
    server = KexSshd(tmp_path)
    try:
        finding = probe_ssh_kex_offer("127.0.0.1", server.port, timeout=6.0, strict=True)
        assert "SSH_LEGACY_ALGORITHM_OFFERED" in finding["policy_issues"]
    finally:
        server.close()


def test_probe_dead_port_is_unreachable():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    finding = probe_ssh_kex_offer("127.0.0.1", port, timeout=3.0)
    assert finding["status"] in {"SSH_UNREACHABLE", "TIMEOUT"}
    assert finding["detail"]


def test_probe_tls_port_is_not_ssh(tmp_path):
    """A TLS port answers with a ServerHello, not an SSH banner."""
    import ssl

    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(tmp_path / "k"), "-out", str(tmp_path / "c"),
         "-days", "2", "-subj", "/CN=localhost"],
        check=True, capture_output=True,
    )
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.listen(1)
    listener.settimeout(10)

    def serve():
        try:
            conn, _ = listener.accept()
        except OSError:
            return
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(str(tmp_path / "c"), str(tmp_path / "k"))
            with ctx.wrap_socket(conn, server_side=True) as tls:
                tls.recv(256)
        except Exception:
            pass

    import threading

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        finding = probe_ssh_kex_offer("127.0.0.1", port, timeout=6.0)
        # a TLS server waits for our ClientHello and never sends a banner ->
        # honest TIMEOUT; a plaintext non-SSH port would be NOT_SSH instead
        assert finding["status"] in {"NOT_SSH", "SSH_UNREACHABLE", "PROBE_ERROR", "TIMEOUT"}
        assert finding["status"] != "OK"
        assert finding["detail"]
    finally:
        listener.close()


# --------------------------------------------------------------------------- #
# scanner integration
# --------------------------------------------------------------------------- #

@pytest.mark.skipif(not LIVE_SUPPORTED, reason="sshd not available")
def test_scanner_merges_kex_issues(tmp_path):
    from network_scanner.core.scanner import NetworkTlsScanner

    server = KexSshd(tmp_path, WEAK_CONFIG)
    try:
        result = NetworkTlsScanner(live=True, timeout=6.0).scan_ssh_hosts(
            [f"127.0.0.1:{server.port}"], include_kex=True
        )
        finding = result["findings"][0]
        assert finding["kex_offer"]["status"] == "OK"
        assert "SSH_WEAK_CIPHER_OFFERED" in finding["policy_issues"]
        assert finding["compliance_issue"] in finding["policy_issues"]
        assert result["ssh_probe_telemetry"]["ssh_weak_algorithm_offers"] == 1
    finally:
        server.close()
