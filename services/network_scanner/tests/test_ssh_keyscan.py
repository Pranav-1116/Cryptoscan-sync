"""SSH host-key scanning: keyscan parsing, policy, TOFU drift, live sshd."""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time

import pytest

from network_scanner.probing.ssh_keyscan import (
    classify_host_key,
    compare_host_keys,
    parse_fingerprint_line,
    parse_keyscan_output,
    scan_ssh_host_keys,
    split_ssh_target,
    ssh_probe_telemetry,
)

SSHD_BIN = "/usr/sbin/sshd"
LIVE_SUPPORTED = os.path.exists(SSHD_BIN) and shutil.which("ssh-keyscan") and shutil.which("ssh-keygen")


# --------------------------------------------------------------------------- #
# pure parsers
# --------------------------------------------------------------------------- #

def test_parse_keyscan_output_forms():
    text = (
        "# 127.0.0.1:22 SSH-2.0-OpenSSH_9.2\r\n"
        "[127.0.0.1]:2222 ssh-rsa AAAAB3data==\n"
        "127.0.0.1 ssh-ed25519 AAAAC3data==\n"
        "garbage line without three fields\n"
    )
    records = parse_keyscan_output(text)
    assert [record["key_type"] for record in records] == ["ssh-rsa", "ssh-ed25519"]
    assert records[0]["host_field"] == "[127.0.0.1]:2222"
    assert records[1]["key_data"] == "AAAAC3data=="


def test_parse_fingerprint_line():
    parsed = parse_fingerprint_line(
        "2048 SHA256:WcbdGbbgLnSuhOuNUqbw+WLxMFYZnko5u95C0ShjqkA [127.0.0.1]:2222 (RSA)"
    )
    assert parsed == {
        "bits": 2048,
        "fingerprint_sha256": "SHA256:WcbdGbbgLnSuhOuNUqbw+WLxMFYZnko5u95C0ShjqkA",
        "comment": "[127.0.0.1]:2222",
        "key_type_label": "RSA",
    }
    assert parse_fingerprint_line("not a fingerprint") is None
    assert parse_fingerprint_line("") is None


def test_classify_host_key_matrix():
    assert classify_host_key("ssh-dss", 1024)["status"] == "DISALLOWED"
    assert "SSH_DSS_HOST_KEY" in classify_host_key("ssh-dss", 1024)["policy_issues"]
    rsa = classify_host_key("ssh-rsa", 2048)
    assert rsa["status"] == "WEAK" and "SSH_RSA_HOST_KEY" in rsa["policy_issues"]
    weak_rsa = classify_host_key("ssh-rsa", 1024)
    assert weak_rsa["status"] == "DISALLOWED" and "SSH_WEAK_HOST_KEY" in weak_rsa["policy_issues"]
    assert classify_host_key("ssh-ed25519", 256)["status"] == "OK"
    assert classify_host_key("ecdsa-sha2-nistp256", 256)["policy_issues"] == []


def test_split_ssh_target():
    assert split_ssh_target("10.0.0.1") == ("10.0.0.1", 22)
    assert split_ssh_target("10.0.0.1:2222") == ("10.0.0.1", 2222)
    assert split_ssh_target("[::1]:2222") == ("::1", 2222)
    assert split_ssh_target("host:notaport") == ("host:notaport", 22)


# --------------------------------------------------------------------------- #
# TOFU drift (pure)
# --------------------------------------------------------------------------- #

def _observed(key_type="ssh-ed25519", fp="SHA256:abc"):
    return [{"key_type": key_type, "fingerprint_sha256": fp}]


def test_drift_first_observation():
    drift = compare_host_keys(None, _observed())
    assert drift["status"] == "FIRST_OBSERVATION"
    assert drift["observed"] == {"ssh-ed25519": "SHA256:abc"}


def test_drift_unchanged():
    drift = compare_host_keys({"ssh-ed25519": "SHA256:abc"}, _observed())
    assert drift["status"] == "UNCHANGED"
    assert drift["changes"] == [] and drift["added"] == [] and drift["removed"] == []


def test_drift_changed_fingerprint():
    drift = compare_host_keys({"ssh-ed25519": "SHA256:old"}, _observed(fp="SHA256:new"))
    assert drift["status"] == "CHANGED"
    assert drift["changes"] == [{"key_type": "ssh-ed25519", "was": "SHA256:old", "now": "SHA256:new"}]


def test_drift_added_and_removed_key_types():
    drift = compare_host_keys({"ssh-rsa": "SHA256:r"}, _observed())
    assert drift["status"] == "CHANGED"  # removal counts as a change
    assert drift["removed"] == ["ssh-rsa"]
    added_case = compare_host_keys({}, _observed())
    assert added_case["status"] == "FIRST_OBSERVATION"  # empty baseline = first look


# --------------------------------------------------------------------------- #
# telemetry (pure)
# --------------------------------------------------------------------------- #

def test_ssh_probe_telemetry():
    rows = [
        {"status": "OK", "policy_issues": ["SSH_RSA_HOST_KEY"]},
        {"status": "OK", "policy_issues": ["SSH_HOST_KEY_CHANGED"]},
        {"status": "OK", "policy_issues": []},
        {"status": "SSH_UNREACHABLE", "policy_issues": []},
    ]
    telemetry = ssh_probe_telemetry(rows)
    assert telemetry["probed"] == 4 and telemetry["ok"] == 3
    assert telemetry["ssh_weak_host_keys"] == 1
    assert telemetry["ssh_host_key_changes"] == 1
    assert telemetry["status"] == "PARTIAL"
    assert ssh_probe_telemetry([])["status"] == "SKIPPED"


# --------------------------------------------------------------------------- #
# live (local sshd)
# --------------------------------------------------------------------------- #

class SshdServer:
    """Real sshd on an ephemeral port with freshly generated host keys."""

    def __init__(self, tmp_path, key_spec=("rsa", "ed25519")):
        self.root = tmp_path
        self.host_keys = {}
        for spec in key_spec:
            args = ["ssh-keygen", "-q", "-t", spec, "-N", ""]
            if spec == "rsa":
                args += ["-b", "2048"]
            path = tmp_path / f"host_{spec}"
            args += ["-f", str(path)]
            subprocess.run(args, check=True, capture_output=True)
            self.host_keys[spec] = path
        self.config = tmp_path / "sshd_config"
        key_lines = "\n".join(f"HostKey {path}" for path in self.host_keys.values())
        self.config.write_text(
            f"Port 0\n{key_lines}\nUsePAM no\nPasswordAuthentication no\nAuthorizedKeysFile none\n"
            f"PidFile {tmp_path}/sshd.pid\n"
        )
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.close()
        self.proc = subprocess.Popen(
            [SSHD_BIN, "-D", "-e", "-f", str(self.config), "-p", str(self.port)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        self._wait_listening()

    def _wait_listening(self, seconds=5.0):
        deadline = time.time() + seconds
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.5):
                    return
            except OSError:
                time.sleep(0.1)
        raise AssertionError("sshd did not start listening")

    def close(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


@pytest.mark.skipif(not LIVE_SUPPORTED, reason="sshd/ssh-keyscan not available")
def test_scan_ssh_live_keys_and_policy(tmp_path):
    server = SshdServer(tmp_path)
    try:
        finding = scan_ssh_host_keys("127.0.0.1", server.port, timeout=6.0)
        assert finding["status"] == "OK"
        types = {key["key_type"] for key in finding["keys"]}
        assert types == {"ssh-rsa", "ssh-ed25519"}
        for key in finding["keys"]:
            assert key["fingerprint_sha256"].startswith("SHA256:")
            assert key["bits"] in {2048, 256}
        assert "SSH_RSA_HOST_KEY" in finding["policy_issues"]
        assert finding["key_drift"]["status"] == "FIRST_OBSERVATION"
    finally:
        server.close()


@pytest.mark.skipif(not LIVE_SUPPORTED, reason="sshd/ssh-keyscan not available")
def test_scan_ssh_tofu_unchanged_then_changed(tmp_path):
    server = SshdServer(tmp_path)
    try:
        first = scan_ssh_host_keys("127.0.0.1", server.port, timeout=6.0)
        baseline = first["key_drift"]["observed"]
        second = scan_ssh_host_keys("127.0.0.1", server.port, timeout=6.0, baseline=baseline)
        assert second["key_drift"]["status"] == "UNCHANGED"
        assert "SSH_HOST_KEY_CHANGED" not in second["policy_issues"]
        tampered = dict(baseline, **{"ssh-ed25519": "SHA256:totallydifferent"})
        third = scan_ssh_host_keys("127.0.0.1", server.port, timeout=6.0, baseline=tampered)
        assert third["key_drift"]["status"] == "CHANGED"
        assert "SSH_HOST_KEY_CHANGED" in third["policy_issues"]
        assert third["compliance_issue"] == "SSH_HOST_KEY_CHANGED"
    finally:
        server.close()


def test_scan_ssh_dead_port_is_unreachable():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()  # nothing listens here
    finding = scan_ssh_host_keys("127.0.0.1", port, timeout=3.0)
    assert finding["status"] == "SSH_UNREACHABLE"
    assert finding["detail"]


def test_scan_ssh_without_binaries(monkeypatch):
    import network_scanner.probing.ssh_keyscan as mod

    monkeypatch.setattr(mod.shutil, "which", lambda name: None)
    finding = mod.scan_ssh_host_keys("127.0.0.1", 22)
    assert finding["status"] == "LOCAL_UNSUPPORTED"
    assert finding["method"] == "ssh-binaries-missing"


# --------------------------------------------------------------------------- #
# scanner integration
# --------------------------------------------------------------------------- #

@pytest.mark.skipif(not LIVE_SUPPORTED, reason="sshd/ssh-keyscan not available")
def test_scanner_scan_ssh_hosts(tmp_path):
    from network_scanner.core.scanner import NetworkTlsScanner

    server = SshdServer(tmp_path, key_spec=("ed25519",))
    try:
        result = NetworkTlsScanner(live=True, timeout=6.0).scan_ssh_hosts(["127.0.0.1"])
        # default port 22 — nothing there; the scan must survive and report it
        endpoints_scanned = [finding["endpoint"] for finding in result["findings"]]
        target = f"127.0.0.1:{server.port}"
        result = NetworkTlsScanner(live=True, timeout=6.0).scan_ssh_hosts(
            [f"127.0.0.1:{server.port}"], known_host_keys={}
        )
        finding = result["findings"][0]
        assert finding["endpoint"] == target
        assert finding["status"] == "OK"
        assert result["ssh_probe_telemetry"]["ok"] == 1
        # the updated baseline map carries the observed fingerprints forward
        assert result["known_host_keys"][target]["ssh-ed25519"].startswith("SHA256:")
        assert endpoints_scanned  # the dead port run completed without raising
    finally:
        server.close()
