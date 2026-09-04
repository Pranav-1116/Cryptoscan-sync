"""Process-level crypto discovery against a fixture /proc tree."""

from __future__ import annotations

import os
from pathlib import Path


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def build_fake_proc(base: Path) -> None:
    # 101: nginx with OpenSSL 1.0.2 (EOL) listening on 443
    _write(base / "101" / "comm", "nginx\n")
    _write(base / "101" / "cmdline", "nginx: master process\x00")
    _write(
        base / "101" / "maps",
        "7f0000000000-7f0000010000 r--p 00000000 08:01 100 /usr/lib/x86_64-linux-gnu/libssl.so.1.0.2\n"
        "7f0000010000-7f0000020000 r--p 00000000 08:01 101 /usr/lib/x86_64-linux-gnu/libcrypto.so.1.0.2\n",
    )
    _write(base / "101" / "cgroup", "0::/kubepods/podabc123/nginx\n")
    # listening socket: inode 9001 -> port 443 (0x1BB)
    _write(
        base / "net" / "tcp",
        "  sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 000000 0 0 9001\n",
    )
    (base / "101" / "fd").mkdir(parents=True, exist_ok=True)
    os.symlink("socket:[9001]", base / "101" / "fd" / "3")

    # 202: java service with modern OpenSSL 3, listening on 8443
    _write(base / "202" / "comm", "java\n")
    _write(base / "202" / "cmdline", "java\x00-jar\x00payments.jar\x00")
    _write(
        base / "202" / "maps",
        "7f1000000000-7f1000010000 r--p 00000000 08:01 200 /usr/lib/jvm/lib/libjvm.so\n"
        "7f1000010000-7f1000020000 r--p 00000000 08:01 201 /usr/lib/x86_64-linux-gnu/libssl.so.3.2.1\n",
    )
    _write(base / "202" / "cgroup", "0::/system.slice/payments.service\n")
    _write(
        base / "net" / "tcp6",
        "  sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 00000000000000000000000000000000:20FB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 000000 0 0 9002\n",
    )
    (base / "202" / "fd").mkdir(parents=True, exist_ok=True)
    os.symlink("socket:[9002]", base / "202" / "fd" / "7")

    # 303: python worker, no TLS libs, not listening
    _write(base / "303" / "comm", "python3\n")
    _write(base / "303" / "cmdline", "python3\x00worker.py\x00")
    _write(base / "303" / "maps", "7f2000000000-7f2000010000 r--p 00000000 08:01 300 /usr/lib/python3.11/libpython3.11.so\n")

    # 404: legacy gnutls 3.5 daemon
    _write(base / "404" / "comm", "legacyd\n")
    _write(base / "404" / "cmdline", "/usr/sbin/legacyd\x00")
    _write(base / "404" / "maps", "7f3000000000-7f3000010000 r--p 00000000 08:01 400 /usr/lib/libgnutls.so.30.14\n")


def test_process_discovery_full_contract(tmp_path):
    from runtime.agent.process_discovery import scan_processes

    build_fake_proc(tmp_path)
    result = scan_processes(str(tmp_path))

    assert result["process_count"] == 4
    assert result["processes_with_tls_libraries"] == 3
    assert result["listening_processes"] == 2

    by_pid = {p["pid"]: p for p in result["processes"]}

    nginx = by_pid[101]
    assert "openssl" in nginx["tls_libraries"]
    assert nginx["library_details"][0]["version"] == "1.0.2"
    assert nginx["containerized"] is True
    assert nginx["listening_ports"] == [443]
    assert nginx["runtime"] == "proxy"

    java = by_pid[202]
    assert set(java["tls_libraries"]) == {"openssl", "java"}
    assert java["listening_ports"] == [8443]  # 0x20FB
    assert java["containerized"] is False
    assert java["runtime"] == "jvm"

    python_proc = by_pid[303]
    assert python_proc["tls_libraries"] == []
    assert python_proc["listening_ports"] == []
    assert python_proc["runtime"] == "python"

    legacy = by_pid[404]
    assert "gnutls" in legacy["tls_libraries"]


def test_process_discovery_flags_risky_libraries(tmp_path):
    from runtime.agent.process_discovery import scan_processes

    build_fake_proc(tmp_path)
    result = scan_processes(str(tmp_path))
    findings = result["findings"]

    # OpenSSL 1.0.2 (nginx) genuinely EOL — must be flagged. The legacy GnuTLS
    # daemon's map only carries the ABI soname (libgnutls.so.30.x) which is NOT
    # a release version; in the fixture the fake path has no package-manager
    # owner, so it is inventory-only (UNKNOWN), never a false DEPRECATED.
    flagged = {(f["process_name"], f["library"], f["version"]) for f in findings}
    assert ("nginx", "openssl", "1.0.2") in flagged
    # soname-only GnuTLS (30.14) must NOT be flagged — 30 is the stable ABI
    # tag shared by modern GnuTLS 3.3–3.8, not an "old 3.5" indicator.
    assert not any(f["pid"] == 404 for f in findings)
    # modern OpenSSL 3 (java) must NOT be flagged
    assert not any(f["pid"] == 202 for f in findings)

    openssl_finding = next(f for f in findings if f["library"] == "openssl")
    assert openssl_finding["status"] == "DISALLOWED"
    assert "EOL" in openssl_finding["notes"]
    assert openssl_finding["listening_ports"] == [443]  # it serves TLS too — worst case


def test_process_discovery_tolerates_empty_proc(tmp_path):
    from runtime.agent.process_discovery import scan_processes

    result = scan_processes(str(tmp_path / "nothing"))
    assert result["process_count"] == 0
    assert result["findings"] == []
