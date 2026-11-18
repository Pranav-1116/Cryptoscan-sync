"""A complete, fake Linux host on disk: root filesystem, /proc and /sys.

Used by the agent's own tests and by the API's end-to-end Cryptava test, so both see
exactly the same machine: a Dell server running nginx with OpenSSL 3.0, a CA-issued
ECDSA certificate, an SSH host key, a TPM 2.0, an Intel NIC and a TLS listener on 8443
owned by nginx.
"""

from __future__ import annotations

import os
from pathlib import Path

DATA = Path(__file__).resolve().parent / "fixtures"

SSH_ED25519_PUB = ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl "
                   "root@swiftgw01\n")

DPKG_STATUS = """\
Package: libssl3
Status: install ok installed
Architecture: amd64
Maintainer: Debian OpenSSL Team <pkg-openssl-devel@alioth-lists.debian.net>
Source: openssl
Version: 3.0.15-1~deb12u1

Package: openssl
Status: install ok installed
Architecture: amd64
Maintainer: Debian OpenSSL Team <pkg-openssl-devel@alioth-lists.debian.net>
Version: 3.0.15-1~deb12u1

Package: nginx
Status: install ok installed
Architecture: amd64
Maintainer: Debian Nginx Maintainers <pkg-nginx-maintainers@alioth-lists.debian.net>
Version: 1.22.1-9

Package: openssh-server
Status: install ok installed
Architecture: amd64
Maintainer: Debian OpenSSH Maintainers <debian-ssh@lists.debian.org>
Version: 1:9.2p1-2+deb12u3

Package: removed-thing
Status: deinstall ok config-files
Architecture: amd64
Version: 1.0
"""

LIBSSL = "/usr/lib/x86_64-linux-gnu/libssl.so.3"
LIBCRYPTO = "/usr/lib/x86_64-linux-gnu/libcrypto.so.3"


def _w(path: Path, text: str | bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(text, bytes):
        path.write_bytes(text)
    else:
        path.write_text(text)
    return path


def _hex_port(port: int) -> str:
    return f"{port:04X}"


def build(base: Path, *, hostname: str = "swiftgw01", ip: str = "10.210.0.4") -> dict[str, str]:
    """Create ``base/root``, ``base/proc`` and ``base/sys``; return a config for them."""
    root, proc, sys = base / "root", base / "proc", base / "sys"

    # -- root filesystem ------------------------------------------------------- #
    _w(root / "etc/hostname", hostname + "\n")
    _w(root / "etc/machine-id", "4f1c2d3e4b5a69788796a5b4c3d2e1f0\n")
    _w(root / "etc/os-release", 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nNAME="Debian GNU/Linux"\n'
                                'VERSION_ID="12"\nID=debian\n')
    _w(root / "etc/passwd", "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n")
    _w(root / "var/lib/dpkg/status", DPKG_STATUS)
    _w(root / "var/lib/dpkg/info/libssl3:amd64.list", f"/.\n/usr\n{LIBSSL}\n{LIBCRYPTO}\n")
    _w(root / "var/lib/dpkg/info/nginx.list", "/usr/sbin/nginx\n")
    _w(root / LIBSSL.lstrip("/"), b"\x7fELF fake")
    _w(root / LIBCRYPTO.lstrip("/"), b"\x7fELF fake")
    _w(root / "etc/ssl/certs/ca-certificates.crt", (DATA / "ca.pem").read_text())
    _w(root / "etc/nginx/tls/swiftgw01.crt", (DATA / "leaf.pem").read_text())
    _w(root / "etc/nginx/tls/swiftgw01.key", "-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----\n")
    _w(root / "etc/nginx/sites-enabled/swift", (
        "server {\n  listen 8443 ssl;\n  ssl_certificate /etc/nginx/tls/swiftgw01.crt;\n"
        "  ssl_certificate_key /etc/nginx/tls/swiftgw01.key;\n  ssl_protocols TLSv1.2 TLSv1.3;\n"
        "  ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:!aNULL;\n}\n"))
    _w(root / "etc/ssl/openssl.cnf", "[system_default_sect]\nMinProtocol = TLSv1.2\nCipherString = DEFAULT@SECLEVEL=2\n")
    _w(root / "etc/ssh/sshd_config", "Port 22\nCiphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com\n"
                                     "KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256\n"
                                     "HostKey /etc/ssh/ssh_host_ed25519_key\n")
    _w(root / "etc/ssh/ssh_host_ed25519_key.pub", SSH_ED25519_PUB)
    _w(root / "etc/ssh/ssh_host_ed25519_key", "-----BEGIN OPENSSH PRIVATE KEY-----\nnever-read\n")
    _w(root / "usr/lib/python3/dist-packages/requests-2.28.1.dist-info/METADATA",
       "Metadata-Version: 2.1\nName: requests\nVersion: 2.28.1\n")
    _w(root / "opt/swift/lib/bcprov-jdk18on-1.78.jar", b"PK\x03\x04")

    # -- /proc ----------------------------------------------------------------- #
    _w(proc / "cpuinfo", "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Xeon(R) Gold 6338 CPU\n"
                         "flags\t\t: fpu sse2 aes pclmulqdq rdrand rdseed sha_ni avx2\n\n"
                         "processor\t: 1\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Xeon(R) Gold 6338 CPU\n"
                         "flags\t\t: fpu sse2 aes pclmulqdq rdrand rdseed sha_ni avx2\n")
    _w(proc / "meminfo", "MemTotal:       65843204 kB\n")
    _w(proc / "sys/crypto/fips_enabled", "0\n")
    _w(proc / "sys/kernel/osrelease", "6.1.0-28-amd64\n")
    _w(proc / "sys/kernel/hostname", hostname + "\n")
    _w(proc / "1/cgroup", "0::/init.scope\n")
    header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    a, b, c, d = (int(x) for x in ip.split("."))
    ip_hex = f"{d:02X}{c:02X}{b:02X}{a:02X}"
    remote = "0B00D20A"  # 10.210.0.11 (an HSM peer)
    _w(proc / "net/tcp", header +
       f"   0: 00000000:{_hex_port(8443)} 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1\n"
       f"   1: 00000000:{_hex_port(22)} 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346 1\n"
       f"   2: {ip_hex}:{_hex_port(51544)} {remote}:{_hex_port(1792)} 01 00000000:00000000 00:00000000 00000000    33        0 12347 1\n")
    _w(proc / "net/tcp6", header)
    _w(proc / "net/udp", header)
    _w(proc / "net/udp6", header)
    for pid, comm, exe, uid, inodes, maps in (
        (4242, "nginx", "/usr/sbin/nginx", "33", ["12345", "12347"], [LIBSSL, LIBCRYPTO]),
        (777, "sshd", "/usr/sbin/sshd", "0", ["12346"], [LIBCRYPTO]),
    ):
        p = proc / str(pid)
        _w(p / "comm", comm + "\n")
        _w(p / "status", f"Name:\t{comm}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
        _w(p / "maps", "".join(f"7f0000000000-7f0000100000 r-xp 00000000 08:01 1 {path}\n" for path in maps)
           + "7f0000200000-7f0000300000 r-xp 00000000 08:01 2 /usr/lib/x86_64-linux-gnu/libc.so.6\n")
        (p / "fd").mkdir(parents=True, exist_ok=True)
        for n, inode in enumerate(inodes, start=3):
            os.symlink(f"socket:[{inode}]", p / "fd" / str(n))
        os.symlink(exe, p / "exe")
        os.symlink(str(root), p / "root")

    # -- /sys ------------------------------------------------------------------ #
    dmi = sys / "class/dmi/id"
    for name, value in {"sys_vendor": "Dell Inc.", "product_name": "PowerEdge R750",
                        "product_serial": "7XK2M93", "bios_vendor": "Dell Inc.", "bios_version": "1.12.1",
                        "bios_date": "04/11/2024", "chassis_asset_tag": "MRDN-DC1-0042"}.items():
        _w(dmi / name, value + "\n")
    _w(sys / "class/net/eth0/address", "b0:26:28:aa:bb:cc\n")
    _w(sys / "class/net/eth0/device/vendor", "0x8086\n")
    _w(sys / "class/net/eth0/device/device", "0x1593\n")
    _w(sys / "class/net/eth0/speed", "25000\n")
    _w(sys / "class/tpm/tpm0/tpm_version_major", "2\n")
    _w(sys / "class/tpm/tpm0/device/caps", "Manufacturer: 0x49465800\nTCG version: 2.0\n")

    return {"root": str(root), "proc": str(proc), "sys": str(sys), "primary_ip": ip,
            "domain": "mrdn.bank", "probe_listeners": False, "dmidecode": False, "jar_dirs": ["/opt"]}
