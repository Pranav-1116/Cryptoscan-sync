"""Repo scans must reach config files: Dockerfile, sshd_config, *.yml, *.properties, .env.*"""
from pathlib import Path

from scanner.core.file_discovery import FileDiscovery, is_named_config_file
from scanner.core.scanner import Scanner
from scanner.registry.language_scanners import scan_file


def test_named_config_files_recognised():
    assert is_named_config_file("Dockerfile")
    assert is_named_config_file("api.Dockerfile")
    assert is_named_config_file(".env.production")
    assert is_named_config_file("sshd_config")
    assert not is_named_config_file("README.md")
    assert not is_named_config_file("main.go")


def test_discovery_yields_config_files(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text("ENV NODE_TLS_REJECT_UNAUTHORIZED=0\n")
    (tmp_path / "app.yml").write_text("server:\n  ssl:\n    enabled-protocols: TLSv1\n")
    (tmp_path / "sshd_config").write_text("Ciphers 3des-cbc\n")
    (tmp_path / "notes.md").write_text("MD5 is mentioned here but markdown is not scanned\n")
    names = {p.name for p in FileDiscovery().discover(tmp_path)}
    assert {"Dockerfile", "app.yml", "sshd_config"} <= names
    assert "notes.md" not in names


def test_scanner_reports_config_crypto(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text("FROM alpine\nENV NODE_TLS_REJECT_UNAUTHORIZED=0\nENV JWT_ALGORITHM=HS256\n")
    (tmp_path / "sshd_config").write_text("Ciphers 3des-cbc,aes128-ctr\nMACs hmac-md5\n")
    result = Scanner().scan(tmp_path)
    algos = {f.crypto.algorithm for f in result.findings}
    assert "TLS-CERT-NONE" in algos
    assert "JWT" in algos
    assert {"3DES", "AES", "HMAC", "MD5"} <= algos


def test_config_tree_does_not_duplicate_discovered_file(tmp_path: Path):
    config = tmp_path / "site.conf"
    config.write_text("ssl_protocols TLSv1;\n")
    expected = scan_file(config, tmp_path)
    assert len(expected) == 1

    result = Scanner().scan(tmp_path)
    assert [(f.source.file_path, f.source.line_number, f.crypto.algorithm) for f in result.findings] == [
        ("site.conf", 1, "TLS1.0")
    ]
    assert result.statistics.files_scanned == 1
    assert result.statistics.total_findings == 1
    assert result.statistics.high_confidence + result.statistics.medium_confidence + result.statistics.low_confidence == 1
    assert result.statistics.files_with_crypto == 1


def test_named_configs_keep_first_pass_findings(tmp_path: Path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("ssl_protocols TLSv1;\n")
    sshd = tmp_path / "sshd_config"
    sshd.write_text("Ciphers 3des-cbc\n")
    expected = {p.name: scan_file(p, tmp_path) for p in (dockerfile, sshd)}
    assert all(expected.values())

    result = Scanner().scan(tmp_path)
    assert result.statistics.files_scanned == 2
    assert result.statistics.total_findings == sum(map(len, expected.values()))
    for name, first_pass in expected.items():
        assert [(f.source.line_number, f.crypto.algorithm, f.scanner_id) for f in result.findings
                if f.source.file_path == name] == [
            (f.source.line_number, f.crypto.algorithm, f.scanner_id) for f in first_pass
        ]


def test_attls_config_keeps_special_pass_without_config_duplicates(tmp_path: Path):
    policy = tmp_path / "TTLS.conf"
    policy.write_text("TTLSRule MQ\n{\n  V3CipherSuites TLS_RSA_WITH_3DES_EDE_CBC_SHA\n}\n")
    expected = scan_file(policy, tmp_path)
    assert {"TLS", "3DES", "RSA", "SHA-1"} <= {f.crypto.algorithm for f in expected}

    result = Scanner().scan(tmp_path)
    assert [(f.source.line_number, f.crypto.algorithm, f.scanner_id) for f in result.findings] == [
        (f.source.line_number, f.crypto.algorithm, f.scanner_id) for f in expected
    ]
    assert result.statistics.total_findings == len(expected)


def test_config_tree_fallback_and_regular_source(tmp_path: Path):
    config = tmp_path / "undiscovered.yml"
    config.write_text("ssl_protocols TLSv1.2;\n")
    source = tmp_path / "app.py"
    source.write_text("import hashlib\nhashlib.md5(b'payload')\n")
    scanner = Scanner()
    scanner.file_discovery = FileDiscovery(extensions=(".py",))
    result = scanner.scan(tmp_path)

    assert result.statistics.files_scanned == 1
    assert result.statistics.total_findings == 2
    assert {(f.source.file_path, f.crypto.algorithm) for f in result.findings} == {
        ("undiscovered.yml", "TLS1.2"), ("app.py", "MD5")
    }


def test_templated_nginx_config_is_scanned_and_lines_are_exact(tmp_path):
    from scanner.core.file_discovery import FileDiscovery
    from scanner.registry.language_scanners import scan_file
    # kubernetes/ingress-nginx rootfs/etc/nginx/template/nginx.tmpl
    tmpl = tmp_path / "nginx.tmpl"
    tmpl.write_text("http {\n\n    ssl_protocols {{ $cfg.SSLProtocols }};\n    ssl_ciphers '{{ $cfg.SSLCiphers }}';\n    ssl_ecdh_curve {{ $cfg.SSLECDHCurve }};\n}\n")
    assert tmpl in set(FileDiscovery().discover(tmp_path))
    found = {(f.source.line_number, f.crypto.algorithm) for f in scan_file(tmpl, tmp_path)}
    assert (3, "TLS") in found
    assert (4, "TLS-CIPHERS") in found
    assert (5, "ECDH") in found
