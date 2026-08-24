from container_scanner.core.scanner import ContainerScanner
from container_scanner.parsers.os_packages import parse_apk_installed, parse_dpkg_status, parse_rpm_qa


def test_dpkg_and_apk_parsers(tmp_path):
    status = tmp_path / "dpkg-status"
    status.write_text(
        "Package: libssl3\nStatus: install ok installed\nVersion: 3.0.2-0ubuntu1\n\n"
        "Package: hello\nStatus: deinstall ok config-files\nVersion: 1\n"
    )
    pkgs = parse_dpkg_status(status)
    assert any(item["name"] == "openssl" for item in pkgs)

    apk = tmp_path / "apk-installed"
    apk.write_text("P:libcrypto3\nV:3.0.8-r4\n\n")
    assert parse_apk_installed(apk)[0]["name"] == "openssl"

    rpm = tmp_path / "rpm-packages.txt"
    rpm.write_text("openssl-3.0.7-1.el9\n")
    assert parse_rpm_qa(rpm)[0]["name"] == "openssl"


def test_scanner_reads_dpkg_status(tmp_path):
    dpkg = tmp_path / "var" / "lib" / "dpkg"
    dpkg.mkdir(parents=True)
    (dpkg / "status").write_text("Package: libssl3\nStatus: install ok installed\nVersion: 3.0.2\n")
    result = ContainerScanner().scan_filesystem(tmp_path)
    names = {pkg["name"] for pkg in result["packages"]}
    assert "openssl" in names
