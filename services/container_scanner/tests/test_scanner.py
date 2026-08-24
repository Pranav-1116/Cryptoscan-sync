from container_scanner.core.scanner import ContainerScanner


def test_container_scanner_reads_manifests_and_cves(tmp_path):
    (tmp_path / "requirements.txt").write_text("pycrypto==2.6.1\ncryptography==41.0.7\n")
    (tmp_path / "package.json").write_text('{"dependencies": {"crypto-js": "4.1.1"}}\n')
    (tmp_path / "libcrypto.so.3").write_text("x")
    result = ContainerScanner().scan_filesystem(tmp_path)
    names = {pkg["name"] for pkg in result["packages"]}
    assert "pycrypto" in names
    assert "crypto-js" in names
    lib_names = {lib["name"] for lib in result["libraries"]}
    assert "cryptography" in lib_names
    cves = {item["cve"] for item in result["vulnerabilities"]}
    assert "CVE-2013-1445" in cves
    assert "CVE-2023-46233" in cves
    assert result["findings"]
