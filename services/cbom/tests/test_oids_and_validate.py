from cbom.generator import CbomGenerator


def test_cbom_includes_oid_and_validates():
    generator = CbomGenerator()
    bom = generator.from_records(
        [
            {
                "id": "e1",
                "algorithm": "AES",
                "mode": "GCM",
                "key_size": 256,
                "file_path": "a.py",
                "line_number": 3,
            }
        ],
        name="demo",
        version="1",
        vulnerabilities=[{"cve": "CVE-2013-1445", "package": "pycrypto", "severity": "MEDIUM"}],
    )
    assert bom["components"][0]["cryptoProperties"]["oid"]
    assert bom["components"][0]["cryptoProperties"]["algorithmProperties"]["primitive"] == "block-cipher"
    assert bom["vulnerabilities"][0]["id"] == "CVE-2013-1445"
    assert bom["dependencies"]
    assert generator.validate(bom)["ok"]
    assert not generator.validate({"bomFormat": "nope"})["ok"]
