"""Key & certificate inventory ingestion: ICSF, TR-31, Luna, nShield, PKCS#11, cloud KMS, Vault, keytool, RACDCERT, cert CSV."""
from pathlib import Path


from scanner.core.file_discovery import FileDiscovery
from scanner.parsers.key_inventory_parser import parse_key_inventory_file
from scanner.registry.language_scanners import scan_file

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "key_inventory"


def _by_label(fs):
    return {(f.inventory.get("key_label") or f.inventory.get("subject")): f for f in fs if not f.inventory.get("role")}


def test_icsf_ckds_pkds():
    fs = parse_key_inventory_file(FIX / "ckds.lst", FIX)
    assert all(f.source.type == "KEY_INVENTORY" and f.metadata.library == "ICSF" for f in fs)
    b = _by_label(fs)
    assert b["PAY.ZPK.ACQ001"].crypto.algorithm == "3DES" and b["PAY.ZPK.ACQ001"].crypto.key_size == 128
    assert b["PAY.ZMK.VISA"].crypto.key_size == 192 and b["STMT.AES.DATA"].crypto.algorithm == "AES" and b["STMT.AES.DATA"].crypto.key_size == 256
    assert b["LEGACY.DATA.SINGLE"].crypto.algorithm == "DES" and b["LEGACY.DATA.SINGLE"].inventory["state"] == "ARCHIVED"
    assert b["CARD.CVK.A"].inventory["last_used"] == "2021-02-02" and b["API.HMAC.KEY"].crypto.algorithm == "HMAC"
    fs = parse_key_inventory_file(FIX / "pkds.lst", FIX)
    b = _by_label(fs)
    assert (b["SWIFT.SIGN.RSA2048"].crypto.algorithm, b["SWIFT.SIGN.RSA2048"].crypto.key_size) == ("RSA", 2048)
    assert b["OLD.SIGN.RSA1024"].crypto.key_size == 1024 and b["PQC.PILOT.MLDSA"].crypto.algorithm == "ML-DSA"
    assert (b["TLS.ECC.P256"].crypto.algorithm, b["TLS.ECC.P256"].crypto.key_size) == ("ECDSA", 256)


def test_tr31_key_blocks():
    fs = parse_key_inventory_file(FIX / "payshield-export.txt", FIX)
    assert all(f.metadata.library == "TR-31" for f in fs)
    usages = {f.inventory["key_usage"][:2]: f for f in fs}
    assert usages["P0"].crypto.algorithm == "3DES" and usages["P0"].inventory["key_block_version"].startswith("TR-31 D")
    assert usages["K0"].crypto.algorithm == "AES" and usages["K0"].inventory["exportability"].startswith("sensitive")
    assert usages["B0"].crypto.algorithm == "3DES" and usages["B0"].inventory["mode_of_use"] == "key derivation"
    assert usages["C0"].inventory["weak_binding"] is True  # version A block


def test_hsm_listings():
    b = _by_label(parse_key_inventory_file(FIX / "luna-cmu.txt", FIX))
    assert (b["tls-server-key-2026"].crypto.algorithm, b["tls-server-key-2026"].crypto.key_size) == ("RSA", 3072)
    assert (b["card-issuer-imk"].crypto.algorithm, b["card-issuer-imk"].crypto.key_size, b["card-issuer-imk"].inventory.get("extractable")) == ("AES", 128, True)
    assert (b["legacy-3des-zmk"].crypto.algorithm, b["legacy-3des-zmk"].crypto.key_size) == ("3DES", 192)
    b = _by_label(parse_key_inventory_file(FIX / "nshield.txt", FIX))
    assert (b["tlsproxy"].crypto.algorithm, b["tlsproxy"].crypto.key_size) == ("RSA", 2048)
    assert b["uc12ab34cd-hmacsign"].crypto.algorithm == "HMAC" and b["swiftlau"].crypto.algorithm == "AES" and b["oldsig"].crypto.key_size == 1024
    fs = parse_key_inventory_file(FIX / "pkcs11-tool.txt", FIX)
    algs = {(f.inventory.get("key_label"), f.inventory.get("object_class")): (f.crypto.algorithm, f.crypto.key_size) for f in fs}
    assert algs[("ebanking-signer", "public")] == ("RSA", 4096) and algs[("mobile-attest", "private")] == ("ECDSA", 384)
    assert algs[("db-tde-master", "secret")] == ("AES", 256) and algs[("ebanking-signer", "certificate")][0] == "X509"


def test_cloud_kms_and_vault():
    b = _by_label(parse_key_inventory_file(FIX / "aws-kms.json", FIX))
    assert (b["core-db-cmk"].crypto.algorithm, b["core-db-cmk"].crypto.key_size, b["core-db-cmk"].inventory["rotation_enabled"]) == ("AES", 256, True)
    assert b["statement-signer"].inventory["state"] == "PendingDeletion" and b["statement-signer"].inventory["key_store"] == "AWS CloudHSM"
    assert b["api-jwt-signer"].crypto.key_size == 384 and b["pqc-pilot"].crypto.algorithm == "ML-DSA"
    b = _by_label(parse_key_inventory_file(FIX / "azure-kv.json", FIX))
    assert (b["payments-wrap"].crypto.algorithm, b["payments-wrap"].crypto.key_size, b["payments-wrap"].inventory["key_store"]) == ("RSA", 3072, "Azure Managed HSM")
    assert (b["token-sign"].crypto.algorithm, b["token-sign"].crypto.key_size, b["token-sign"].inventory["state"]) == ("ECDSA", 256, "Disabled")
    assert (b["data-key"].crypto.algorithm, b["data-key"].crypto.key_size) == ("AES", 256)
    b = _by_label(parse_key_inventory_file(FIX / "gcp-kms.json", FIX))
    assert b["ledger-cmek"].inventory["key_store"] == "Cloud HSM" and b["ledger-cmek"].inventory["rotation_period"] == "7776000s"
    assert (b["doc-sign"].crypto.algorithm, b["doc-sign"].crypto.key_size, b["doc-sign"].inventory["key_store"]) == ("RSA", 2048, "Cloud KMS software")
    b = _by_label(parse_key_inventory_file(FIX / "vault-transit.json", FIX))
    assert (b["cards-pan"].crypto.algorithm, b["cards-pan"].crypto.key_size, b["cards-pan"].inventory["key_version"]) == ("AES", 256, "7")


def test_certificates_keytool_racdcert_csv():
    fs = parse_key_inventory_file(FIX / "keytool.txt", FIX)
    b = _by_label(fs)
    assert (b["ebank-tls"].crypto.algorithm, b["ebank-tls"].crypto.key_size, b["ebank-tls"].inventory["not_after"], b["ebank-tls"].inventory["expired"]) == ("RSA", 2048, "2026-01-12", True)
    assert b["legacy-partner-ca"].crypto.key_size == 1024 and b["legacy-partner-ca"].inventory["self_signed"] is True and b["legacy-partner-ca"].inventory["expired"] is False
    assert b["hmac-session"].crypto.algorithm == "HMAC"
    assert {f.crypto.algorithm for f in fs if f.inventory.get("role")} == {"SHA-256", "SHA-1"}  # signature digests
    b = _by_label(parse_key_inventory_file(FIX / "racdcert.txt", FIX))
    assert (b["PAY.SERVER.CERT"].crypto.key_size, b["PAY.SERVER.CERT"].inventory["key_store"], b["PAY.SERVER.CERT"].inventory["not_after"]) == (2048, "ICSF", "2027-01-01")
    assert b["OLD.BATCH.CERT"].inventory["expired"] is True and b["OLD.BATCH.CERT"].crypto.key_size == 1024
    b = _by_label(parse_key_inventory_file(FIX / "certs.csv", FIX))
    assert (b["mobile.bank.example"].crypto.algorithm, b["mobile.bank.example"].crypto.key_size) == ("ECDSA", 256)
    assert b["legacy.bank.example"].inventory["expired"] is True


def test_plain_text_is_silent_and_discovery_is_opt_in(monkeypatch):
    assert parse_key_inventory_file(FIX / "app-notes.txt", FIX) == []
    monkeypatch.delenv("CRYPTOSCAN_KEY_INVENTORY", raising=False)
    assert scan_file(FIX / "ckds.lst", FIX) == [] or all(f.source.type != "KEY_INVENTORY" for f in scan_file(FIX / "aws-kms.json", FIX))
    monkeypatch.setenv("CRYPTOSCAN_KEY_INVENTORY", "1")
    found = [p for p in FileDiscovery().discover(FIX)]
    assert len(found) >= 13
    inv = [f for p in found for f in scan_file(p, FIX) if f.source.type == "KEY_INVENTORY"]
    assert len({f.metadata.library for f in inv}) >= 11
    assert not [f for f in inv if f.source.file_path.endswith("app-notes.txt")]
