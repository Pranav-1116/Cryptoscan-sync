from cbom.core.generator import CbomGenerator
from cbom.serializers.xml_serializer import to_xml
from cbom.signing.cbom_signer import sign_cbom, verify_cbom
from cbom.signing.key_manager import KeyManager
from cbom.validators.cbom_validator import CbomValidator


def test_spec_named_cbom_modules_round_trip():
    bom = CbomGenerator().from_records(
        [{"id": "e1", "algorithm": "AES", "mode": "GCM", "file_path": "a.py", "line_number": 1}]
    )
    xml = to_xml(bom)
    assert "<bom" in xml
    signed = sign_cbom(bom, "secret")
    assert verify_cbom(signed, "secret")
    assert not verify_cbom(signed, "other")
    keys = KeyManager(secret="secret")
    again = keys.sign(bom)
    assert keys.verify(again)
    assert CbomValidator().validate(bom)["ok"]
    assert not CbomValidator().validate({"bomFormat": "nope"})["ok"]
