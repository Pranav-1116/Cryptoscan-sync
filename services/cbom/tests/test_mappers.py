from cbom.mappers.oid_lookup import lookup_oid
from cbom.mappers.primitive_mapper import map_primitive


def test_oid_and_primitive():
    assert lookup_oid("DES") == "1.3.14.3.2.7"
    assert map_primitive("AES") == "block-cipher"
    assert map_primitive(None, "SIGNING") == "signature"
