# import pytest
from payment_crypto.iso20022 import parse_iso20022_xml
from cbom.kmip import assess_kmip_object

def test_iso20022_signature_parsing_valid():
    sample_xml = '''<?xml version="1.0" encoding="UTF-8"?>
    <head.001.001.01 xmlns="urn:iso:std:iso:20022:tech:xsd:head.001.001.01">
      <BizMsgIdr>BMSG-2026-CH-00912</BizMsgIdr>
      <CreDt>2026-09-19T10:00:00Z</CreDt>
      <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
        <SignedInfo>
          <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
          <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
        </SignedInfo>
        <KeyInfo>
          <X509Data>
            <X509Certificate>MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0+m193...</X509Certificate>
          </X509Data>
        </KeyInfo>
      </Signature>
    </head.001.001.01>'''
    report = parse_iso20022_xml(sample_xml)
    assert report.signature_present is True
    assert report.business_message_identifier == "BMSG-2026-CH-00912"
    assert "rsa-sha256" in report.signature_algorithm

def test_iso20022_missing_signature():
    report = parse_iso20022_xml("<head.001.001.01><BizMsgIdr>NO-SIG</BizMsgIdr></head.001.001.01>")
    assert report.signature_present is False
    assert report.compliance_status == "FAIL"

def test_kmip_object_assessment():
    obj_legacy = assess_kmip_object({"id": "KEY-1", "algorithm": "3DES", "key_length": 168})
    assert obj_legacy.fips_compliant is False
    assert "violates FIPS 140-3" in obj_legacy.findings[0]

    obj_pqc = assess_kmip_object({"id": "KEY-2", "algorithm": "ML-KEM", "key_length": 768})
    assert obj_pqc.pqc_ready is True
    assert obj_pqc.quantum_risk == "NONE"
