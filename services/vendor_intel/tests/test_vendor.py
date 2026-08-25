from vendor_intel.docs_extract import extract_crypto_mentions
from vendor_intel.questionnaire import generate_questionnaire, parse_questionnaire
from vendor_intel.risk import score_vendor
from vendor_intel.sbom_import import import_vendor_cbom


def test_questionnaire_and_strong_vendor():
    form = generate_questionnaire("Stripe")
    assert len(form["questions"]) == 6
    parsed = parse_questionnaire(
        {"transit": "TLS 1.3", "rest": "AES-256", "kms": "Cloud KMS", "pqc": "Planned", "cbom": "Yes"}
    )
    assert parsed["pqc_status"] == "planned"
    scored = score_vendor(profile=parsed, inventory=parsed["inventory"], classifications=["PCI-DSS"])
    assert scored["category"] == "LOW"
    assert scored["score"] < 40


def test_weak_vendor_and_sbom_and_docs():
    parsed = parse_questionnaire({"transit": "TLS 1.0", "rest": "AES-128", "pqc": "No", "cbom": "No"})
    scored = score_vendor(
        profile=parsed,
        inventory=parsed["inventory"],
        classifications=["PII"],
        long_lived_data=True,
        refuses_disclosure=True,
    )
    assert scored["category"] == "HIGH"
    assert scored["score"] > 70
    items = import_vendor_cbom(
        {
            "bomFormat": "CycloneDX",
            "components": [
                {
                    "type": "cryptographic-asset",
                    "name": "TLS 1.3 for API",
                    "cryptoProperties": {
                        "algorithmProperties": {"primitive": "ae", "parameterSetIdentifier": "256", "mode": "gcm"}
                    },
                }
            ],
        }
    )
    assert items[0]["discovery_method"] == "SBOM"
    docs = extract_crypto_mentions("Amazon S3 uses AES-256 server-side encryption and TLS 1.3")
    algos = {row["algorithm"] for row in docs["inventory"]}
    assert "AES-256" in algos
