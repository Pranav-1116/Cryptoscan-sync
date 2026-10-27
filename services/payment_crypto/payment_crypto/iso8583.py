"""ISO 8583 field-level cryptographic inventory.

An ISO 8583 interface spec says which data elements a link carries. Several of
those elements *are* cryptography — a PIN block, a MAC, EMV chip data, a
key-management block — so the field list is a crypto inventory for the link,
and one that a bank usually has written down long before anyone can point at
the code that builds it.

This maps declared data elements onto the crypto they imply and reports what a
PCI/migration review needs: which links carry PINs, which are MACed, and which
are still on TDES.

Scope: **structure only**. This takes a field list (``[52, 64]`` or
``{"52": ..., "64": ...}``), never a live message, and it does not parse,
build, encipher or verify anything. Field *values* on a real link are account
data; the analysers below ignore any value supplied and read only which fields
are present, so a caller cannot accidentally push cardholder data through here.

Secondary bitmap fields (65–128) are as meaningful as primary ones: field 128
is the MAC on messages that use the secondary bitmap, and reading only 1–64
would report such a link as unauthenticated.
"""

from __future__ import annotations

from dataclasses import dataclass, field as dc_field

#: Data elements that carry, or directly govern, cryptography.
#: field -> (name, kind, note)
CRYPTO_FIELDS: dict[int, tuple[str, str, str]] = {
    52: ("PIN Data", "PIN",
         "enciphered PIN block; the format and key determine PCI PIN exposure"),
    53: ("Security Related Control Information", "KEY_MGMT",
         "declares the key-management scheme in use on the link"),
    55: ("ICC Data / EMV", "EMV",
         "EMV chip data: carries the ARQC application cryptogram and CVN"),
    64: ("MAC (primary bitmap)", "MAC",
         "message authentication code over the message"),
    96: ("Key Management Data", "KEY_MGMT",
         "key block / key-change payload"),
    128: ("MAC (secondary bitmap)", "MAC",
          "message authentication code over the message"),
}

#: Elements that carry cardholder data rather than crypto. Tracked so a link
#: that carries a PAN but no MAC can be reported as such.
SENSITIVE_FIELDS: dict[int, str] = {
    2: "Primary Account Number (PAN)",
    14: "Expiration Date",
    35: "Track 2 Data",
    36: "Track 3 Data",
    45: "Track 1 Data",
}

_MAC_FIELDS = (64, 128)


@dataclass
class Iso8583Crypto:
    """What the declared field list implies for one link."""

    fields_present: list[int] = dc_field(default_factory=list)
    crypto_fields: list[dict] = dc_field(default_factory=list)
    sensitive_fields: list[dict] = dc_field(default_factory=list)
    carries_pin: bool = False
    carries_emv: bool = False
    is_maced: bool = False
    carries_cardholder_data: bool = False
    algorithms: list[str] = dc_field(default_factory=list)
    issues: list[dict] = dc_field(default_factory=list)
    errors: list[str] = dc_field(default_factory=list)


def _coerce_fields(fields) -> tuple[list[int], list[str]]:
    """Accept a list, a set, or a dict keyed by field number. Values are ignored."""
    errors: list[str] = []
    raw = fields.keys() if isinstance(fields, dict) else fields
    out: list[int] = []
    for item in raw or []:
        try:
            num = int(str(item).strip())
        except (TypeError, ValueError):
            errors.append(f"not a data-element number: {item!r}")
            continue
        if not 1 <= num <= 128:
            errors.append(f"data element out of range 1-128: {num}")
            continue
        out.append(num)
    return sorted(set(out)), errors


def analyse_message_fields(fields, *, mac_algorithm: str | None = None,
                           pin_block_format: str | None = None,
                           link: str | None = None) -> Iso8583Crypto:
    """Inventory the cryptography implied by a declared ISO 8583 field list.

    ``mac_algorithm`` and ``pin_block_format`` are the link's declared settings
    when known; both are cross-checked rather than assumed.
    """
    present, errors = _coerce_fields(fields)
    result = Iso8583Crypto(fields_present=present, errors=errors)

    for num in present:
        if num in CRYPTO_FIELDS:
            name, kind, note = CRYPTO_FIELDS[num]
            result.crypto_fields.append({"field": num, "name": name, "kind": kind, "note": note})
        if num in SENSITIVE_FIELDS:
            result.sensitive_fields.append({"field": num, "name": SENSITIVE_FIELDS[num]})

    result.carries_pin = 52 in present
    result.carries_emv = 55 in present
    result.is_maced = any(f in present for f in _MAC_FIELDS)
    result.carries_cardholder_data = bool(result.sensitive_fields)

    # A PIN-bearing or cardholder-data-bearing link with no MAC field cannot
    # detect tampering in transit. This is the finding most worth surfacing.
    if result.carries_pin and not result.is_maced:
        result.issues.append({
            "severity": "HIGH", "code": "PIN_WITHOUT_MAC",
            "detail": "field 52 carries an enciphered PIN block but neither field 64 "
                      "nor 128 is present, so the message is not authenticated",
        })
    elif result.carries_cardholder_data and not result.is_maced:
        result.issues.append({
            "severity": "MEDIUM", "code": "CARDHOLDER_DATA_WITHOUT_MAC",
            "detail": "the link carries cardholder data with no MAC field",
        })

    if 52 in present and 53 not in present:
        result.issues.append({
            "severity": "LOW", "code": "NO_KEY_MGMT_DECLARATION",
            "detail": "field 52 present without field 53, so the key-management "
                      "scheme for the PIN key is not declared on the link",
        })

    if pin_block_format:
        from payment_crypto.pinblocks import analyse_pin_block_format

        verdict = analyse_pin_block_format(pin_block_format)
        if verdict.block_cipher:
            result.algorithms.append(verdict.block_cipher)
        for issue in verdict.issues:
            result.issues.append({**issue, "source": "field 52 PIN block format"})
        for err in verdict.errors:
            result.errors.append(f"PIN block format: {err}")

    if mac_algorithm:
        alg = mac_algorithm.strip().upper()
        result.algorithms.append(alg)
        # Retail MAC (ISO 9797-1 Algorithm 3) is a DES construction; CMAC/AES is
        # the modern equivalent. Anything DES-based is a scheduled migration.
        if any(tok in alg for tok in ("DES", "X9.19", "X9.9", "ALGORITHM3", "ALGORITHM 3", "RETAIL")):
            result.issues.append({
                "severity": "MEDIUM", "code": "TDES_MAC",
                "detail": f"MAC algorithm {mac_algorithm!r} is a DES/TDES construction; "
                          "AES-CMAC is the migration target",
            })
    elif result.is_maced:
        result.issues.append({
            "severity": "LOW", "code": "MAC_ALGORITHM_UNDECLARED",
            "detail": "a MAC field is present but the MAC algorithm is not declared",
        })

    result.algorithms = sorted(set(a for a in result.algorithms if a))
    if link:
        result.issues = [{**i, "link": link} for i in result.issues]
    return result


def summarise_links(links: list[dict]) -> dict:
    """Roll up many links: ``[{"link": ..., "fields": [...], "mac_algorithm": ...}]``."""
    results = []
    for spec in links:
        verdict = analyse_message_fields(
            spec.get("fields") or [],
            mac_algorithm=spec.get("mac_algorithm"),
            pin_block_format=spec.get("pin_block_format"),
            link=spec.get("link"),
        )
        results.append({
            "link": spec.get("link"),
            "carries_pin": verdict.carries_pin,
            "carries_emv": verdict.carries_emv,
            "is_maced": verdict.is_maced,
            "algorithms": verdict.algorithms,
            "issues": verdict.issues,
            "errors": verdict.errors,
        })
    return {
        "total": len(results),
        "pin_links": sum(1 for r in results if r["carries_pin"]),
        "emv_links": sum(1 for r in results if r["carries_emv"]),
        "unmaced_links": sum(1 for r in results if not r["is_maced"]),
        "links_with_findings": sum(1 for r in results if r["issues"]),
        "results": results,
    }
