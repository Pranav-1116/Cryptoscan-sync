"""TR-31 / ANSI X9.143 key-block header parsing.

Layout (public, fixed):

==== ========= ==================================================
off  size      field
==== ========= ==================================================
0    2         Version ID        (``B0`` legacy, ``B1``.. binding…)
2    2         Key Usage         (KEK, BDK, ZMK, ZPK, PIN, MAC, CVK, IMK…)
4    2         Algorithm         (TDES, AES, RSA, EC…)
6    1         Mode of Use       (generate, derive, encrypt, verify…)
7    1         Reserved
8    2         Key Version Number
10   1         Exportability
11   1         Reserved
12   4         Optional-blocks length (hex digits)
16   …         Optional blocks (ID(2) + len(4 hex) + value) then key data
==== ========= ==================================================

Only structure is *known*; code tables vary by vendor. The maps below carry
the widely published values and anything unrecognized is surfaced verbatim as
``UNKNOWN(code)`` — never guessed. ``B0`` blocks predate the HMAC binding of
later versions, which is a migration finding on its own.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Best-effort code tables (public/commonly documented values only).
USAGE_NAMES = {
    "00": "KEK",
    "01": "BASE_DERIVATION_KEY",
    "04": "ZONE_MASTER_KEY_ZMK",
    "05": "ZONE_PIN_KEY_ZPK",
    "06": "PIN_VERIFICATION_KEY",
    "07": "CARD_VERIFICATION_KEY_CVK",
    "08": "DATA_ENCRYPTION_KEY",
    "0A": "MAC_GENERATION_KEY",
    "0B": "MAC_VERIFICATION_KEY",
    "0C": "ISSUER_MASTER_KEY_IMK",
    "10": "KEY_AGREEMENT_KEY",
    "18": "INITIAL_PIN_TRANSLATION_KEY",
    "1F": "SUMMIT_KEY_KEK",
    "B0": "BASE_DERIVATION_KEY",
    "B1": "DERIVED_TRANSACTION_KEY",
    "B2": "INITIAL_PIN_TRANSACTION_KEY",
    "D0": "SYMMETRIC_DATA_ENCRYPTION",
    "D1": "ASYMMETRIC_DATA_ENCRYPTION",
    "E0": "EMV_ISSUER_MASTER_KEY",
    "E1": "EMV_ACQUIRER_MASTER_KEY",
}

ALGORITHM_NAMES = {
    "01": "TRIPLE_DES",
    "02": "AES",
    "03": "RSA",
    "04": "ECC",
    "05": "HMAC",
    "10": "AES",
    "11": "TRIPLE_DES",
    "12": "RSA",
    "13": "ECC",
}

MODE_NAMES = {
    "B": "ANY",
    "E": "ENCRYPT",
    "D": "DECRYPT",
    "G": "GENERATE",
    "C": "DERIVE",
    "V": "VERIFY",
    "S": "SIGN",
    "K": "KEY_AGREEMENT",
    "N": "NO_OPERATION",
}

EXPORTABILITY = {
    "E": "EXPORTABLE_ANY",
    "S": "SENSITIVE_EXPORTABLE_KEK_ONLY",
    "N": "NON_EXPORTABLE",
    "T": "TRUSTED_KEEP_WITHIN_HSM",
}


@dataclass
class Tr31Header:
    valid: bool
    version_id: str = ""
    key_usage_code: str = ""
    key_usage: str = ""
    algorithm_code: str = ""
    algorithm: str = ""
    mode_of_use_code: str = ""
    mode_of_use: str = ""
    key_version: str = ""
    exportability_code: str = ""
    exportability: str = ""
    optional_block_ids: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def legacy_binding(self) -> bool:
        """``B0`` key blocks carry no cryptographic binding over key data."""
        return self.valid and self.version_id == "B0"


def _map(table: dict[str, str], code: str) -> str:
    return table.get(code, f"UNKNOWN({code})")


def parse_tr31_header(block: str) -> Tr31Header:
    """Parse the fixed TR-31 header + optional-block IDs from a key block."""
    if not isinstance(block, str) or not block.strip():
        return Tr31Header(valid=False, errors=["empty key block"])
    text = block.strip()
    errors: list[str] = []
    if len(text) < 16:
        errors.append(f"too short for TR-31 header ({len(text)} < 16)")

    header = Tr31Header(
        valid=not errors,
        version_id=text[0:2],
        key_usage_code=text[2:4],
        algorithm_code=text[4:6],
        mode_of_use_code=text[6:7],
        key_version=text[8:10],
        exportability_code=text[10:11],
        errors=errors,
    )
    if not header.valid:
        return header

    header.key_usage = _map(USAGE_NAMES, header.key_usage_code)
    header.algorithm = _map(ALGORITHM_NAMES, header.algorithm_code)
    header.mode_of_use = _map(MODE_NAMES, header.mode_of_use_code)
    header.exportability = _map(EXPORTABILITY, header.exportability_code)

    try:
        opt_len = int(text[12:16], 16)
    except ValueError:
        header.errors.append("optional-block length is not hexadecimal")
        return header

    optional = text[16 : 16 + opt_len]
    if len(optional) < opt_len:
        header.errors.append(f"optional blocks truncated ({len(optional)} < {opt_len})")
    pos = 0
    while pos + 6 <= len(optional):
        block_id = optional[pos : pos + 2]
        try:
            value_len = int(optional[pos + 2 : pos + 6], 16)
        except ValueError:
            header.errors.append(f"optional block {block_id} has bad length")
            break
        header.optional_block_ids.append(block_id)
        pos += 6 + value_len
    if pos != len(optional) and pos + 6 > len(optional) and optional:
        header.errors.append("trailing bytes after last optional block")
    return header
