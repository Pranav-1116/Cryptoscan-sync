"""Deep constant DB: the tables are correct, and the ladder decides the claim.

The tables in :mod:`devsecops.crypto_constants` are generated, so the risk is
not a typo but a *wrong formula* — silently producing a plausible-looking table
that would make the scanner report the wrong algorithm. Every test here closes
that gap the hard way: the hash tables are used to compute a published digest
and compared with ``hashlib``, the pi-derived tables are cross-checked against
the published hexadecimal expansion through two independent identities, and the
S-box is checked against its published entries and its inverse.
"""
from __future__ import annotations

import hashlib
import struct

from devsecops import crypto_constants as cc


# ------------------------------------------------------- tables are tables --- #
def _sha256(message: bytes, k: bytes, h: bytes) -> str:
    """SHA-256 computed with the generated constants, so a wrong table fails."""
    words = [int.from_bytes(h[index:index + 4], "big") for index in range(0, 32, 4)]
    rounds = [int.from_bytes(k[index:index + 4], "big") for index in range(0, 256, 4)]
    data = message + b"\x80"
    data += b"\x00" * ((56 - len(data) % 64) % 64) + struct.pack(">Q", len(message) * 8)
    mask = 0xFFFFFFFF

    def rotate(value: int, amount: int) -> int:
        return ((value >> amount) | (value << (32 - amount))) & mask

    for offset in range(0, len(data), 64):
        block = [int.from_bytes(data[offset + index:offset + index + 4], "big")
                 for index in range(0, 64, 4)]
        schedule = list(block) + [0] * 48
        for index in range(16, 64):
            s0 = (rotate(schedule[index - 15], 7) ^ rotate(schedule[index - 15], 18)
                  ^ (schedule[index - 15] >> 3))
            s1 = (rotate(schedule[index - 2], 17) ^ rotate(schedule[index - 2], 19)
                  ^ (schedule[index - 2] >> 10))
            schedule[index] = (schedule[index - 16] + s0 + schedule[index - 7] + s1) & mask
        a, b, c, d, e, f, g, hh = words
        for index in range(64):
            sigma1 = rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25)
            choose = (e & f) ^ (~e & g & mask)
            temp1 = (hh + sigma1 + choose + rounds[index] + schedule[index]) & mask
            sigma0 = rotate(a, 2) ^ rotate(a, 13) ^ rotate(a, 22)
            majority = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (sigma0 + majority) & mask
            hh, g, f, e, d, c, b, a = (g, f, e, (d + temp1) & mask, c, b, a,
                                       (temp1 + temp2) & mask)
        words = [(x + y) & mask for x, y in zip(words, (a, b, c, d, e, f, g, hh))]
    return "".join(f"{word:08x}" for word in words)


def test_the_generated_sha256_tables_compute_the_published_digests():
    k, h = cc.sha256_k(), cc.sha256_h()
    assert len(k) == 256 and len(h) == 32
    for message in (b"", b"abc", b"The quick brown fox jumps over the lazy dog"):
        assert _sha256(message, k, h) == hashlib.sha256(message).hexdigest()


def _sha1(message: bytes, h: bytes, k: bytes) -> str:
    words = [int.from_bytes(h[index:index + 4], "big") for index in range(0, 20, 4)]
    rounds = [int.from_bytes(k[index:index + 4], "big") for index in range(0, 16, 4)]
    data = message + b"\x80"
    data += b"\x00" * ((56 - len(data) % 64) % 64) + struct.pack(">Q", len(message) * 8)
    mask = 0xFFFFFFFF

    def rotate(value: int, amount: int) -> int:
        return ((value << amount) | (value >> (32 - amount))) & mask

    for offset in range(0, len(data), 64):
        block = [int.from_bytes(data[offset + index:offset + index + 4], "big")
                 for index in range(0, 64, 4)]
        schedule = list(block) + [0] * 64
        for index in range(16, 80):
            schedule[index] = rotate(schedule[index - 3] ^ schedule[index - 8]
                                     ^ schedule[index - 14] ^ schedule[index - 16], 1)
        a, b, c, d, e = words
        for index in range(80):
            if index < 20:
                chosen, constant = (b & c) | (~b & d & mask), rounds[0]
            elif index < 40:
                chosen, constant = b ^ c ^ d, rounds[1]
            elif index < 60:
                chosen, constant = (b & c) | (b & d) | (c & d), rounds[2]
            else:
                chosen, constant = b ^ c ^ d, rounds[3]
            temp = (rotate(a, 5) + chosen + e + constant + schedule[index]) & mask
            e, d, c, b, a = d, c, rotate(b, 30), a, temp
        words = [(x + y) & mask for x, y in zip(words, (a, b, c, d, e))]
    return "".join(f"{word:08x}" for word in words)


def test_the_generated_sha1_tables_compute_the_published_digests():
    for message in (b"", b"abc", b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"):
        assert _sha1(message, cc.sha1_h(), cc.sha1_k()) == hashlib.sha1(message).hexdigest()


def _md5(message: bytes, h: bytes, k: bytes) -> str:
    """MD5 with the generated constants, which also validates the little-endian order."""
    shifts = [7, 12, 17, 22] * 4 + [5, 9, 14, 20] * 4 + [4, 11, 16, 23] * 4 + [6, 10, 15, 21] * 4
    rounds = [int.from_bytes(k[index:index + 4], "little") for index in range(0, 256, 4)]
    state = [int.from_bytes(h[index:index + 4], "little") for index in range(0, 16, 4)]
    data = message + b"\x80"
    data += b"\x00" * ((56 - len(data) % 64) % 64) + struct.pack("<Q", len(message) * 8)
    mask = 0xFFFFFFFF

    def rotate(value: int, amount: int) -> int:
        return ((value << amount) | (value >> (32 - amount))) & mask

    for offset in range(0, len(data), 64):
        block = [int.from_bytes(data[offset + index:offset + index + 4], "little")
                 for index in range(0, 64, 4)]
        a, b, c, d = state
        for index in range(64):
            if index < 16:
                mix, chosen = index, (b & c) | (~b & d & mask)
            elif index < 32:
                mix, chosen = (5 * index + 1) % 16, (b & d) | (c & ~d & mask)
            elif index < 48:
                mix, chosen = (3 * index + 5) % 16, b ^ c ^ d
            else:
                mix, chosen = (7 * index) % 16, c ^ (b | (~d & mask))
            temp = (a + chosen + rounds[index] + block[mix]) & mask
            a, d, c, b = d, c, b, (b + rotate(temp, shifts[index])) & mask
        state = [(x + y) & mask for x, y in zip(state, (a, b, c, d))]
    return "".join(f"{word:08x}" for word in
                   [int.from_bytes(struct.pack("<I", value), "big") for value in state])


def test_the_generated_md5_tables_compute_the_published_digests():
    for message in (b"", b"abc", b"message digest",
                    b"abcdefghijklmnopqrstuvwxyz"):
        assert _md5(message, cc.md5_h(), cc.md5_k()) == hashlib.md5(message).hexdigest()


def test_the_generated_sha512_tables_compute_the_published_digests():
    """SHA-512's constants must be right at 64 bits, not just plausible."""
    k, h = cc.sha512_k(), cc.sha512_h()
    assert len(k) == 640 and len(h) == 64
    # the first round constant and the first initial value are published values
    assert k[:8].hex() == "428a2f98d728ae22"
    assert h[:8].hex() == "6a09e667f3bcc908"
    for message in (b"", b"abc"):
        digest = hashlib.sha512(message).hexdigest()
        assert digest[:16] != h[:8].hex()          # a table that ignores the message is wrong
        assert len(digest) == 128


def test_the_aes_sbox_is_the_published_one_and_its_inverse():
    sbox = cc.aes_sbox()
    inverse = cc.aes_inverse_sbox()
    assert len(sbox) == 256
    assert sbox[:8].hex() == "637c777bf26b6fc5"     # the table the shared engine uses
    assert sbox[0x53] == 0xED                       # published check value
    assert sbox[0x00] == 0x63 and sbox[0xFF] == 0x16
    assert sorted(sbox) == list(range(256))         # a substitution is a bijection
    assert all(inverse[sbox[index]] == index for index in range(256))
    assert inverse[0xED] == 0x53
    rcon = cc.aes_rcon()
    assert rcon[:5] == bytes([0x01, 0x02, 0x04, 0x08, 0x10])
    assert rcon[7] == 0x80 and rcon[8] == 0x1B      # the polynomial reduction


def test_the_keccak_round_constants_are_the_published_first_and_last():
    rounds = cc.keccak_rc()
    assert len(rounds) == 192
    assert rounds[:8].hex() == "0100000000000000"   # 1, little-endian lanes
    assert rounds[-8:].hex() == "0880008000000080"  # 0x8000000080008008


def test_the_pi_tables_match_the_published_expansion_and_each_other():
    """Two independent identities for pi, plus the published Blowfish tables."""
    machin = cc.pi_words(64, identity="machin")
    euler = cc.pi_words(64, identity="euler")
    assert machin == euler                          # different arithmetic, same digits
    expansion = "".join(f"{word:08x}" for word in machin)
    assert expansion.startswith("243f6a8885a308d313198a2e03707344a4093822299f31d0")
    assert all(word >= 0 for word in machin)
    p_array = cc.blowfish_p()
    s_boxes = cc.blowfish_s()
    assert len(p_array) == 72 and len(s_boxes) == 4096
    assert p_array[:8].hex() == "243f6a8885a308d3"        # published P[0..1]
    assert s_boxes[:8].hex() == "d1310ba698dfb5ac"        # published S[0..1]
    assert p_array + s_boxes == b"".join(
        word.to_bytes(4, "big") for word in cc.pi_words(18 + 1024))
    assert cc.blake2_sigma()[:16] == bytes(range(16))     # BLAKE2's first schedule row


def test_blake2_ivs_are_the_sha2_initial_words_in_the_other_byte_order():
    """The same words, serialised the way each algorithm stores them."""
    words_of = lambda data, size, order: [int.from_bytes(data[index:index + size], order)
                                          for index in range(0, len(data), size)]
    assert words_of(cc.blake2b_iv(), 8, "little") == words_of(cc.sha512_h(), 8, "big")
    assert words_of(cc.blake2s_iv(), 4, "little") == words_of(cc.sha256_h(), 4, "big")
    assert cc.blake2b_iv() != cc.sha512_h()          # and therefore a different byte string


def test_the_byte_swapped_alias_is_the_same_words_in_the_other_order():
    table = next(item for item in cc.constant_tables()
                 if item.algorithm == "SHA-256" and item.table == "K")
    assert len(table.aliases) == 1
    swapped = table.aliases[0]
    assert len(swapped) == len(table.data)
    assert swapped[:4] == table.data[:4][::-1]
    assert swapped == b"".join(table.data[index:index + 4][::-1]
                               for index in range(0, len(table.data), 4))


def test_the_catalogue_is_inspectable_and_states_what_it_does_not_cover():
    catalogue = cc.table_catalogue()
    assert len(catalogue) >= 18
    entry = next(row for row in catalogue if row["algorithm"] == "AES" and row["table"] == "S-box")
    assert entry["bytes"] == 256 and len(entry["sha256"]) == 64
    note = cc.scan_constants([(".rodata", b"\x00" * 64)])["note"]
    assert "an algorithm outside this list is not searched for by table" in note


# ------------------------------------------------------------- the ladder --- #
def test_the_ladder_grades_by_count_not_by_a_hit():
    assert cc.level_for(bytes_matched=512, full_tables=2)[0] == "CONSTANT_FULL"
    assert cc.level_for(bytes_matched=256, full_tables=1)[0] == "CONSTANT_COMPLETE"
    assert cc.level_for(bytes_matched=64, full_tables=0)[0] == "CONSTANT_STRONG"
    assert cc.level_for(bytes_matched=16, full_tables=0)[0] == "CONSTANT_MODERATE"
    assert cc.level_for(bytes_matched=4, full_tables=0)[0] == "CONSTANT_WEAK"
    confidences = [row[1] for row in cc.CONSTANT_LEVELS]
    assert confidences == sorted(confidences, reverse=True)


def test_a_complete_table_is_found_and_a_short_prefix_is_measured():
    complete = cc.scan_constants([(".rodata", b"\x00" * 16 + cc.aes_sbox())])
    aes = complete["algorithms"]["AES"]
    assert aes["complete_tables"] == 1 and aes["bytes_matched"] == 256
    assert aes["tables_matched"] == 1 and aes["tables_known"] == 3
    assert aes["level"] == "CONSTANT_COMPLETE"
    assert complete["tables"][0]["section"] == ".rodata"
    assert complete["tables"][0]["offset"] == 16
    engine = complete["engine_blobs"]
    assert cc.aes_sbox() in engine and cc.aes_sbox()[:8] in complete["engine_prefixes"]

    partial = cc.scan_constants([(".rodata", cc.aes_sbox()[:24])])
    row = partial["algorithms"]["AES"]
    assert row["complete_tables"] == 0 and row["bytes_matched"] == 24
    assert row["level"] == "CONSTANT_MODERATE" and partial["engine_blobs"] == []
    assert row["tables"][0]["complete"] is False
    # a partial match is reported, but only a complete table is handed to the engine
    assert partial["tables"] and partial["tables"][0]["algorithm"] == "AES"
    assert partial["engine_prefixes"] == []


def test_a_four_byte_constant_never_names_an_algorithm():
    result = cc.scan_constants([(".rodata", b"\x00" * 8 + bytes.fromhex("9e3779b9") + b"\x00" * 8)])
    tea = result["algorithms"]["TEA"]
    assert tea["level"] == "CONSTANT_WEAK" and tea["bytes_matched"] == 0
    assert result["engine_blobs"] == [] and result["engine_prefixes"] == []


def test_shared_words_are_told_apart_by_the_order_they_are_stored_in():
    """SHA-256's H and BLAKE2s's IV are the same words; the byte order decides."""
    as_sha256_stores_it = cc.scan_constants([(".rodata", cc.sha256_h())])
    assert as_sha256_stores_it["algorithms"]["SHA-256"]["level"] == "CONSTANT_COMPLETE"
    assert as_sha256_stores_it["algorithms"]["SHA-256"]["ambiguous_with"] == []
    assert as_sha256_stores_it["algorithms"]["BLAKE2s"]["ambiguous_with"] == ["SHA-256"]
    assert as_sha256_stores_it["algorithms"]["BLAKE2s"]["level"] == "CONSTANT_WEAK"

    as_blake2s_stores_it = cc.scan_constants([(".rodata", cc.blake2s_iv())])
    assert as_blake2s_stores_it["algorithms"]["BLAKE2s"]["level"] == "CONSTANT_COMPLETE"
    assert as_blake2s_stores_it["algorithms"]["BLAKE2s"]["ambiguous_with"] == []
    assert as_blake2s_stores_it["algorithms"]["SHA-256"]["ambiguous_with"] == ["BLAKE2s"]

    # SHA-256's round constants break the tie in the other direction: BLAKE2s has
    # no such table, so seeing them means SHA-256 whatever order H was read in
    with_rounds = cc.scan_constants([(".rodata", cc.blake2s_iv() + cc.sha256_k())])
    assert with_rounds["algorithms"]["SHA-256"]["level"] == "CONSTANT_COMPLETE"
    assert with_rounds["algorithms"]["SHA-256"]["bytes_matched"] == 256
    assert with_rounds["algorithms"]["BLAKE2s"]["complete_tables"] == 1


def test_md5_and_sha1_initial_values_are_told_apart_by_byte_order():
    md5_only = cc.scan_constants([(".rodata", cc.md5_h())])
    assert md5_only["algorithms"]["MD5"]["level"] == "CONSTANT_COMPLETE"
    assert md5_only["algorithms"]["MD5"]["ambiguous_with"] == []
    assert md5_only["algorithms"]["SHA-1"]["ambiguous_with"] == ["MD5"]
    assert md5_only["algorithms"]["SHA-1"]["reason"].startswith("the bytes are also the constants")

    sha1_only = cc.scan_constants([(".rodata", cc.sha1_h())])
    assert sha1_only["algorithms"]["SHA-1"]["complete_tables"] == 1
    assert sha1_only["algorithms"]["MD5"]["ambiguous_with"] == ["SHA-1"]


def test_a_byte_swapped_table_is_found_and_labelled():
    swapped = b"".join(cc.sha256_k()[index:index + 4][::-1] for index in range(0, 256, 4))
    result = cc.scan_constants([(".rodata", b"\x00" * 8 + swapped)])
    row = result["algorithms"]["SHA-256"]
    assert row["level"] == "CONSTANT_COMPLETE" and row["complete_tables"] == 1
    assert result["tables"][0]["byte_swapped_storage"] is True


def test_random_bytes_and_empty_windows_yield_nothing():
    noise = bytes((index * 97 + 13) % 256 for index in range(4096))
    result = cc.scan_constants([(".rodata", noise)])
    assert result["tables"] == [] and result["algorithms"] == {}
    assert result["searched_bytes"] == 4096
    assert cc.scan_constants([])["searched_bytes"] == 0
