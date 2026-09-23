"""Deep crypto constant database and the count-based confidence ladder.

Constant-table evidence is the strongest thing a scanner can read out of a
stripped, statically linked binary: symbols are gone, strings may be stripped,
but the AES S-box or the SHA-256 round constants are in the file or they are
not. The upstream fingerprint table carries seven eight-byte prefixes; this
module carries whole tables for the algorithms the platform actually reports,
and grades a match by *how much* of the table is present rather than treating
one hit as proof.

Two design rules, both enforced by tests:

* **Every table is computed from its definition, not transcribed.** The AES
  S-box comes from the GF(2^8) inverse plus the affine transform, the SHA-2
  constants from the fractional parts of the square and cube roots of the first
  primes, MD5's from ``abs(sin(i))``, the Keccak round constants from the LFSR
  in the specification, and Blowfish's P-array/S-boxes from the hexadecimal
  expansion of pi computed with integer arithmetic. A table typed in by hand is
  a table with a typo, and a typo here is a scanner that reports the wrong
  algorithm. The suite recomputes a published digest with the generated
  constants, so a wrong table fails the build instead of shipping.
* **A count is not a claim.** ``scan_constants`` reports the bytes matched, the
  tables matched out of the tables known, and whether a table is *complete*;
  the ladder turns that into a named level with the reason attached. One short
  prefix is ``CONSTANT_WEAK`` and is not allowed to name an algorithm.

Constants are searched in the order a real implementation stores them, which
differs per algorithm (SHA-2 and Blowfish are big-endian, MD5 and BLAKE2
little-endian, Keccak lanes little-endian). Word-based tables also carry a
byte-swapped alias, because an implementation that stores its constants
reversed is still an implementation.

That alias creates a real ambiguity, and the code resolves it rather than
guessing. Some tables are the same words in the other order: MD5's H read
little-endian is SHA-1's H read big-endian, and BLAKE2s's/BLAKE2b's IVs are
SHA-256's/SHA-512's initial values. Those bytes cannot name an algorithm on
their own, so a match that is also another algorithm's canonical table is
reported as ``ambiguous_with`` that algorithm, is kept out of the byte count the
ladder grades, and never reaches the engine that names algorithms. The
tie-breaker is a second table nothing else shares — SHA-256's round constants,
MD5's ``abs(sin)`` constants — which is exactly the kind of corroboration the
ladder is for.
"""

from __future__ import annotations

import hashlib
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator, Mapping

# ------------------------------------------------------------------ limits --- #
MAX_TABLE_MATCHES = 512          # table candidates accepted per call
MAX_REPORTED_TABLES = 64         # rows returned per call
#: the shortest trigger a table may have: eight bytes of a real table is not a
#: guessable coincidence (2^-64), and how much *more* is present is what the
#: ladder grades. ``minimum`` on a table overrides this where the whole table is
#: the trigger (a short constant, a text marker).
TABLE_TRIGGER = 8
#: what a table loaded from an update bundle may claim. The ceiling is a real
#: number of bytes a table can have and still be a *table* — anything larger is a
#: file being smuggled in through the constant database, and would make every scan
#: search for it.
MAX_TABLE_BYTES = 65536
TABLE_KINDS = ("table", "text", "constant")
TABLE_WEIGHTS = ("normal", "low")
#: the shortest trigger a loaded table may declare; below this a "table" is a
#: string, and a string that names an algorithm is a claim this database does not
#: make from eight bytes or fewer
MIN_TABLE_MINIMUM = 4


class TableError(ValueError):
    """A constant table document that cannot be trusted as evidence."""


#: a trigger also has to be *worth* triggering on. Keccak's first round constant
#: is ``01`` followed by seven zeros — eight bytes that occur in padding, in
#: zero-filled structures and in every second Mach-O header. A trigger is
#: therefore extended until it carries at least this many distinct byte values
#: (or the table runs out), so it cannot be a run of zeros with a bit in it.
TRIGGER_MIN_DISTINCT = 6
TRIGGER_MAX = 32


def trigger_length(data: bytes, minimum: int) -> int:
    """The length a candidate must match: long enough to mean something.

    Between the floor and :data:`TRIGGER_MAX` the smallest length carrying enough
    distinct byte values wins. A table whose every prefix is too repetitive to
    discriminate — Keccak's round constants begin ``01`` then seven zero bytes —
    falls back to the whole table, because those bytes only mean anything when
    all of them are present.
    """
    length = max(minimum, TABLE_TRIGGER)
    if length >= len(data):
        return len(data)
    for candidate in range(length, min(len(data), TRIGGER_MAX) + 1):
        if len(set(data[:candidate])) >= TRIGGER_MIN_DISTINCT:
            return candidate
    return len(data)


@dataclass(frozen=True)
class ConstantTable:
    """One named constant table, in the byte order implementations store it."""

    algorithm: str
    table: str
    data: bytes
    minimum: int                 # bytes that must match to be a *candidate*
    kind: str = "table"          # table | text | constant
    weight: str = "normal"       # normal | low  (low can never prove an algorithm)
    aliases: tuple[bytes, ...] = field(default_factory=tuple)
    note: str = ""
    #: where the table came from, when it did not come from this module — a pack
    #: name and version, so evidence resting on it can name its source
    source: str = ""

    @property
    def length(self) -> int:
        return len(self.data)

    @property
    def prefix(self) -> bytes:
        return self.data[:trigger_length(self.data, self.minimum)]


# ------------------------------------------------------- table generation --- #
def _primes(count: int) -> list[int]:
    out: list[int] = []
    candidate = 2
    while len(out) < count:
        if all(candidate % prime for prime in out if prime * prime <= candidate):
            out.append(candidate)
        candidate += 1
    return out


def _root_frac(prime: int, power: int, bits: int) -> int:
    from decimal import Decimal, getcontext

    getcontext().prec = 80
    root = Decimal(prime) ** (Decimal(1) / Decimal(power))
    fraction = root - int(root)
    scaled = int(fraction * (1 << bits))
    return scaled & ((1 << bits) - 1)


def sha256_k() -> bytes:
    """SHA-256 round constants: cube roots of the first 64 primes."""
    return b"".join(_root_frac(prime, 3, 32).to_bytes(4, "big")
                    for prime in _primes(64))


def sha256_h() -> bytes:
    """SHA-256 initial hash values: square roots of the first 8 primes."""
    return b"".join(_root_frac(prime, 2, 32).to_bytes(4, "big")
                    for prime in _primes(8))


def sha512_k() -> bytes:
    """SHA-512 round constants: cube roots of the first 80 primes, 64 bits each."""
    return b"".join(_root_frac(prime, 3, 64).to_bytes(8, "big")
                    for prime in _primes(80))


def sha512_h() -> bytes:
    """SHA-512 initial hash values: square roots of the first 8 primes, 64 bits."""
    return b"".join(_root_frac(prime, 2, 64).to_bytes(8, "big")
                    for prime in _primes(8))


def sha1_h() -> bytes:
    return bytes.fromhex("67452301efcdab8998badcfe10325476c3d2e1f0")


def sha1_k() -> bytes:
    return bytes.fromhex("5a8279996ed9eba18f1bbcdcca62c1d6")


def md5_k() -> bytes:
    """MD5 round constants: ``floor(abs(sin(i + 1)) * 2**32)``, little-endian."""
    import math

    return b"".join(int(abs(math.sin(index + 1)) * (1 << 32)).to_bytes(4, "little")
                    for index in range(64))


def md5_h() -> bytes:
    return bytes.fromhex("0123456789abcdeffedcba9876543210")


def keccak_rc() -> bytes:
    """Keccak-f[1600] round constants, generated by the spec's LFSR."""
    constants: list[int] = []
    lfsr = 1
    for _round in range(24):
        value = 0
        for bit in range(7):
            lfsr, bit_out = ((lfsr << 1) ^ (0x71 if lfsr & 0x80 else 0)) & 0xFF, lfsr & 1
            if bit_out:
                position = (1 << bit) - 1
                value ^= 1 << position
        constants.append(value)
    return b"".join(value.to_bytes(8, "little") for value in constants)


def blake2b_iv() -> bytes:
    """BLAKE2b's IV is SHA-512's initial values (the same words, little-endian)."""
    return b"".join(sha512_h()[index:index + 8][::-1] for index in range(0, 64, 8))


def blake2s_iv() -> bytes:
    """BLAKE2s's IV is SHA-256's initial values (the same words, little-endian)."""
    return b"".join(sha256_h()[index:index + 4][::-1] for index in range(0, 32, 4))


def blake2_sigma() -> bytes:
    """BLAKE2/BLAKE3 message schedule (10 rounds x 16 byte indices)."""
    rows = ((0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
            (14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
            (11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
            (7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
            (9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
            (2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
            (12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
            (13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
            (6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
            (10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0))
    return bytes(index for row in rows for index in row)


def aes_sbox() -> bytes:
    """AES S-box: multiplicative inverse in GF(2^8) plus the affine transform."""
    out = bytearray(256)
    for value in range(256):
        inverse = 0 if value == 0 else _gf_inverse(value)
        rotated = inverse
        for shift in range(1, 5):
            rotated ^= ((inverse << shift) | (inverse >> (8 - shift))) & 0xFF
        out[value] = rotated ^ 0x63
    return bytes(out)


def aes_inverse_sbox() -> bytes:
    sbox = aes_sbox()
    out = bytearray(256)
    for index, value in enumerate(sbox):
        out[value] = index
    return bytes(out)


def _gf_inverse(value: int) -> int:
    """``value ** 254`` in GF(2^8) (the AES field), by square-and-multiply."""
    result, base, exponent = 1, value, 254
    while exponent:
        if exponent & 1:
            result = _gf_mul(result, base)
        base = _gf_mul(base, base)
        exponent >>= 1
    return result


def _gf_mul(left: int, right: int) -> int:
    """Carry-less multiply modulo the AES polynomial 0x11B."""
    product = 0
    while right:
        if right & 1:
            product ^= left
        left <<= 1
        if left & 0x100:
            left ^= 0x11B
        right >>= 1
    return product & 0xFF


def aes_rcon() -> bytes:
    """AES key-schedule round constants (the first 10)."""
    out = bytearray([0x01])
    for _ in range(9):
        previous = out[-1]
        doubled = (previous << 1) & 0xFF
        out.append(doubled ^ (0x1B if previous & 0x80 else 0))
    return bytes(out)


#: two independent identities for pi, so the expansion can be cross-checked
#: against itself: Machin's ``pi/4 = 4*atan(1/5) - atan(1/239)`` and Euler's
#: ``pi/4 = atan(1/2) + atan(1/3)``. They share no arithmetic, so agreement over
#: thousands of digits is evidence the fixed-point code is right.
PI_IDENTITIES: dict[str, tuple[tuple[int, int], ...]] = {
    "machin": ((5, 4), (239, -1)),
    "euler": ((2, 1), (3, 1)),
}


def pi_words(count: int, *, identity: str = "machin") -> list[int]:
    """The first ``count`` 32-bit words of pi's fraction, exactly.

    Evaluated in fixed-point integer arithmetic (``atan`` by its series), so
    every word is exact rather than a float approximation. Verified against the
    published hexadecimal expansion of pi and against the second identity.
    """
    bits = count * 32 + 128
    scale = 1 << bits

    def arctan(inverse: int) -> int:
        total = scale // inverse
        term = total
        square = inverse * inverse
        index, sign = 3, -1
        while term:
            term //= square
            if not term:
                break
            total += sign * (term // index)
            sign = -sign
            index += 2
        return total

    # each identity gives pi/4, so the sum is scaled by four to reach pi
    quarter = sum(multiplier * arctan(inverse)
                  for inverse, multiplier in PI_IDENTITIES[identity])
    fraction = 4 * quarter - 3 * scale
    if fraction < 0:                      # unreachable unless the series is wrong
        raise ValueError("pi expansion produced a negative fraction")
    words = []
    for _ in range(count):
        fraction *= 1 << 32
        word, fraction = divmod(fraction, scale)
        words.append(word)
    return words


#: Blowfish's P-array is the first 18 words of pi's fraction and its S-boxes
#: are the next 1024 — a table nobody should ever hand-type.
def blowfish_p() -> bytes:
    return b"".join(word.to_bytes(4, "big") for word in pi_words(18))


def blowfish_s() -> bytes:
    words = pi_words(18 + 1024)
    return b"".join(word.to_bytes(4, "big") for word in words[18:])


# ------------------------------------------------------------- the library --- #
def _swapped(data: bytes, size: int) -> bytes:
    """Byte-swap every ``size``-byte word — the reversed-order variant."""
    return b"".join(data[index:index + size][::-1] for index in range(0, len(data), size))


def _word_table(algorithm: str, table: str, data: bytes, size: int, *, note: str,
                minimum: int | None = None, weight: str = "normal") -> ConstantTable:
    return ConstantTable(algorithm=algorithm, table=table, data=data,
                         minimum=minimum or min(TABLE_TRIGGER, len(data)),
                         aliases=(_swapped(data, size),), note=note, weight=weight)


def _build_tables() -> tuple[ConstantTable, ...]:
    tables: list[ConstantTable] = [
        ConstantTable("AES", "S-box", aes_sbox(), TABLE_TRIGGER,
                      note="256-byte substitution table"),
        ConstantTable("AES", "inverse S-box", aes_inverse_sbox(), TABLE_TRIGGER,
                      note="256-byte inverse substitution table"),
        ConstantTable("AES", "Rcon", aes_rcon(), 10, kind="constant", weight="low",
                      note="key-schedule round constants (short)"),
        _word_table("SHA-256", "K", sha256_k(), 4,
                    note="64 round constants from cube roots of primes"),
        _word_table("SHA-256", "H", sha256_h(), 4,
                    note="8 initial hash values from square roots of primes"),
        _word_table("SHA-512", "K", sha512_k(), 8,
                    note="80 64-bit round constants"),
        _word_table("SHA-512", "H", sha512_h(), 8,
                    note="8 64-bit initial hash values"),
        _word_table("SHA-1", "H", sha1_h(), 4, note="5 initial hash values"),
        _word_table("SHA-1", "K", sha1_k(), 4, note="4 round constants"),
        _word_table("MD5", "K", md5_k(), 4, note="64 round constants from abs(sin)"),
        _word_table("MD5", "H", md5_h(), 4, note="4 initial hash values"),
        ConstantTable("SHA-3", "round constants", keccak_rc(), TABLE_TRIGGER,
                      aliases=(_swapped(keccak_rc(), 8),),
                      note="24 Keccak-f round constants (little-endian lanes)"),
        ConstantTable("BLAKE2b", "IV", blake2b_iv(), TABLE_TRIGGER,
                      aliases=(sha512_h(),),
                      note="8 64-bit IV words (SHA-512's H, read little-endian)"),
        ConstantTable("BLAKE2s", "IV", blake2s_iv(), TABLE_TRIGGER,
                      aliases=(sha256_h(),),
                      note="8 32-bit IV words (SHA-256's H, read little-endian)"),
        ConstantTable("BLAKE2", "sigma schedule", blake2_sigma(), TABLE_TRIGGER,
                      note="message permutation rows"),
        ConstantTable("Blowfish", "P-array", blowfish_p(), TABLE_TRIGGER,
                      note="18 words of pi's hexadecimal fraction"),
        ConstantTable("Blowfish", "S-boxes", blowfish_s(), TABLE_TRIGGER,
                      note="1024 words of pi's hexadecimal fraction"),
        ConstantTable("ChaCha20", "sigma", b"expand 32-byte k", 16, kind="text",
                      note="ChaCha20/Salsa20 constant text"),
        ConstantTable("BLAKE3", "marker", b"BLAKE3", 6, kind="text", weight="low",
                      note="BLAKE3 appears as a marker, not a constant table"),
        ConstantTable("TEA", "delta", bytes.fromhex("9e3779b9"), 4,
                      kind="constant", weight="low",
                      note="golden-ratio delta — too short to prove anything alone"),
    ]
    return tuple(tables)


def table_digest(table: ConstantTable) -> str:
    """SHA-256 of a table's canonical bytes — how a pack lists what it carries."""
    return hashlib.sha256(table.data).hexdigest()


def constant_table_from_document(document: Mapping[str, Any], *, source: str = "") -> ConstantTable:
    """Build a table from a JSON document, refusing anything it cannot honour.

    Every field is checked against what the scanner actually does, and unknown
    fields are *refused* rather than ignored: a pack author who writes
    ``"mimimum"`` has stated a threshold that will not be applied, and installing
    that quietly would mean the installed evidence no longer says what the file
    says.

    The rules enforce what makes a loaded table worth as much as a built-in one:
    bounded hex bytes, a declared minimum the table can satisfy, and a kind and a
    weight from the vocabularies the confidence ladder understands.
    """
    if not isinstance(document, Mapping):
        raise TableError(f"a table is a JSON object, got {type(document).__name__}")

    known = {"algorithm", "table", "encoding", "bytes", "minimum", "kind", "weight",
             "aliases", "note"}
    unknown = sorted(set(document) - known)
    if unknown:
        raise TableError("unknown field(s) " + ", ".join(repr(key) for key in unknown)
                         + " — a field the scanner does not honour must not be installed")

    if "algorithm" not in document:
        raise TableError("the table has no 'algorithm'")
    if "table" not in document:
        raise TableError("the table has no 'table'")
    algorithm = str(document.get("algorithm") or "").strip()
    name = str(document.get("table") or "").strip()
    for label, value in (("algorithm", algorithm), ("table", name)):
        if not value:
            raise TableError(f"the table has no {label}")
        if len(value) > 64 or not all(character.isprintable() for character in value):
            raise TableError(f"the {label} name must be at most 64 printable characters")

    encoding = str(document.get("encoding") or "").strip().lower()
    if encoding != "hex":
        raise TableError(f"unsupported encoding {encoding!r}: constant tables are hex")

    def _hex(raw: Any, label: str) -> bytes:
        text = str(raw or "").strip().replace(" ", "")
        if not text:
            raise TableError(f"the table has no {label}")
        if len(text) % 2:
            raise TableError(f"{label} has an odd number of hex digits")
        try:
            return bytes.fromhex(text)
        except ValueError as exc:
            raise TableError(f"{label} is not hex: {exc}") from exc

    data = _hex(document.get("bytes"), "bytes")
    if len(data) > MAX_TABLE_BYTES:
        raise TableError(f"the table carries {len(data)} bytes; the ceiling is {MAX_TABLE_BYTES}")

    minimum_raw = document.get("minimum")
    minimum = min(TABLE_TRIGGER, len(data)) if minimum_raw is None else int(minimum_raw)
    if minimum < MIN_TABLE_MINIMUM:
        raise TableError(f"minimum {minimum} is below {MIN_TABLE_MINIMUM}: a trigger that short "
                         "cannot carry evidence")
    if minimum > len(data):
        raise TableError(f"minimum {minimum} exceeds the {len(data)} bytes the table carries")

    kind = str(document.get("kind") or "table").strip()
    if kind not in TABLE_KINDS:
        raise TableError(f"unknown kind {kind!r}: expected one of {', '.join(TABLE_KINDS)}")
    weight = str(document.get("weight") or "normal").strip()
    if weight not in TABLE_WEIGHTS:
        raise TableError(f"unknown weight {weight!r}: expected one of {', '.join(TABLE_WEIGHTS)}")

    aliases_raw = document.get("aliases") or []
    if isinstance(aliases_raw, (str, bytes)) or not isinstance(aliases_raw, Iterable):
        raise TableError("aliases must be a list of hex strings")
    aliases = tuple(_hex(item, "an alias") for item in aliases_raw)
    for alias in aliases:
        if len(alias) != len(data):
            raise TableError(f"an alias is {len(alias)} bytes where the table is {len(data)}: "
                             "aliases are the same table in another storage order")

    note = str(document.get("note") or "").strip()
    if len(note) > 200:
        raise TableError("the note is longer than 200 characters")

    return ConstantTable(algorithm=algorithm, table=name, data=data, minimum=minimum,
                         kind=kind, weight=weight, aliases=aliases, note=note, source=source)


def constant_table_problems(document: Mapping[str, Any], *,
                            existing: Iterable[ConstantTable] | None = None) -> list[str]:
    """Everything wrong with one table document, as reasons.

    Collisions are checked here because they are the failure a signature cannot
    catch: bytes already in the database are evidence for *that* algorithm,
    whoever else claims them. A pack may add evidence, never relabel it.

    ``existing`` defaults to the built-in database — the safe comparison — and a
    caller checking a whole pack passes the built-ins plus the tables already
    accepted from that pack.
    """
    try:
        table = constant_table_from_document(document)
    except TableError as exc:
        return [str(exc)]
    others = constant_tables() if existing is None else tuple(existing)
    problems: list[str] = []
    for other in others:
        if other.algorithm == table.algorithm and other.table == table.table:
            problems.append(f"{table.algorithm}/{table.table} already exists in the database "
                            "and would be shadowed; a pack adds evidence, it does not replace it")
        elif other.data == table.data:
            problems.append(f"these bytes are already the {other.algorithm}/{other.table} table; "
                            "renaming an existing table would make every match ambiguous")
    return problems


_TABLES: tuple[ConstantTable, ...] | None = None


def constant_tables() -> tuple[ConstantTable, ...]:
    """The database, built once (generation is exact but not free)."""
    global _TABLES
    if _TABLES is None:
        _TABLES = _build_tables()
    return _TABLES


#: tables an installed pack adds to the current scan. A context variable rather
#: than an argument threaded through four format parsers: the search is called from
#: inside them, the *set* is a property of the scan, and a token-scoped set cannot
#: leak tables from one scan into the next
_EXTRA_TABLES: ContextVar[tuple[ConstantTable, ...]] = ContextVar("cryptoscan_extra_tables",
                                                                 default=())


@contextmanager
def use_constant_tables(extra: Iterable[ConstantTable]) -> Iterator[tuple[ConstantTable, ...]]:
    """Search ``extra`` tables, plus the built-ins, for the duration of the block."""
    token = _EXTRA_TABLES.set(tuple(extra))
    try:
        yield active_constant_tables()
    finally:
        _EXTRA_TABLES.reset(token)


def active_constant_tables() -> tuple[ConstantTable, ...]:
    """What a scan searches right now: the built-in database plus any added set."""
    return constant_tables() + _EXTRA_TABLES.get()


def tableset_digest(tables: Iterable[ConstantTable]) -> str:
    """Digest of a table set: sorted ``algorithm/table/sha256`` lines, hashed.

    The counterpart of the ruleset digest. A report that says "the AES S-box table
    matched" has to be reproducible, and *which* tables were searched is half of
    what made the match mean something.
    """
    lines = sorted(f"{table.algorithm}/{table.table}/{table_digest(table)}" for table in tables)
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


# ------------------------------------------------------------- the ladder --- #
#: (level, confidence, reason) — highest applicable entry wins
CONSTANT_LEVELS: tuple[tuple[str, float, str], ...] = (
    ("CONSTANT_FULL", 0.95, "two or more complete tables present"),
    ("CONSTANT_COMPLETE", 0.9, "a complete constant table present"),
    ("CONSTANT_STRONG", 0.8, "at least 64 bytes of a constant table present"),
    ("CONSTANT_MODERATE", 0.7, "at least 16 bytes of a constant table present"),
    ("CONSTANT_WEAK", 0.5, "only a short constant or a partial prefix"),
)

#: below this level a match is evidence for the report, not for an algorithm name
NAMING_LEVEL = "CONSTANT_MODERATE"


def level_for(*, bytes_matched: int, full_tables: int) -> tuple[str, float, str]:
    """The count-based ladder: how much of the table is there decides the level."""
    if full_tables >= 2:
        return CONSTANT_LEVELS[0]
    if full_tables == 1:
        return CONSTANT_LEVELS[1]
    if bytes_matched >= 64:
        return CONSTANT_LEVELS[2]
    if bytes_matched >= 16:
        return CONSTANT_LEVELS[3]
    return CONSTANT_LEVELS[4]


def _twin_algorithms(matched: bytes, algorithm: str,
                     canonical: list[tuple[bytes, str, str]]) -> list[str]:
    """Every other algorithm whose canonical table starts with exactly these bytes."""
    if len(matched) < TABLE_TRIGGER:
        return []
    return sorted({other for data, other, _table in canonical
                   if other != algorithm and data.startswith(matched)})


def _match_length(window: bytes, start: int, table: bytes) -> int:
    """Bytes of ``table`` present from ``start`` (bounded by the table length)."""
    chunk = window[start:start + len(table)]
    if chunk == table:
        return len(table)
    length = 0
    for index, value in enumerate(chunk):
        if value != table[index]:
            break
        length += 1
    return length


def scan_constants(windows: Iterable[tuple[str, bytes]], *,
                   tables: tuple[ConstantTable, ...] | None = None) -> dict[str, Any]:
    """Search named sections for known constant tables, with counts.

    ``windows`` is ``(section_name, bytes)`` pairs. Each table is searched for
    its canonical serialisation and its byte-swapped alias. A candidate records
    how many bytes matched, whether the table is complete and where it was
    found; the *level* then follows from those counts, not from the fact of a
    hit — a two-word prefix and a full 256-byte S-box are not the same evidence.

    With no explicit ``tables``, the search uses the active set — the built-in
    database plus whatever a scan added with ``use_constant_tables`` — so a search
    inside a packaged scan cannot accidentally run on the built-ins alone.
    """
    table_list = active_constant_tables() if tables is None else tables
    window_list = [(name, data) for name, data in windows if data]
    #: canonical bytes of every table, as a list — two tables can hold identical
    #: bytes (that is the whole point), so a dict keyed by the bytes would silently
    #: drop one of them and report the ambiguity on one side only
    canonical: list[tuple[bytes, str, str]] = [(table.data, table.algorithm, table.table)
                                              for table in table_list]
    results: dict[tuple[str, str], dict[str, Any]] = {}
    searched = 0
    candidates = 0
    for name, window in window_list:
        searched += len(window)
        for table in table_list:
            if candidates >= MAX_TABLE_MATCHES:
                break
            index = window.find(table.prefix)
            serialisation, byte_swapped = table.data, False
            if index < 0:
                for alias in table.aliases:
                    if not alias:
                        continue
                    index = window.find(alias[:len(table.prefix)])
                    if index >= 0:
                        serialisation, byte_swapped = alias, True
                        break
            if index < 0:
                continue
            candidates += 1
            key = (table.algorithm, table.table)
            if key in results:
                continue
            matched = _match_length(window, index, serialisation)
            # Some tables are shared outright. MD5's H read little-endian is
            # SHA-1's H read big-endian; SHA-256's H is BLAKE2s's IV and SHA-512's
            # H is BLAKE2b's IV, because those are the same words in the other
            # byte order. Neither algorithm can be claimed from those bytes — the
            # tie-breaker is a second table (SHA-256's K, MD5's K), which nothing
            # else shares. The comparison uses the bytes that actually matched,
            # because the two tables are not always the same length.
            ambiguous_with = _twin_algorithms(serialisation[:matched], table.algorithm,
                                              canonical)
            results[key] = {
                "algorithm": table.algorithm, "table": table.table, "section": name,
                "offset": int(index), "bytes_matched": int(matched),
                "table_bytes": table.length, "minimum": table.minimum,
                "kind": table.kind, "weight": table.weight,
                "complete": matched >= table.length,
                "ratio": round(matched / table.length, 3) if table.length else 0.0,
                "byte_swapped_storage": byte_swapped,
                "ambiguous_with": ambiguous_with,
                "note": table.note or None,
                # which table set this row rests on: a built-in, or a pack that an
                # operator installed across the air gap
                "source": table.source or None,
            }

    rows = sorted(results.values(),
                  key=lambda row: (-row["bytes_matched"], row["algorithm"], row["table"]))
    by_algorithm: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_algorithm.setdefault(row["algorithm"], []).append(row)

    known = {table.algorithm: 0 for table in table_list}
    for table in table_list:
        known[table.algorithm] += 1

    algorithms: dict[str, dict[str, Any]] = {}
    partials: list[dict[str, Any]] = []
    engine_blobs: list[bytes] = []
    for algorithm, algorithm_rows in sorted(by_algorithm.items()):
        strong = [row for row in algorithm_rows
                  if row["weight"] != "low" and not row["ambiguous_with"]]
        ambiguous = [row for row in algorithm_rows if row["ambiguous_with"]]
        byte_count = sum(row["bytes_matched"] for row in strong)
        full = sum(1 for row in strong if row["complete"])
        level, confidence, reason = level_for(bytes_matched=byte_count, full_tables=full)
        # a lone short constant never names an algorithm, and neither does a table
        # whose bytes are equally consistent with another algorithm's constants
        if not strong or byte_count < 16:
            level, confidence, reason = CONSTANT_LEVELS[-1]
            if ambiguous and not strong:
                twins = sorted({name for row in ambiguous for name in row["ambiguous_with"]})
                reason = ("the bytes are also the constants of " + " or ".join(twins)
                          + " read in the opposite byte order — the file alone cannot say which")
                for row in ambiguous:
                    row["note"] = reason
        algorithms[algorithm] = {
            "tables_matched": len(algorithm_rows), "tables_known": known.get(algorithm, 0),
            "complete_tables": full, "bytes_matched": byte_count,
            "ambiguous_tables": len(ambiguous),
            "ambiguous_with": sorted({name for row in ambiguous for name in row["ambiguous_with"]}),
            "level": level, "confidence": confidence, "reason": reason,
            "tables": [{"table": row["table"], "section": row["section"],
                        "offset": row["offset"], "bytes_matched": row["bytes_matched"],
                        "table_bytes": row["table_bytes"], "complete": row["complete"],
                        "byte_swapped_storage": row["byte_swapped_storage"],
                        "ambiguous_with": row["ambiguous_with"]}
                       for row in algorithm_rows],
        }
        if level == "CONSTANT_WEAK":
            partials.extend(algorithm_rows)
            continue
        for row in algorithm_rows:
            if row["complete"]:
                table = next((item for item in table_list
                              if item.algorithm == algorithm and item.table == row["table"]), None)
                if table is not None:
                    engine_blobs.append(table.data)
    partials.sort(key=lambda row: (-row["bytes_matched"], row["algorithm"]))

    return {
        "searched_bytes": searched,
        "tables": rows[:MAX_REPORTED_TABLES],
        "algorithms": algorithms,
        "partials": partials[:MAX_REPORTED_TABLES],
        # complete tables are handed to the shared engine both whole and as the
        # eight-byte prefixes its table uses, so its CONSTANT_MATCH fires only
        # when the whole table really is there
        "engine_blobs": engine_blobs,
        "engine_prefixes": [blob[:8] for blob in engine_blobs],
        "truncated": candidates >= MAX_TABLE_MATCHES,
        "tables_in_use": len(table_list),
        "installed_tables": sum(1 for table in table_list if table.source),
        "tableset_digest": tableset_digest(table_list),
        "sources": sorted({table.source for table in table_list if table.source}),
        "note": _catalogue_note(table_list),
    }


def _catalogue_note(tables: Iterable[ConstantTable] | None = None) -> str:
    """What this catalogue covers — stated, so absence is not read as cleanliness."""
    table_list = tuple(tables) if tables is not None else constant_tables()
    families = sorted({table.algorithm for table in table_list})
    installed = sorted({table.source for table in table_list if table.source})
    note = ("constant tables are held for " + ", ".join(families)
            + "; an algorithm outside this list is not searched for by table, "
              "and its absence from the evidence is not evidence of absence")
    if installed:
        note += ("; tables from installed packs are included: " + ", ".join(installed))
    return note


def table_catalogue(tables: Iterable[ConstantTable] | None = None) -> list[dict[str, Any]]:
    """The database itself, for the API to expose and a reviewer to inspect."""
    table_list = tuple(tables) if tables is not None else constant_tables()
    return [{"algorithm": table.algorithm, "table": table.table, "bytes": table.length,
             "minimum": table.minimum, "kind": table.kind, "weight": table.weight,
             "aliases": len([alias for alias in table.aliases if alias]),
             "sha256": table_digest(table), "note": table.note or None,
             "source": table.source or None}
            for table in table_list]
