"""Hostile values from real source must not abort a whole scan.

Both guards here exist because scanning pyca/cryptography killed a
20,000-file scan outright. Neither failure was a bad *finding* — they were
single values the loader handed to PostgreSQL unmodified, and psycopg
rejected the entire batch insert:

    psycopg2.errors.NumericValueOutOfRange: integer out of range
    psycopg2.errors.UntranslatableCharacter: unsupported Unicode escape
        sequence -- \\u0000 cannot be converted to text

The severity is not the bad value, it is that one file in twenty thousand
takes every other finding down with it. A crypto library is exactly the
corpus that produces both: enormous numeric literals in test vectors, and
binary fixtures containing NUL bytes.

Both also only appear on PostgreSQL. SQLite stores NULs happily and is
loose about integer width, so the suite's default backend cannot see either
one — which is why they survived until a real repository met the database
production mandates.
"""

from __future__ import annotations

import json

import pytest

from db.loader.evidence_loader import (
    MAX_PLAUSIBLE_KEY_BITS,
    _plausible_key_size,
    _strip_nuls,
)

INT32_MAX = 2_147_483_647


# --------------------------------------------------------------------------- #
# key_size
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("value", [None, "", "not-a-number", object()])
def test_unparseable_key_sizes_become_none(value):
    assert _plausible_key_size(value) is None


@pytest.mark.parametrize("value", [0, 128, 256, 2048, 4096, "2048", MAX_PLAUSIBLE_KEY_BITS])
def test_real_key_sizes_survive(value):
    assert _plausible_key_size(value) == int(value)


@pytest.mark.parametrize(
    "value",
    [
        INT32_MAX + 1,          # the exact int4 boundary psycopg rejected
        2 ** 40,
        4294967296,             # a 2**32 literal, the shape a misparse produces
        MAX_PLAUSIBLE_KEY_BITS + 1,
        -1,                     # a negative key size is a parse artefact too
    ],
)
def test_implausible_key_sizes_are_dropped_not_stored(value):
    """Dropping beats crashing: the other findings in the scan still land."""
    assert _plausible_key_size(value) is None


def test_the_ceiling_is_below_the_postgres_integer_bound():
    """Otherwise the guard would pass values the column still cannot hold."""
    assert MAX_PLAUSIBLE_KEY_BITS < INT32_MAX


# --------------------------------------------------------------------------- #
# NUL bytes
# --------------------------------------------------------------------------- #

def test_nul_is_removed_from_a_plain_string():
    assert _strip_nuls("AES\x00KEY") == "AESKEY"


def test_nul_is_removed_from_nested_finding_data():
    """finding_data is jsonb and the snippet sits several levels down."""
    finding = {
        "source": {"code_snippet": "key = b'\\x00'\x00", "file_path": "vectors\x00.txt"},
        "crypto": {"algorithm": "AES"},
        "tags": ["a\x00b", {"deep": "c\x00"}],
    }
    cleaned = _strip_nuls(finding)
    assert "\x00" not in json.dumps(cleaned)
    assert cleaned["crypto"]["algorithm"] == "AES"
    assert cleaned["source"]["file_path"] == "vectors.txt"


def test_values_without_nuls_are_returned_unchanged():
    finding = {"source": {"code_snippet": "AES.new(key)"}, "n": 2048, "ok": True, "x": None}
    assert _strip_nuls(finding) == finding


def test_non_string_scalars_are_left_alone():
    """Stripping must not coerce types; key_size stays an int, flags stay bools."""
    for value in (2048, True, False, None, 3.14):
        assert _strip_nuls(value) is value or _strip_nuls(value) == value


def test_tuples_keep_their_type():
    assert _strip_nuls(("a\x00", "b")) == ("a", "b")
