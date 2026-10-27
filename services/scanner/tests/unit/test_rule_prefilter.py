"""The literal prefilter in rule_engine must never skip a rule that could match."""
import re

import pytest

from scanner.parsers.rule_engine import _may_match, _required_literals, _split_top_level


def test_split_top_level_ignores_nested_alternation():
    assert _split_top_level(r"\bfoo(?:a|b)\(|\bbar\b") == [r"\bfoo(?:a|b)\(", r"\bbar\b"]
    assert _split_top_level(r"[a|b]x|y") == [r"[a|b]x", "y"]


@pytest.mark.parametrize(
    "alt, expected",
    [
        (r"\bhashlib\.sha256\s*\(", {"hashlib", "sha256"}),
        (r"\bLcobucci\\\\JWT\b", {"lcobucci"}),  # JWT is < 4 chars
        (r"\bsha256?\b", {"sha25"}),  # last char optional
        (r"\bmd5(?:_file)?\s*\(", set()),  # md5 < 4 chars; group contents ignored
        (r"(?i)Cipher\.getInstance", {"cipher", "getinstance"}),
        (r"\bfoo\d+barn", {"barn"}),  # "foo" is 3 chars
        (r"\bxtoken*", {"xtoke"}),
        (r"\bxtoken\*", {"xtoken"}),  # escaped star is a literal
    ],
)
def test_required_literals(alt, expected):
    assert _required_literals(alt) == frozenset(expected)


@pytest.mark.parametrize(
    "pattern, text",
    [
        (r"\bhashlib\.sha256\s*\(", "h = hashlib.sha256(b'x')"),
        (r"(?i)\bMessageDigest\.getInstance\s*\(", "MESSAGEDIGEST.GETINSTANCE(\"MD5\")"),
        (r"\bsha256?\b", "use sha25"),
        (r"\bnew\s+(?:Lcobucci\\JWT\\)?Token\\Builder\s*\(", "new Token\\Builder("),
        (r"\bopenssl_encrypt\s*\(|\bmcrypt_encrypt\s*\(", "mcrypt_encrypt($d)"),
    ],
)
def test_prefilter_never_skips_a_real_match(pattern, text):
    compiled = re.compile(pattern)
    assert compiled.search(text) is not None
    assert _may_match(compiled, text.lower())


def test_prefilter_skips_when_literal_is_absent():
    compiled = re.compile(r"\bhashlib\.sha256\s*\(")
    assert not _may_match(compiled, "print('hello')")
