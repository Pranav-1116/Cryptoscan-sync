"""A YARA subset, implemented so rules run air-gapped and every match explains itself.

This is **not** YARA — it is a documented subset, parsed and evaluated in pure
Python, because the platform must run with no network and no C toolchain. What it
supports is written down here and enforced by tests:

* ``private`` rules (evaluated, matched, never reported on their own).
* ``meta:`` with string, integer and boolean values; the first ``severity`` key
  becomes the finding's severity, everything else is carried as evidence.
* ``strings:`` three kinds:
  - text ``"..."`` with ``nocase``, ``wide`` (UTF-16LE), ``ascii``, ``fullword``;
  - hex ``{ 63 7C ?? [4-6] ( 01 | 02 ) }`` with single-nibble wildcards, jumps and
    alternatives (compiled to a regular expression, so the semantics are Python's);
  - regex ``/.../`` with ``nocase``/``wide`` — Python's regular expression syntax,
    not PCRE, and that difference is real: a rule that uses a construct Python
    cannot compile is reported as a rule error, never silently skipped.
* ``condition:`` with ``any of them`` / ``all of them`` / ``N of them`` /
  ``any of ($prefix*)``, ``$a``, ``#a``, ``@a``, ``filesize``, integer and boolean
  comparisons, ``and`` / ``or`` / ``not`` and parentheses.

What it does **not** support is refused loudly: ``for`` loops, ``of`` against rule
sets, ``xor``/``base64``/``base64wide`` modifiers, ``at``/``in`` operators, math
modules, external variables and includes. A rule that uses one of them is dropped
**with a reported error** — a rule engine that silently ignores half a rule is
worse than no rule engine, because the report reads as "checked and clean".

Every match reports the rule, its namespace, tags, the meta that made it, the
string identifiers that fired with their offsets and counts, and the digest of the
rule text that produced it — so a finding can be reproduced from the rules alone.
Files larger than :data:`MAX_SCAN_BYTES` are matched against a prefix, and the
result says the scan was truncated.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

#: how much of a file the engine reads. A match is a byte pattern; a prefix that
#: stops is reported as a truncated scan, never as "no match".
MAX_SCAN_BYTES = 64 * 1024 * 1024
#: occurrences recorded per string (the count stays exact, the offsets are capped)
MAX_OFFSETS_PER_STRING = 32
#: offsets recorded per rule across all of its strings
MAX_OFFSETS_PER_RULE = 256
#: highest jump a hex pattern may use, matching YARA's own bound
MAX_HEX_JUMP = 2000
#: rules compiled from one bundle before it is refused as unreasonable
MAX_RULES = 5000

class YaraError(Exception):
    """A rule could not be parsed or compiled. Never swallowed silently."""


# --------------------------------------------------------------------------- #
# patterns
# --------------------------------------------------------------------------- #

@dataclass
class TextPattern:
    """A literal string, optionally case-insensitive, wide, and word-bounded."""

    text: bytes
    nocase: bool = False
    wide: bool = False
    ascii: bool = False
    fullword: bool = False

    def variants(self) -> list[bytes]:
        """The byte sequences to search for — ``wide`` is UTF-16LE interleaved."""
        raw = self.text
        sequences: list[bytes] = []
        if self.wide:
            sequences.append(b"".join(bytes((byte, 0)) for byte in raw))
        if self.ascii or not self.wide:
            sequences.append(raw)
        return sequences

    def find(self, data: bytes, lower: bytes | None) -> tuple[list[int], int]:
        """All offsets (bounded) and the exact occurrence count."""
        offsets: list[int] = []
        count = 0
        for sequence in self.variants():
            needle = sequence.lower() if self.nocase else sequence
            haystack = lower if (self.nocase and lower is not None) else data
            start = 0
            while True:
                index = haystack.find(needle, start)
                if index < 0:
                    break
                if not self.fullword or _is_word_bounded(data, index, len(needle)):
                    count += 1
                    if len(offsets) < MAX_OFFSETS_PER_STRING:
                        offsets.append(index)
                start = index + 1
        return sorted(offsets), count


@dataclass
class RegexPattern:
    """A regular expression, compiled from YARA ``/.../`` syntax or a hex block."""

    source: str
    pattern: re.Pattern[bytes]
    bytes_source: bytes = b""
    nocase: bool = False
    wide: bool = False
    kind: str = "regex"

    def find(self, data: bytes, _lower: bytes | None) -> tuple[list[int], int]:
        offsets: list[int] = []
        count = 0
        for match in self.pattern.finditer(data):
            count += 1
            if len(offsets) < MAX_OFFSETS_PER_STRING:
                offsets.append(match.start())
        return offsets, count


_WORD = re.compile(rb"[A-Za-z0-9_]")


def _is_word_bounded(data: bytes, index: int, length: int) -> bool:
    before = data[index - 1:index] if index else b""
    after = data[index + length:index + length + 1]
    return not _WORD.match(before or b"") and not _WORD.match(after or b"")


# --------------------------------------------------------------------------- #
# tokenizer and parser
# --------------------------------------------------------------------------- #

_TOKEN = re.compile(rb"""
    (?P<space>\s+)
  | (?P<comment>//[^\n]*|/\*.*?\*/)
  | (?P<regex>/(?:\\.|[^/\\\n])+/[a-z]*)
  | (?P<string>"(?:\\.|[^"\\])*")
  | (?P<ident>[A-Za-z_][A-Za-z0-9_]*)
  | (?P<number>0x[0-9A-Fa-f]+|\d+(?:KB|MB|kb|mb)?)
  | (?P<op>[$#@][A-Za-z0-9_*]*|[{}:()\[\],|=<>!?+\-*/.]+)
""", re.VERBOSE | re.DOTALL)


@dataclass
class _Token:
    kind: str
    value: bytes
    line: int
    start: int = 0
    end: int = 0


def _tokenize(text: str) -> list[_Token]:
    raw = text.encode("utf-8", "replace")
    tokens: list[_Token] = []
    position = 0
    while position < len(raw):
        match = _TOKEN.match(raw, position)
        if match is None:
            raise YaraError(f"unexpected character at offset {position}: {raw[position:position + 20]!r}")
        position = match.end()
        kind = match.lastgroup or ""
        if kind in ("space", "comment"):
            continue
        tokens.append(_Token(kind, match.group(), raw[:match.start()].count(b"\n") + 1,
                             match.start(), match.end()))
    return tokens


def _unquote(text: bytes) -> bytes:
    body = text[1:-1]
    out = bytearray()
    index = 0
    while index < len(body):
        char = body[index]
        if char == 0x5C and index + 1 < len(body):          # backslash
            nxt = body[index + 1]
            out.append({0x6E: 0x0A, 0x74: 0x09, 0x72: 0x0D, 0x30: 0x00}.get(nxt, nxt))
            index += 2
            continue
        out.append(char)
        index += 1
    return bytes(out)


class _Parser:
    def __init__(self, text: str, source: str) -> None:
        self.tokens = _tokenize(text)
        self.position = 0
        self.source = source
        self.raw = text.encode("utf-8", "replace")

    # -- helpers ----------------------------------------------------------- #
    def peek(self, offset: int = 0) -> _Token | None:
        index = self.position + offset
        return self.tokens[index] if index < len(self.tokens) else None

    def collect_hex_block(self, opening: _Token) -> bytes:
        """Take the text of ``{ 63 7C ?? [4-6] ( 01 | 02 ) }`` verbatim.

        The tokenizer cannot know a hex block from a rule body — both are
        ``{ ... }`` — so the block is sliced out of the source here, where the
        grammar already knows a pattern is expected. Slicing keeps the byte
        boundaries the rule author wrote (``7C`` is one token in the source, but
        two on the way through the tokenizer).
        """
        line = opening.line
        start = opening.start
        depth = 1
        end = opening.end
        while True:
            token = self.peek()
            if token is None:
                raise YaraError(f"{self.source}:{line}: unterminated hex block")
            self.position += 1
            if token.value == b"{":
                depth += 1
            elif token.value == b"}":
                depth -= 1
                if depth == 0:
                    end = token.end
                    break
        return self.raw[start:end]

    def next(self) -> _Token:
        token = self.peek()
        if token is None:
            raise YaraError(f"{self.source}: unexpected end of rules")
        self.position += 1
        return token

    def expect(self, value: bytes) -> _Token:
        token = self.next()
        if token.value != value:
            raise YaraError(f"{self.source}:{token.line}: expected {value.decode()!r}, "
                            f"found {token.value.decode(errors='replace')!r}")
        return token

    def accept(self, value: bytes) -> bool:
        token = self.peek()
        if token is not None and token.value == value:
            self.position += 1
            return True
        return False

    # -- rules ------------------------------------------------------------- #
    def parse_ruleset(self) -> list["Rule"]:
        rules: list["Rule"] = []
        while self.peek() is not None:
            rules.append(self.parse_rule())
            if len(rules) > MAX_RULES:
                raise YaraError(f"{self.source}: more than {MAX_RULES} rules in one bundle")
        return rules

    def parse_rule(self) -> "Rule":
        private = self.accept(b"private")
        token = self.next()
        if token.value != b"rule":
            raise YaraError(f"{self.source}:{token.line}: expected 'rule', "
                            f"found {token.value.decode(errors='replace')!r}")
        name = self.expect_identifier()
        tags: list[str] = []
        if self.accept(b":"):
            while self.peek() is not None and self.peek().kind == "ident" \
                    and self.peek().value not in (b"meta", b"strings", b"condition", b"{"):
                tags.append(self.expect_identifier())
            trailing = self.peek()
            if trailing is not None and trailing.kind == "op" and b"-" in trailing.value:
                raise YaraError(f"{self.source}:{trailing.line}: tags are letters, digits and "
                                f"underscores — {trailing.value.decode()!r} cannot be part of "
                                f"one (use an underscore)")
        self.expect(b"{")
        meta: dict[str, Any] = {}
        patterns: dict[str, Any] = {}
        condition: "_Node | None" = None
        while not self.accept(b"}"):
            section = self.next()
            if section.value == b"meta":
                self.expect(b":")
                meta.update(self.parse_meta())
            elif section.value == b"strings":
                self.expect(b":")
                patterns.update(self.parse_strings())
            elif section.value == b"condition":
                self.expect(b":")
                condition = self.parse_condition()
            else:
                raise YaraError(f"{self.source}:{section.line}: unexpected section "
                                f"{section.value.decode(errors='replace')!r}")
        if condition is None:
            raise YaraError(f"{self.source}: rule {name} has no condition")
        referenced = condition.names() if hasattr(condition, "names") else set()
        unknown = {name for name in referenced if name not in patterns}
        if unknown:
            raise YaraError(f"{self.source}: rule {name} refers to unknown string(s): "
                            f"{', '.join(sorted(unknown))}")
        return Rule(name=name, tags=tags, meta=meta, patterns=patterns,
                    condition=condition, private=private, source=self.source)

    def expect_identifier(self) -> str:
        token = self.next()
        if token.kind != "ident":
            raise YaraError(f"{self.source}:{token.line}: expected an identifier, "
                            f"found {token.value.decode(errors='replace')!r}")
        return token.value.decode()

    def parse_meta(self) -> dict[str, Any]:
        meta: dict[str, Any] = {}
        while self.peek() is not None and self.peek().kind == "ident" \
                and self.peek(1) is not None and self.peek(1).value == b"=":
            key = self.expect_identifier()
            self.expect(b"=")
            value = self.next()
            if value.kind == "string":
                meta[key] = _unquote(value.value).decode("utf-8", "replace")
            elif value.kind == "number":
                meta[key] = _number(value.value)
            elif value.value == b"true":
                meta[key] = True
            elif value.value == b"false":
                meta[key] = False
            else:
                raise YaraError(f"{self.source}:{value.line}: unsupported meta value "
                                f"{value.value.decode(errors='replace')!r}")
        return meta

    def parse_strings(self) -> dict[str, Any]:
        patterns: dict[str, Any] = {}
        while self.peek() is not None and self.peek().kind == "op" \
                and self.peek().value.startswith(b"$"):
            identifier = self.next().value.decode()
            if identifier == "$":
                raise YaraError(f"{self.source}: anonymous strings need a condition this "
                                f"subset does not support; name the string ($a)")
            self.expect(b"=")
            patterns[identifier] = self.parse_pattern()
        return patterns

    def parse_pattern(self) -> Any:
        token = self.next()
        if token.kind == "string":
            pattern: Any = TextPattern(_unquote(token.value))
        elif token.value == b"{":
            pattern = _hex_pattern(self.collect_hex_block(token), self.source, token.line)
        elif token.kind == "regex":
            pattern = self.parse_regex(token.value, token.line)
        else:
            raise YaraError(f"{self.source}:{token.line}: expected a string, hex block or "
                            f"regex, found {token.value.decode(errors='replace')!r}")
        supported = {b"nocase", b"wide", b"ascii", b"fullword"}
        unsupported = {b"xor", b"base64", b"base64wide", b"private"}
        while self.peek() is not None and self.peek().kind == "ident":
            if self.peek().value in unsupported:
                token = self.next()
                raise YaraError(f"{self.source}:{token.line}: string modifier "
                                f"{token.value.decode()!r} is not supported by this subset")
            if self.peek().value not in supported:
                break                          # meta:/strings:/condition: — end of the block
            modifier = self.next().value
            if modifier == b"nocase":
                pattern.nocase = True
                if isinstance(pattern, RegexPattern):
                    flags = pattern.pattern.flags | re.IGNORECASE
                    pattern.pattern = re.compile(pattern.bytes_source, flags)
            elif modifier == b"wide":
                pattern.wide = True
            elif modifier == b"ascii":
                pattern.ascii = True
            elif modifier == b"fullword":
                if not isinstance(pattern, TextPattern):
                    raise YaraError(f"{self.source}: 'fullword' applies to text strings only")
                pattern.fullword = True
        return pattern

    def parse_regex(self, token: bytes, line: int) -> RegexPattern:
        body, _, flags = token[1:].rpartition(b"/")
        flag_text = flags.decode()
        unsupported = set(flag_text) - {"i", "s"}
        if unsupported:
            raise YaraError(f"{self.source}:{line}: unsupported regex flag(s): "
                            f"{''.join(sorted(unsupported))}")
        try:
            compiled = re.compile(body, re.DOTALL | (re.IGNORECASE if "i" in flag_text else 0))
        except re.error as exc:
            raise YaraError(f"{self.source}:{line}: regex does not compile in Python: {exc}")
        return RegexPattern(source=body.decode("latin-1"), pattern=compiled, bytes_source=body,
                            nocase="i" in flag_text)

    # -- condition --------------------------------------------------------- #
    def parse_condition(self) -> "_Node":
        return self.parse_or()

    def parse_or(self) -> "_Node":
        node = self.parse_and()
        while self.accept(b"or"):
            node = _Binary("or", node, self.parse_and())
        return node

    def parse_and(self) -> "_Node":
        node = self.parse_not()
        while self.accept(b"and"):
            node = _Binary("and", node, self.parse_not())
        return node

    def parse_not(self) -> "_Node":
        if self.accept(b"not"):
            return _Not(self.parse_not())
        return self.parse_comparison()

    def parse_comparison(self) -> "_Node":
        node = self.parse_arith()
        token = self.peek()
        if token is not None and token.value in (b">", b">=", b"<", b"<=", b"==", b"!="):
            operator = self.next().value.decode()
            return _Compare(operator, node, self.parse_arith())
        return node

    def parse_arith(self) -> "_Node":
        node = self.parse_primary()
        while self.peek() is not None and self.peek().value in (b"+", b"-"):
            operator = self.next().value.decode()
            node = _Arithmetic(operator, node, self.parse_primary())
        return node

    def parse_primary(self) -> "_Node":
        token = self.next()
        if token.value == b"(":
            node = self.parse_or()
            self.expect(b")")
            return node
        if token.value in (b"true", b"false"):
            return _Literal(token.value == b"true")
        if token.kind == "number":
            if self.accept(b"of"):
                return self.parse_of(_number(token.value))
            return _Literal(_number(token.value))
        if token.value.startswith(b"$"):
            return _StringRef(token.value.decode(), "match")
        if token.value.startswith(b"#"):
            return _StringRef(token.value.decode(), "count")
        if token.value.startswith(b"@"):
            return _StringRef(token.value.decode(), "offset")
        if token.value in (b"any", b"all"):
            if self.accept(b"of"):
                return self.parse_of(0 if token.value == b"any" else -1)
            raise YaraError(f"{self.source}:{token.line}: {token.value.decode()} needs "
                            f"'of them' or 'of ($prefix*)'")
        if token.value == b"filesize":
            return _Filesize()
        if token.value in (b"for", b"of", b"them", b"in", b"at", b"contains", b"matches",
                           b"defined", b"entrypoint"):
            raise YaraError(f"{self.source}:{token.line}: {token.value.decode()!r} is a YARA "
                            f"construct this subset does not implement")
        if token.kind == "ident":
            following = self.peek()
            if following is not None and following.value == b"(":
                # YARA module functions (uint16(), math.entropy(), hash.md5()...)
                # are not implemented, and a rule that needs one must say so
                raise YaraError(f"{self.source}:{token.line}: module function "
                                f"{token.value.decode()}() is not implemented by this subset")
            return _RuleRef(token.value.decode())
        raise YaraError(f"{self.source}:{token.line}: unsupported condition token "
                        f"{token.value.decode(errors='replace')!r}")

    def parse_of(self, minimum: int) -> "_Node":
        token = self.next()
        if token.value == b"them":
            return _Of(minimum, None)
        if token.value == b"(":
            group = self.next()
            if group.kind != "op" or not group.value.startswith(b"$"):
                raise YaraError(f"{self.source}:{group.line}: 'of' takes 'them' or a "
                                f"string set like ($a*)")
            self.expect(b")")
            return _Of(minimum, group.value.decode())
        raise YaraError(f"{self.source}:{token.line}: 'of' takes 'them' or ($prefix*)")


def _number(token: bytes) -> int:
    text = token.decode()
    if text.lower().startswith("0x"):
        return int(text, 16)
    multiplier = {"kb": 1024, "mb": 1024 * 1024}
    suffix = text[-2:].lower()
    if suffix in multiplier:
        return int(text[:-2]) * multiplier[suffix]
    return int(text)


_NIBBLE = {**{f"{value:x}".encode(): value for value in range(16)},
           **{f"{value:X}".encode(): value for value in range(16)}}


def _hex_pattern(token: bytes, source: str, line: int) -> RegexPattern:
    """Compile a YARA hex block into a regular expression.

    ``??`` is any byte, ``?A``/``A?`` restrict a nibble, ``[n-m]`` is a jump of
    n..m bytes and ``( 01 | 02 )`` is an alternative. Compiling to a regular
    expression keeps the semantics auditable and the matcher fast; jumps are
    bounded to :data:`MAX_HEX_JUMP` exactly as YARA bounds them.
    """
    body = token[1:-1].strip()
    pieces: list[str] = []
    index = 0
    while index < len(body):
        char = body[index:index + 1]
        if char.isspace():
            index += 1
            continue
        if char == b"?":
            if body[index + 1:index + 2] == b"?":
                pieces.append(r"[\x00-\xff]")           # any byte
                index += 2
            elif body[index + 1:index + 2] in _NIBBLE:
                low = _NIBBLE[body[index + 1:index + 2]]  # high nibble unknown: 0A..0F
                pieces.append(rf"[\x{low:02x}-\x{(low << 4) | 0x0f:02x}]")
                index += 2
            else:
                raise YaraError(f"{source}:{line}: incomplete wildcard in hex block")
            continue
        if char in _NIBBLE:
            nxt = body[index + 1:index + 2]
            if nxt in _NIBBLE:
                byte = (_NIBBLE[char] << 4) | _NIBBLE[nxt]
                pieces.append(rf"\x{byte:02x}")
                index += 2
            elif nxt == b"?":
                high = _NIBBLE[char] << 4                 # low nibble unknown: 40..4F
                pieces.append(rf"[\x{high:02x}-\x{high | 0x0f:02x}]")
                index += 2
            else:
                raise YaraError(f"{source}:{line}: hex byte needs two nibbles")
            continue
        if char == b"[":
            end = body.find(b"]", index)
            if end < 0:
                raise YaraError(f"{source}:{line}: unterminated jump in hex block")
            spec = body[index + 1:end].decode().strip()
            low, _, high = spec.partition("-")
            try:
                low_value = int(low)
                high_value = int(high) if high else low_value
            except ValueError:
                raise YaraError(f"{source}:{line}: jump must be numeric")
            if high_value > MAX_HEX_JUMP or high_value < low_value:
                raise YaraError(f"{source}:{line}: jump {spec!r} is out of range "
                                f"(0..{MAX_HEX_JUMP})")
            pieces.append(f".{{{low_value},{high_value}}}")
            index = end + 1
            continue
        if char == b"(":
            depth = 1
            end = index + 1
            while end < len(body) and depth:
                if body[end:end + 1] == b"(":
                    depth += 1
                elif body[end:end + 1] == b")":
                    depth -= 1
                end += 1
            inner = body[index + 1:end - 1].split(b"|")
            alternatives = []
            for alternative in inner:
                compiled = _hex_pattern(b"{" + alternative + b"}", source, line)
                alternatives.append(compiled.source)
            pieces.append("(?:" + "|".join(alternatives) + ")")
            index = end
            continue
        if char == b"|":
            raise YaraError(f"{source}:{line}: '|' is only valid inside a hex alternative")
        raise YaraError(f"{source}:{line}: unsupported hex token "
                        f"{char.decode(errors='replace')!r}")
    if not pieces:
        raise YaraError(f"{source}:{line}: empty hex block")
    source_text = "".join(pieces)
    try:
        compiled = re.compile(source_text.encode("latin-1"), re.DOTALL)
    except re.error as exc:
        raise YaraError(f"{source}:{line}: hex block does not compile: {exc}")
    return RegexPattern(source=source_text, pattern=compiled,
                        bytes_source=source_text.encode("latin-1"), kind="hex")


# --------------------------------------------------------------------------- #
# condition AST
# --------------------------------------------------------------------------- #

@dataclass
class _Node:
    def evaluate(self, context: dict[str, Any]) -> Any:      # pragma: no cover - interface
        raise NotImplementedError

    def names(self) -> set[str]:
        return set()

    def rule_refs(self) -> set[str]:
        return set()


@dataclass
class _RuleRef(_Node):
    """Another rule used as a condition — YARA's main way of factoring rules."""

    name: str

    def rule_refs(self) -> set[str]:
        return {self.name}

    def evaluate(self, context: dict[str, Any]) -> Any:
        resolver = context.get("rule")
        if resolver is None:
            raise YaraError(f"rule reference {self.name!r} has no resolver in this context")
        return resolver(self.name)


@dataclass
class _Literal(_Node):
    value: Any

    def evaluate(self, context: dict[str, Any]) -> Any:
        return self.value


@dataclass
class _Filesize(_Node):
    def evaluate(self, context: dict[str, Any]) -> Any:
        return context["filesize"]


@dataclass
class _StringRef(_Node):
    name: str
    kind: str

    def names(self) -> set[str]:
        # '#a'/'@a' refer to the same declared string as '$a'
        return {"$" + self.name[1:]}

    def evaluate(self, context: dict[str, Any]) -> Any:
        row = context["strings"].get("$" + self.name[1:])   # '#a'/'@a' name the same $a
        if row is None:
            # a string that never matched: YARA's undefined, treated as 0 for counts
            # and offsets, and as false for the boolean form
            return 0 if self.kind in ("count", "offset") else False
        if self.kind == "count":
            return row["count"]
        if self.kind == "offset":
            offsets = row.get("offsets") or []
            return offsets[0] if offsets else 0
        return row["count"] > 0


@dataclass
class _Of(_Node):
    minimum: int
    prefix: str | None

    def names(self) -> set[str]:
        return set()

    def evaluate(self, context: dict[str, Any]) -> Any:
        strings = context["strings"]
        if self.prefix:
            # '($a*)' is every string starting with $a; '($a)' names that one string
            if self.prefix.endswith("*"):
                stem = self.prefix[:-1]
                wanted = [name for name in context["declared"] if name.startswith(stem)]
            else:
                wanted = [self.prefix] if self.prefix in context["declared"] else []
        else:
            wanted = list(context["declared"])
        matched = [name for name in wanted if strings.get(name, {}).get("count")]
        if self.minimum < 0:                      # 'all of'
            return bool(wanted) and len(matched) == len(wanted)
        if self.minimum == 0:                     # 'any of'
            return bool(matched)
        return len(matched) >= self.minimum


@dataclass
class _Not(_Node):
    node: _Node

    def names(self) -> set[str]:
        return self.node.names()

    def rule_refs(self) -> set[str]:
        return self.node.rule_refs()

    def evaluate(self, context: dict[str, Any]) -> Any:
        return not self.node.evaluate(context)


@dataclass
class _Binary(_Node):
    operator: str
    left: _Node
    right: _Node

    def names(self) -> set[str]:
        return self.left.names() | self.right.names()

    def rule_refs(self) -> set[str]:
        return self.left.rule_refs() | self.right.rule_refs()

    def evaluate(self, context: dict[str, Any]) -> Any:
        if self.operator == "and":
            return bool(self.left.evaluate(context)) and bool(self.right.evaluate(context))
        return bool(self.left.evaluate(context)) or bool(self.right.evaluate(context))


@dataclass
class _Arithmetic(_Node):
    operator: str
    left: _Node
    right: _Node

    def names(self) -> set[str]:
        return self.left.names() | self.right.names()

    def rule_refs(self) -> set[str]:
        return self.left.rule_refs() | self.right.rule_refs()

    def evaluate(self, context: dict[str, Any]) -> Any:
        left = self.left.evaluate(context)
        right = self.right.evaluate(context)
        return left + right if self.operator == "+" else left - right


@dataclass
class _Compare(_Node):
    operator: str
    left: _Node
    right: _Node

    def names(self) -> set[str]:
        return self.left.names() | self.right.names()

    def rule_refs(self) -> set[str]:
        return self.left.rule_refs() | self.right.rule_refs()

    def evaluate(self, context: dict[str, Any]) -> Any:
        left = self.left.evaluate(context)
        right = self.right.evaluate(context)
        return {
            ">": lambda: left > right,
            ">=": lambda: left >= right,
            "<": lambda: left < right,
            "<=": lambda: left <= right,
            "==": lambda: left == right,
            "!=": lambda: left != right,
        }[self.operator]()


# --------------------------------------------------------------------------- #
# rules and matching
# --------------------------------------------------------------------------- #

@dataclass
class Rule:
    name: str
    condition: _Node
    patterns: dict[str, Any] = field(default_factory=dict)
    meta: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    private: bool = False
    source: str = ""

    def severity(self) -> str:
        value = str(self.meta.get("severity") or "MEDIUM").upper()
        return value if value in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") else "MEDIUM"

    def references(self) -> set[str]:
        return self.condition.rule_refs()

    def match(self, data: bytes, *, rule_context: Any = None) -> dict[str, Any] | None:
        """Evaluate the rule against the bytes; ``None`` when the condition is false.

        ``rule_context`` resolves references to other rules by name; without it a
        rule that refers to another rule cannot be evaluated and says so.
        """
        lower = data.lower() if any(getattr(p, "nocase", False)
                                    and isinstance(p, TextPattern)
                                    for p in self.patterns.values()) else None
        strings: dict[str, dict[str, Any]] = {}
        total = 0
        for identifier, pattern in self.patterns.items():
            offsets, count = pattern.find(data, lower)
            if total >= MAX_OFFSETS_PER_RULE:
                offsets = []
            total += len(offsets)
            strings[identifier] = {"offsets": offsets, "count": count}
        context = {"strings": strings, "declared": list(self.patterns),
                   "filesize": len(data), "rule": rule_context}
        try:
            fired = bool(self.condition.evaluate(context))
        except Exception as exc:  # noqa: BLE001 — a condition that cannot be evaluated is a bug
            raise YaraError(f"rule {self.name}: condition failed to evaluate: {exc}")
        if not fired:
            return None
        return {
            "rule": self.name, "namespace": self.meta.get("namespace"),
            "tags": list(self.tags), "meta": dict(self.meta),
            "severity": self.severity(), "private": self.private,
            "source": self.source,
            "strings": [{"id": identifier, "offsets": row["offsets"], "count": row["count"]}
                        for identifier, row in sorted(strings.items()) if row["count"]],
        }


@dataclass
class RuleSet:
    """A parsed bundle: the rules, the errors, and the digest that identifies it."""

    rules: list[Rule] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    digest: str = ""
    truncated: bool = False
    #: how much of a file the rules are matched against; a match beyond it is not
    #: looked for, and the result says so rather than reporting "no match"
    scan_limit: int = MAX_SCAN_BYTES

    def summary(self) -> dict[str, Any]:
        return {
            "rules": len(self.rules),
            "private_rules": sum(1 for rule in self.rules if rule.private),
            "namespaces": sorted({str(rule.meta.get("namespace")) for rule in self.rules
                                  if rule.meta.get("namespace")}),
            "sources": list(self.sources),
            "errors": self.errors[:20],
            "error_count": len(self.errors),
            "digest": self.digest,
            "truncated": self.truncated,
            "note": ("a rule that does not parse is reported as an error and dropped; a "
                     "bundle with errors is not a clean bundle"),
        }

    def by_name(self) -> dict[str, Rule]:
        return {rule.name: rule for rule in self.rules}

    def unknown_references(self) -> list[str]:
        """Rules whose condition names a rule this bundle does not contain."""
        known = set(self.by_name())
        return sorted({name for rule in self.rules for name in rule.references()
                       if name not in known})

    def scan(self, data: bytes, *, limit: int | None = None) -> dict[str, Any]:
        """Match every rule against ``data``; a prefix sample says it was a sample.

        Rules that refer to other rules are resolved on demand, so a rule may use
        one declared later in the bundle; a reference cycle is reported instead of
        recursing forever.
        """
        sample = data[:self.scan_limit if limit is None else limit]
        known = self.by_name()
        fired: dict[str, bool] = {}
        pending: list[str] = []

        def resolve(name: str) -> bool:
            if name in fired:
                return fired[name]
            rule = known.get(name)
            if rule is None:
                raise YaraError(f"condition refers to unknown rule {name!r}")
            if name in pending:
                raise YaraError(f"rule reference cycle: {' -> '.join([*pending, name])}")
            pending.append(name)
            try:
                row = rule.match(sample, rule_context=resolve)
            finally:
                pending.pop()
            fired[name] = row is not None
            return fired[name]

        matches: list[dict[str, Any]] = []
        for rule in self.rules:
            if rule.name not in fired:
                # evaluating one rule may already have evaluated it as a reference
                resolve(rule.name)
            if fired[rule.name] and not rule.private:
                row = rule.match(sample, rule_context=resolve)
                if row is not None:
                    matches.append(row)
        matches.sort(key=lambda row: (row["rule"], row["namespace"] or ""))
        return {"matches": matches, "bytes_scanned": len(sample),
                "truncated": len(data) > len(sample), "rules": len(self.rules)}


# --------------------------------------------------------------------------- #
# loading
# --------------------------------------------------------------------------- #

def parse_rules(text: str, source: str = "<string>") -> list[Rule]:
    """Parse one bundle of rules, raising :class:`YaraError` on the first problem."""
    rules = _Parser(text, source).parse_ruleset()
    known = {rule.name for rule in rules}
    for rule in rules:
        missing = sorted(name for name in rule.references() if name not in known)
        if missing:
            raise YaraError(f"{source}: rule {rule.name} refers to unknown rule(s): "
                            f"{', '.join(missing)}")
    return rules


def load_rules(paths: Iterable[str | Path] = (), *, include_builtin: bool = True,
               scan_limit: int | None = None) -> RuleSet:
    """Load and compile rules from files or directories, plus the built-in set.

    Every source is recorded and the bundle is digested: a finding from a YAML
    rule cites the digest, so the rule text that produced it can be named and
    reproduced on another machine.
    """
    ruleset = RuleSet()
    if scan_limit is not None:
        ruleset.scan_limit = max(1, int(scan_limit))
    sources: list[tuple[str, str]] = []
    if include_builtin:
        sources.append(("builtin:devsecops.yar", BUILTIN_RULES))
    for entry in paths:
        path = Path(entry).expanduser()
        if path.is_dir():
            files = sorted([*path.rglob("*.yar"), *path.rglob("*.yara")])
            if not files:
                ruleset.errors.append({"source": str(path), "error": "no .yar/.yara files in directory"})
            sources.extend((str(file), file.read_text("utf-8", "replace")) for file in files)
            continue
        if not path.is_file():
            ruleset.errors.append({"source": str(path), "error": "rule file not found"})
            continue
        sources.append((str(path), path.read_text("utf-8", "replace")))
    seen: set[str] = set()
    for source, text in sources:
        ruleset.sources.append(source)
        try:
            parsed = parse_rules(text, source)
        except YaraError as exc:
            ruleset.errors.append({"source": source, "error": str(exc)})
            continue
        for rule in parsed:
            key = f"{rule.meta.get('namespace') or ''}:{rule.name}"
            if key in seen:
                ruleset.errors.append({"source": source,
                                       "error": f"duplicate rule {rule.name!r} in namespace "
                                                f"{rule.meta.get('namespace')!r} — "
                                                f"the first definition wins"})
                continue
            seen.add(key)
            ruleset.rules.append(rule)
            if len(ruleset.rules) > MAX_RULES:
                ruleset.truncated = True
                break
        if ruleset.truncated:
            break
    for name in ruleset.unknown_references():
        ruleset.errors.append({"source": "ruleset",
                               "error": f"a condition refers to rule {name!r}, which no "
                                        f"loaded file defines"})
    digest = hashlib.sha256()
    for source, text in sources:
        digest.update(source.encode("utf-8", "replace"))
        digest.update(b"\x00")
        digest.update(text.encode("utf-8", "replace"))
        digest.update(b"\x00")
    ruleset.digest = digest.hexdigest()
    return ruleset


def scan_bytes(data: bytes, ruleset: RuleSet, *, limit: int | None = None) -> dict[str, Any]:
    """Match one buffer, returning the ruleset summary with it (provenance)."""
    result = ruleset.scan(data, limit=limit)
    result["ruleset"] = ruleset.summary()
    return result


#: The rules that ship with the platform. They are deliberately specific: a rule
#: that fires on a word like "crypto" would be noise dressed as detection. Each
#: one carries its own description and severity so a finding explains itself.
BUILTIN_RULES = r"""
/* Built-in markers for the binary scanner. Specific strings only: every rule
   here states what it looks for and why that is worth reporting. */

private rule private_key_material
{
    meta:
        description = "PEM or OpenSSH private key material"
        category = "secret-material"
    strings:
        $pem = "-----BEGIN PRIVATE KEY-----"
        $rsa = "-----BEGIN RSA PRIVATE KEY-----"
        $ec  = "-----BEGIN EC PRIVATE KEY-----"
        $openssh = "-----BEGIN OPENSSH PRIVATE KEY-----"
        $pgp = "-----BEGIN PGP PRIVATE KEY BLOCK-----"
    condition:
        any of them
}

rule crypto_private_key_in_binary : key_material
{
    meta:
        description = "a private key is embedded in the file — certificate or not, this is secret material"
        severity = "HIGH"
        category = "secret-material"
        reference = "the embedded-key reader reports the key itself; this rule is the cheap pre-filter"
    strings:
        $pem = "-----BEGIN PRIVATE KEY-----"
        $rsa = "-----BEGIN RSA PRIVATE KEY-----"
        $ec  = "-----BEGIN EC PRIVATE KEY-----"
        $openssh = "-----BEGIN OPENSSH PRIVATE KEY-----"
        $pgp = "-----BEGIN PGP PRIVATE KEY BLOCK-----"
    condition:
        any of them
}

rule cryptominer_markers : malware cryptominer
{
    meta:
        description = "mining pool or miner markers"
        severity = "HIGH"
        category = "malware"
        reference = "STRATUM, RandomX and known miner binaries are specific enough to match on"
    strings:
        $xmrig = "xmrig" nocase
        $stratum = "stratum+tcp://" nocase
        $randomx = "RandomX" 
        $minerd = "minerd" nocase
        $cryptonight = "cryptonight" nocase
    condition:
        2 of them
}

rule ransomware_note_markers : malware ransomware
{
    meta:
        description = "a ransom note or an on-disk encryption marker"
        severity = "CRITICAL"
        category = "malware"
    strings:
        $encrypted = "your files have been encrypted" nocase
        $decrypt = "to decrypt your files" nocase
        $tor = ".onion" nocase
        $note = "RECOVER-FILES.txt" nocase
        $wallet = "bitcoin wallet" nocase
    condition:
        $encrypted or (#decrypt + #note + #wallet + #tor) >= 2
}

rule credential_dumping_toolkit : malware
{
    meta:
        description = "known credential-dumping toolkit markers"
        severity = "HIGH"
        category = "malware"
    strings:
        $mimikatz = "mimikatz" nocase
        $sekurlsa = "sekurlsa::" nocase
        $lsadump = "lsadump::" nocase
        $kerberos = "kerberos::golden" nocase
    condition:
        any of them
}

rule reverse_shell_markers : suspicious
{
    meta:
        description = "interactive shell over a socket"
        severity = "MEDIUM"
        category = "suspicious"
    strings:
        $sh_i = "/bin/sh -i"
        $bash_c = "/bin/bash -c"
        $nc = "nc -e /bin/sh"
        $pty = "pty.spawn"
    condition:
        any of them
}

rule upx_packer_markers : packer
{
    meta:
        description = "UPX packer markers — packed binaries hide strings and symbols"
        severity = "LOW"
        category = "packer"
    strings:
        $sig = "UPX!"
        $section = "UPX0"
        $section2 = "UPX1"
        $note = "$Info: This file is packed with the UPX executable packer" 
    condition:
        $sig and ($section or $section2 or $note)
}

rule hardcoded_test_credentials : suspicious
{
    meta:
        description = "credentials that look like build or test fixtures"
        severity = "LOW"
        category = "suspicious"
    strings:
        $user = "admin:admin"
        $pass = "password123"
        $token = "changeme"
        $secret = "AKIA" fullword
    condition:
        2 of them
}
"""
