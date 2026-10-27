"""A read-only GraphQL subset — enough to query the platform, nothing that runs.

Why a subset rather than a library: the platform's dependencies are pinned and an
air-gapped install cannot fetch a new one at update time, so — exactly like the
YARA subset in :mod:`devsecops.yara_rules` — this is a documented subset that
**refuses out loud** what it does not implement instead of guessing. Anything a
client sends that this module cannot honour comes back as a GraphQL-shaped error,
never as a silently different answer.

Supported
---------
* ``query`` operations only. ``mutation``/``subscription`` are refused: this
  surface is read-only by construction, so a write cannot be smuggled through it.
* fields, nested selections, **aliases** (``a: b``)
* arguments: strings (with ``\\u``/``\\n`` escapes), integers, floats, booleans,
  ``null``, enums, lists, input objects, and **variables** (``$x``) with defaults
* named ``fragment`` definitions and ``...spread``; ``... on Type`` inline
  fragments apply when the type matches (or when the parent has no type)
* ``@skip(if:)`` / ``@include(if:)``
* ``__typename`` on any object; a ``__schema`` root field (introspection-lite:
  the names and types this surface actually resolves)

Refused
-------
* directives other than ``skip``/``include``, and directive arguments other than
  ``if``
* mutations and subscriptions; duplicate fragment names; unknown variables used in
  the document; unparseable documents
* anything past the depth, field-count and list-size limits, which are echoed in
  the response's ``extensions`` so a client can see the ceiling it hit
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field as dc_field
from typing import Any, Iterable, Mapping

#: nested selection sets a single query may use
MAX_DEPTH = 12
#: fields a single query may select, summed across every branch
MAX_FIELDS = 500
#: items any list-returning field will emit before it truncates (and says so)
MAX_LIST = 200
#: characters in one query text
MAX_QUERY_CHARS = 100_000


class GraphQLSyntaxError(ValueError):
    """The document is not a query this surface can parse."""


@dataclass
class Error:
    """One GraphQL error: a message, the path it happened at, and an extension."""

    message: str
    path: list[str] = dc_field(default_factory=list)
    code: str = "GRAPHQL_ERROR"

    def as_dict(self) -> dict[str, Any]:
        return {"message": self.message, "path": list(self.path),
                "extensions": {"code": self.code}}


# --------------------------------------------------------------------------- #
# lexer
# --------------------------------------------------------------------------- #

# NOTE: in a verbose regex even ``#`` starts a comment, so the GraphQL comment
# token has to escape it — the alternative silently eats the rest of the pattern.
_TOKEN = re.compile(r"""
    (?P<skip>[\s,\ufeff]+|\#[^\n\r]*)
  | (?P<spread>\.\.\.)
  | (?P<punct>[!$():=@\[\]{}|])
  | (?P<name>[_A-Za-z][_A-Za-z0-9]*)
  | (?P<float>-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)
  | (?P<string>"(?:\\.|[^"\\])*")
""", re.VERBOSE)


class _Lexer:
    def __init__(self, text: str):
        self.tokens: list[tuple[str, str, int]] = []
        position = 0
        for match in _TOKEN.finditer(text):
            if match.start() != position:
                character = text[position] if position < len(text) else ""
                if character == '"':
                    raise GraphQLSyntaxError(
                        f"unterminated string starting at offset {position}: a string needs a "
                        'closing " on the same line')
                raise GraphQLSyntaxError(
                    f"unexpected character {character!r} at offset {position}")
            position = match.end()
            kind = match.lastgroup or ""
            if kind == "skip":
                continue
            if kind == "float":
                following = text[match.end():match.end() + 1]
                if following.isdigit() or following == ".":
                    raise GraphQLSyntaxError(
                        f"invalid number at offset {match.start()}: leading zeros and two "
                        "decimal points are not numbers")
            self.tokens.append((kind, match.group(), match.start()))
        if position != len(text):
            raise GraphQLSyntaxError(f"unexpected character {text[position]!r} at offset {position}")
        self.tokens.append(("eof", "", len(text)))
        self.index = 0

    def peek(self) -> tuple[str, str, int]:
        return self.tokens[self.index]

    def next(self) -> tuple[str, str, int]:
        token = self.tokens[self.index]
        self.index += 1
        return token

    def expect(self, value: str) -> tuple[str, str, int]:
        kind, text, offset = self.next()
        if text != value:
            raise GraphQLSyntaxError(f"expected {value!r} but found {text!r} at offset {offset}")
        return kind, text, offset

    def name(self) -> str:
        kind, text, offset = self.next()
        if kind != "name":
            raise GraphQLSyntaxError(f"expected a name but found {text!r} at offset {offset}")
        return text

    def optional(self, value: str) -> bool:
        if self.peek()[1] == value:
            self.index += 1
            return True
        return False


# --------------------------------------------------------------------------- #
# document model
# --------------------------------------------------------------------------- #

@dataclass
class Argument:
    name: str
    value: Any


@dataclass
class Field:
    name: str
    alias: str | None = None
    arguments: list[Argument] = dc_field(default_factory=list)
    selection: list["Field"] = dc_field(default_factory=list)
    directives: list[Argument] = dc_field(default_factory=list)   # only @skip/@include
    fragment_spreads: list[str] = dc_field(default_factory=list)
    inline_fragments: list[tuple[str | None, list["Field"]]] = dc_field(default_factory=list)

    @property
    def response_key(self) -> str:
        return self.alias or self.name

    def argument(self, name: str, default: Any = None) -> Any:
        for argument in self.arguments:
            if argument.name == name:
                return argument.value
        return default

    def has_argument(self, name: str) -> bool:
        return any(argument.name == name for argument in self.arguments)


@dataclass
class Document:
    operation: str
    fields: list[Field]
    variables: dict[str, Any]
    variable_names: list[str]
    fragments: dict[str, tuple[str | None, list[Field]]]


def _parse_value(lexer: _Lexer) -> Any:
    kind, text, offset = lexer.peek()
    if text == "$":
        lexer.next()
        return Variable(lexer.name())
    if text == "[":
        lexer.next()
        items: list[Any] = []
        while not lexer.optional("]"):
            items.append(_parse_value(lexer))
        return items
    if text == "{":
        lexer.next()
        obj: dict[str, Any] = {}
        while not lexer.optional("}"):
            key = lexer.name()
            lexer.expect(":")
            obj[key] = _parse_value(lexer)
        return obj
    lexer.next()
    if kind == "string":
        return _unquote(text)
    if kind == "float":
        return float(text) if any(character in text for character in ".eE") else int(text)
    if kind == "name":
        if text == "true":
            return True
        if text == "false":
            return False
        if text == "null":
            return None
        return Enum(text)
    raise GraphQLSyntaxError(f"unexpected value {text!r} at offset {offset}")


class Enum(str):
    """A bare word used as a value — an enum, or a scalar the resolver parses."""


class Variable:
    __slots__ = ("name",)

    def __init__(self, name: str):
        self.name = name


def _unquote(text: str) -> str:
    body = text[1:-1]
    if "\\" not in body:
        return body
    out: list[str] = []
    escapes = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", '"': '"', "\\": "\\", "/": "/"}
    index = 0
    while index < len(body):
        character = body[index]
        if character != "\\" or index + 1 >= len(body):
            out.append(character)
            index += 1
            continue
        code = body[index + 1]
        if code == "u" and index + 5 < len(body) + 1:
            hex_digits = body[index + 2:index + 6]
            try:
                out.append(chr(int(hex_digits, 16)))
            except ValueError as exc:
                raise GraphQLSyntaxError(f"bad unicode escape {body[index:index + 6]!r}") from exc
            index += 6
            continue
        if code not in escapes:
            raise GraphQLSyntaxError(f"unsupported escape \\{code}")
        out.append(escapes[code])
        index += 2
    return "".join(out)


def _parse_arguments(lexer: _Lexer) -> list[Argument]:
    if not lexer.optional("("):
        return []
    arguments: list[Argument] = []
    while not lexer.optional(")"):
        name = lexer.name()
        lexer.expect(":")
        arguments.append(Argument(name, _parse_value(lexer)))
    return arguments


def _parse_directives(lexer: _Lexer, where: str) -> list[Argument]:
    """Only @skip/@include, and only with ``if:`` — anything else is refused."""
    directives: list[Argument] = []
    while lexer.optional("@"):
        name = lexer.name()
        if name not in ("skip", "include"):
            raise GraphQLSyntaxError(
                f"@{name} at {where}: only @skip and @include are supported")
        arguments = _parse_arguments(lexer)
        for argument in arguments:
            if argument.name != "if":
                raise GraphQLSyntaxError(
                    f"@{name}({argument.name}:) at {where}: only the 'if' argument is supported")
        if len(arguments) != 1:
            raise GraphQLSyntaxError(f"@{name} at {where}: needs exactly one 'if' argument")
        value = arguments[0].value
        if not isinstance(value, Variable) and not isinstance(value, bool):
            raise GraphQLSyntaxError(
                f"@{name}(if:) at {where} needs true or false (or a $variable), got {value!r}")
        directives.append(Argument(name, value))
    return directives


def _parse_selection(lexer: _Lexer, depth: int) -> list[Field]:
    if depth > MAX_DEPTH:
        raise GraphQLSyntaxError(f"selection set nested deeper than {MAX_DEPTH} levels")
    lexer.expect("{")
    fields: list[Field] = []
    while not lexer.optional("}"):
        if lexer.peek()[0] == "eof":
            raise GraphQLSyntaxError("unterminated selection set: expected '}'")
        if lexer.peek()[1] == "...":
            lexer.next()
            if lexer.peek()[1] == "on":
                lexer.next()
                type_name = lexer.name()
                selection = _parse_selection(lexer, depth + 1)
                fields.append(Field(name="__inline", inline_fragments=[(type_name, selection)]))
                continue
            if lexer.peek()[1] == "{":
                raise GraphQLSyntaxError(
                    "an inline fragment must name its type: write '... on Type { … }'")
            name = lexer.name()
            field = Field(name="__spread", fragment_spreads=[name])
            field.directives = _parse_directives(lexer, f"...{name}")
            fields.append(field)
            continue
        name = lexer.name()
        alias = None
        if lexer.optional(":"):
            alias, name = name, lexer.name()
        field = Field(name=name, alias=alias, arguments=_parse_arguments(lexer),
                      directives=_parse_directives(lexer, name))
        if lexer.peek()[1] == "{":
            field.selection = _parse_selection(lexer, depth + 1)
        fields.append(field)
    if not fields:
        # "{}" is valid GraphQL syntax that selects nothing; answering it with an
        # empty object would read as "no data" rather than "you asked for nothing"
        raise GraphQLSyntaxError("an empty selection set selects nothing — name at least one field")
    return fields


def parse(query: str, *, variables: Mapping[str, Any] | None = None) -> Document:
    """Parse one document into a :class:`Document`, or raise :class:`GraphQLSyntaxError`."""
    if not isinstance(query, str) or not query.strip():
        raise GraphQLSyntaxError("the query is empty")
    if len(query) > MAX_QUERY_CHARS:
        raise GraphQLSyntaxError(f"the query is longer than {MAX_QUERY_CHARS} characters")
    lexer = _Lexer(query)
    fragments: dict[str, tuple[str | None, list[Field]]] = {}
    operation: str | None = None
    variable_names: list[str] = []
    defaults: dict[str, Any] = {}
    fields: list[Field] = []

    # fragment definitions may come before or after the operation
    while lexer.peek()[0] != "eof":
        if lexer.peek()[1] == "{":
            if operation is not None:
                raise GraphQLSyntaxError("a document may carry exactly one operation")
            operation = "query"
            fields = _parse_selection(lexer, 1)
            continue
        keyword = lexer.peek()[1]
        if keyword == "fragment":
            lexer.next()
            name = lexer.name()
            type_name = None
            if lexer.optional("on"):
                type_name = lexer.name()
            if name in fragments:
                raise GraphQLSyntaxError(f"fragment {name} is defined twice")
            fragments[name] = (type_name, _parse_selection(lexer, 1))
            continue
        if keyword in ("query", "mutation", "subscription"):
            lexer.next()
            if operation is not None:
                raise GraphQLSyntaxError("a document may carry exactly one operation")
            operation = keyword
            if lexer.peek()[0] == "name":
                lexer.next()  # operation name — accepted, not needed
            if lexer.optional("("):
                while not lexer.optional(")"):
                    lexer.expect("$")
                    variable_names.append(lexer.name())
                    lexer.expect(":")
                    _skip_type(lexer)
                    if lexer.optional("="):
                        defaults[variable_names[-1]] = _parse_value(lexer)
            _parse_directives(lexer, f"{keyword} operation")
            fields = _parse_selection(lexer, 1)
            continue
        raise GraphQLSyntaxError(f"unexpected {keyword!r} at offset {lexer.peek()[2]}")

    if operation is None:
        raise GraphQLSyntaxError("the document has no operation")
    if operation != "query":
        raise GraphQLSyntaxError(
            f"{operation} operations are not supported: this surface is read-only "
            "(every write path is a REST endpoint with its own roles and audit)")

    # variables: bound value, else declared default, else missing
    bound: dict[str, Any] = {}
    for name in variable_names:
        if variables and name in variables:
            bound[name] = variables[name]
        elif name in defaults:
            bound[name] = defaults[name]
        elif variables is None or name not in variables:
            bound[name] = _MISSING
    if variables:
        for name in variables:
            if name not in variable_names:
                raise GraphQLSyntaxError(
                    f"variable ${name} was supplied but is not declared by the operation")
    document = Document(operation=operation, fields=fields, variables=bound,
                        variable_names=variable_names, fragments=fragments)
    _check_fragment_references(document)
    _count_fields(document)
    return document


def _skip_type(lexer: _Lexer) -> None:
    """Consume a type reference: ``[Name!]!`` and friends."""
    if lexer.optional("["):
        _skip_type(lexer)
        lexer.expect("]")
    else:
        lexer.name()
    lexer.optional("!")


#: a declared variable that no value was passed for
_MISSING = object()


class MissingVariable(ValueError):
    """A ``$var`` used in the query was never supplied."""

    def __init__(self, name: str):
        super().__init__(f"variable ${name} is required but was not supplied")
        self.name = name


def _check_fragment_references(document: Document) -> None:
    known = set(document.fragments)

    def walk(fields: Iterable[Field]) -> None:
        for field in fields:
            for name in field.fragment_spreads:
                if name not in known:
                    raise GraphQLSyntaxError(f"fragment {name} is spread but never defined")
            walk(field.selection)
            for _type_name, selection in field.inline_fragments:
                walk(selection)

    walk(document.fields)
    # a fragment that spreads itself would never terminate on expansion
    for name, (_type_name, selection) in document.fragments.items():
        seen: set[str] = set()

        def visit(items: Iterable[Field], trail: list[str]) -> None:
            for item in items:
                for spread in item.fragment_spreads:
                    if spread == name or spread in trail:
                        raise GraphQLSyntaxError(
                            f"fragment {name} spreads itself (cycle: {' -> '.join([*trail, spread])})")
                    seen.add(spread)
                    visit(document.fragments.get(spread, (None, []))[1], [*trail, spread])
                visit(item.selection, trail)
                for _t, nested in item.inline_fragments:
                    visit(nested, trail)

        visit(selection, [name])


def _count_fields(document: Document) -> None:
    total = 0

    def walk(fields: Iterable[Field], seen: frozenset[str]) -> None:
        nonlocal total
        for field in fields:
            total += 1
            if total > MAX_FIELDS:
                raise GraphQLSyntaxError(f"the query selects more than {MAX_FIELDS} fields")
            nested = seen
            for spread in field.fragment_spreads:
                if spread in seen:
                    continue
                nested = nested | {spread}
                walk(document.fragments[spread][1], nested)
            walk(field.selection, nested)
            for _type_name, selection in field.inline_fragments:
                walk(selection, nested)

    walk(document.fields, frozenset())


# --------------------------------------------------------------------------- #
# resolution
# --------------------------------------------------------------------------- #

#: a resolver is either a callable ``(args, ctx) -> value``, a plain value, or a
#: nested mapping of resolvers
Resolver = Any


@dataclass
class ExecutionContext:
    """What a resolver may read: the request context plus the limits in force."""

    data: dict[str, Any] = dc_field(default_factory=dict)
    limit: int = MAX_LIST
    depth: int = 1
    fields_resolved: int = 0

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)


def _directive_allows(field: Field, variables: Mapping[str, Any]) -> bool:
    allowed = True
    for directive in field.directives:
        value = resolve_value(directive.value, variables)
        if not isinstance(value, bool):
            raise GraphQLSyntaxError(
                f"@{directive.name}(if:) needs true or false, got {value!r}")
        if directive.name == "skip" and value:
            allowed = False
        if directive.name == "include" and not value:
            allowed = False
    return allowed


def resolve_value(value: Any, variables: Mapping[str, Any]) -> Any:
    """Substitute variables into a parsed argument value."""
    if isinstance(value, Variable):
        if value.name not in variables:
            raise MissingVariable(value.name)
        bound = variables[value.name]
        if bound is _MISSING:
            raise MissingVariable(value.name)
        return bound
    if isinstance(value, list):
        return [resolve_value(item, variables) for item in value]
    if isinstance(value, dict):
        return {key: resolve_value(item, variables) for key, item in value.items()}
    if isinstance(value, Enum):
        return str(value)
    return value


def _expand(fields: Iterable[Field], document: Document, type_name: str | None,
            trail: frozenset[str]) -> list[Field]:
    """Flatten spreads and inline fragments into a plain selection list.

    A fragment written ``... on Type`` applies when the parent's runtime type is
    known and matches — or when the parent does not declare one, in which case
    there is nothing to compare against and the fragment is applied (the schema's
    own objects always carry ``__type__``, so this leniency only affects resolver
    trees that do not).
    """
    out: list[Field] = []
    for field in fields:
        if field.name == "__spread":
            if not _directive_allows(field, document.variables):
                continue
            for name in field.fragment_spreads:
                if name in trail:  # a cycle; parse() already refuses these, this is belt and braces
                    continue
                spread_type, selection = document.fragments[name]
                if spread_type is not None and type_name is not None and spread_type != type_name:
                    continue
                out.extend(_expand(selection, document, type_name, trail | {name}))
            continue
        if field.name == "__inline":
            for inline_type, selection in field.inline_fragments:
                if inline_type is not None and type_name is not None and inline_type != type_name:
                    continue
                out.extend(_expand(selection, document, type_name, trail))
            continue
        out.append(field)
    return out


def _as_mapping(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    if isinstance(value, (list, tuple)):
        return {"items": list(value), "count": len(value)}
    return {}


def execute(document: Document, root: Mapping[str, Resolver],
            *, context: ExecutionContext | None = None) -> dict[str, Any]:
    """Run a parsed document against a resolver tree.

    Partial success is the model: a field that raises becomes ``null`` plus an entry
    in ``errors`` with its path, and the rest of the answer is still returned — the
    alternative (all-or-nothing) hides the fields that did resolve. ``extensions``
    always reports the limits in force and how many fields were resolved, so a
    client can tell "no data" from "hit a ceiling".
    """
    context = context or ExecutionContext()
    errors: list[Error] = []
    data: dict[str, Any] = {}

    def walk(fields: list[Field], source: Resolver, current_path: list[str],
             type_name: str | None = None) -> dict[str, Any]:
        if context.depth > MAX_DEPTH:
            raise GraphQLSyntaxError(f"selection nested deeper than {MAX_DEPTH} levels")
        expanded = _expand(fields, document, type_name, frozenset())
        out: dict[str, Any] = {}
        for field in expanded:
            key = field.response_key
            path = [*current_path, key]
            if not _directive_allows(field, document.variables):
                continue
            context.fields_resolved += 1
            if context.fields_resolved > MAX_FIELDS:
                raise GraphQLSyntaxError(f"the query resolved more than {MAX_FIELDS} fields")
            if field.name == "__typename":
                out[key] = type_name
                continue
            child = source
            if isinstance(child, Mapping) and field.name in child:
                child = child[field.name]
            else:
                errors.append(Error(f"field {field.name!r} is not part of this schema", path,
                                    "FIELD_NOT_IN_SCHEMA"))
                out[key] = None
                continue
            try:
                value = _call(child, field, context, document)
            except MissingVariable as exc:
                errors.append(Error(str(exc), path, "MISSING_VARIABLE"))
                out[key] = None
                continue
            except GraphQLSyntaxError:
                raise
            except Exception as exc:  # noqa: BLE001 — one bad field must not lose the answer
                errors.append(Error(f"{type(exc).__name__}: {exc}", path,
                                    "RESOLVER_ERROR"))
                out[key] = None
                continue
            value_type = type_name if not field.selection else _type_hint(field)
            out[key] = _shape(value, field, value_type, path)
        return out

    def _shape(value: Any, field: Field, type_name: str | None, path: list[str]) -> Any:
        if not field.selection:
            if isinstance(value, (list, tuple)):
                return list(value)[:context.limit]
            return value
        if isinstance(value, (list, tuple)):
            items = list(value)
            shaped = []
            for index, item in enumerate(items[:context.limit]):
                shaped.append(_shape_one(item, field, path, index))
            if len(items) > context.limit:
                errors.append(Error(
                    f"{field.name} returned {len(items)} items; this surface answers with the "
                    f"first {context.limit}", path, "LIST_TRUNCATED"))
            return shaped
        if value is None:
            return None
        return _shape_one(value, field, path, None)

    def _shape_one(item: Any, field: Field, path: list[str], index: int | None) -> Any:
        if isinstance(item, Mapping):
            context.depth += 1
            try:
                return walk(field.selection, item, [*path, *( [str(index)] if index is not None else [])],
                            _type_hint(field, item))
            finally:
                context.depth -= 1
        # a scalar inside a selection: report the type, nothing else
        return {"__typename": type(item).__name__} if field.selection else item

    try:
        data = walk(document.fields, root, [])
    except GraphQLSyntaxError as exc:
        errors.append(Error(str(exc), [], "QUERY_LIMIT"))
    return {
        "data": data or None,
        "errors": [error.as_dict() for error in errors] or None,
        "extensions": {
            "limits": {"depth": MAX_DEPTH, "fields": MAX_FIELDS, "list": MAX_LIST},
            "fields_resolved": context.fields_resolved,
            "read_only": True,
        },
    }


def _call(resolver: Resolver, field: Field, context: ExecutionContext,
          document: Document) -> Any:
    if callable(resolver):
        arguments = {argument.name: resolve_value(argument.value, document.variables)
                     for argument in field.arguments}
        return resolver(arguments, context)
    if isinstance(resolver, Mapping) and field.selection:
        return resolver
    return resolver


#: resolvers may add ``__type__`` to a mapping to tell the executor what it is
def _type_hint(field: Field, item: Any = None) -> str | None:
    if isinstance(item, Mapping):
        hint = item.get("__type__")
        if isinstance(hint, str):
            return hint
    return None
