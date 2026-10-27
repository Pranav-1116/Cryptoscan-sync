"""The read-only GraphQL subset: what it parses, and what it refuses.

Half of these tests are refusals. A query surface that answers a mutation with
"you asked for a field I do not have" is worse than one that says no, and a parser
that quietly ignores something it does not understand is worse still — so the
refusals here are specific and named.
"""
from __future__ import annotations

import pytest

from api.graphql_lang import (
    MAX_DEPTH,
    MAX_FIELDS,
    GraphQLSyntaxError,
    execute,
    parse,
)

TREE = {
    "thing": lambda args, ctx: {"name": "thing-1", "size": 3, "tags": ["a", "b"]},
    "things": lambda args, ctx: [{"name": f"t{i}", "size": i} for i in range(args.get("limit", 4))],
    "count": 7,
    "nothing": None,
    "echo": lambda args, ctx: {"value": args.get("value")},
}


def run(query: str, tree=None, variables=None):
    return execute(parse(query, variables=variables), tree or TREE)


# ------------------------------------------------------------- parsing ----- #

def test_a_bare_selection_set_is_a_query():
    document = parse("{ count }")
    assert document.operation == "query"
    assert [f.name for f in document.fields] == ["count"]
    assert run("{ count }")["data"] == {"count": 7}


def test_aliases_keep_the_field_name_for_resolution():
    assert run("{ size: count }")["data"] == {"size": 7}
    assert run("{ a: count b: count }")["data"] == {"a": 7, "b": 7}


def test_arguments_of_every_scalar_shape_land_in_the_resolver():
    result = run('{ echo(value: "hi\nthere") { value } }')
    assert result["data"]["echo"] == {"value": "hi\nthere"}
    assert run("{ echo(value: 12) { value } }")["data"]["echo"]["value"] == 12
    assert run("{ echo(value: -1.5) { value } }")["data"]["echo"]["value"] == -1.5
    assert run("{ echo(value: true) { value } }")["data"]["echo"]["value"] is True
    assert run("{ echo(value: null) { value } }")["data"]["echo"]["value"] is None
    assert run("{ echo(value: CRITICAL) { value } }")["data"]["echo"]["value"] == "CRITICAL"
    assert run("{ echo(value: [1, 2]) { value } }")["data"]["echo"]["value"] == [1, 2]
    assert run("{ echo(value: {a: 1, b: \"x\"}) { value } }")["data"]["echo"]["value"] == {"a": 1, "b": "x"}


def test_unicode_escapes_are_decoded():
    assert run('{ echo(value: "\\u00e9t\\u00e9") { value } }')["data"]["echo"]["value"] == "été"
    with pytest.raises(GraphQLSyntaxError, match="bad unicode escape"):
        parse('{ echo(value: "\\u00zz") { value } }')


def test_comments_and_commas_are_ignored():
    document = parse("""
      # the leading comment
      { count, # trailing
        thing { name } }
    """)
    assert [f.name for f in document.fields] == ["count", "thing"]


def test_an_unknown_escape_is_refused_rather_than_guessed():
    with pytest.raises(GraphQLSyntaxError, match="unsupported escape"):
        parse('{ echo(value: "a\\qb") { value } }')


@pytest.mark.parametrize("query,match", [
    ("", "empty"),
    ("   ", "empty"),
    ("{", "unterminated selection set"),
    ("{ }", "selects nothing"),
    ("{ thing { } }", "selects nothing"),
    ("{ count", "unterminated selection set"),
    ("{ 1count }", "expected a name"),
    ("count", "unexpected"),
    ("{ count } { count }", "exactly one operation"),
    ("query A { a } query B { b }", "exactly one operation"),
    ('{ echo(value: "unterminated) { value } }', "unterminated string"),
    ("{ things(limit: 01) }", "invalid number"),
    ("{ things(limit: 1.2.3) }", "invalid number"),
])
def test_malformed_documents_are_refused_with_a_reason(query, match):
    with pytest.raises(GraphQLSyntaxError, match=match):
        parse(query)


def test_mutations_and_subscriptions_are_refused_by_name():
    with pytest.raises(GraphQLSyntaxError, match="mutation operations are not supported"):
        parse("mutation { deleteEverything }")
    with pytest.raises(GraphQLSyntaxError, match="subscription operations are not supported"):
        parse("subscription { things }")


def test_the_read_only_refusal_says_where_writes_live():
    with pytest.raises(GraphQLSyntaxError, match="read-only"):
        parse("mutation M { x }")


def test_the_operation_name_is_accepted_and_ignored():
    assert parse("query Named($x: Int) { count }", variables={"x": 1}).operation == "query"


# ----------------------------------------------------------- variables ----- #

def test_declared_variables_are_bound_and_substituted():
    result = run("query Q($n: Int) { things(limit: $n) { name } }", variables={"n": 2})
    assert [row["name"] for row in result["data"]["things"]] == ["t0", "t1"]


def test_a_variable_default_is_used_when_none_is_passed():
    result = run("query Q($n: Int = 3) { things(limit: $n) { name } }")
    assert len(result["data"]["things"]) == 3


def test_a_missing_variable_is_an_error_at_its_field_not_a_crash():
    result = run("query Q($n: Int) { things(limit: $n) { name } }")
    assert result["data"] == {"things": None}
    assert result["errors"][0]["extensions"]["code"] == "MISSING_VARIABLE"
    assert "$n" in result["errors"][0]["message"]


def test_a_variable_values_can_nest():
    result = run("query Q($v: [Int]) { echo(value: $v) { value } }", variables={"v": [1, 2, 3]})
    assert result["data"]["echo"]["value"] == [1, 2, 3]


def test_supplying_an_undeclared_variable_is_refused():
    with pytest.raises(GraphQLSyntaxError, match="not declared"):
        parse("query Q($a: Int) { count }", variables={"a": 1, "b": 2})


# ----------------------------------------------------------- fragments ----- #

def test_a_named_fragment_is_expanded():
    result = run("{ thing { ...Bits } } fragment Bits on Thing { name size }")
    assert result["data"]["thing"] == {"name": "thing-1", "size": 3}


def test_a_fragment_at_the_root_is_expanded_in_place():
    result = run("{ count ...More } fragment More on Root { size: count }")
    assert result["data"] == {"count": 7, "size": 7}


def test_an_inline_fragment_applies_when_the_type_matches():
    tree = {"thing": {"__type__": "Thing", "name": "thing-1", "size": 3}}
    result = execute(parse("{ thing { ... on Thing { name } ... on Other { size } } }"), tree)
    assert result["data"]["thing"] == {"name": "thing-1"}


def test_an_inline_fragment_applies_when_the_parent_type_is_unknown():
    """Nothing to compare against, so the fragment is applied rather than dropped."""
    result = run("{ thing { ... on Other { name } } }")
    assert result["data"]["thing"] == {"name": "thing-1"}


def test_an_inline_fragment_must_name_its_type():
    with pytest.raises(GraphQLSyntaxError, match="must name its type"):
        parse("{ thing { ... { name } } }")


def test_a_spread_fragment_that_is_never_defined_is_refused():
    with pytest.raises(GraphQLSyntaxError, match="spread but never defined"):
        parse("{ thing { ...Ghost } }")


def test_a_duplicate_fragment_definition_is_refused():
    with pytest.raises(GraphQLSyntaxError, match="defined twice"):
        parse("{ count } fragment A on X { count } fragment A on X { count }")


def test_a_fragment_cycle_is_refused_rather_than_looping():
    with pytest.raises(GraphQLSyntaxError, match="spreads itself|cycle"):
        parse("{ ...A } fragment A on X { ...B } fragment B on X { ...A }")


# ---------------------------------------------------------- directives ----- #

def test_skip_and_include_decide_whether_a_field_is_answered():
    assert run("{ count nope @skip(if: true) }")["data"] == {"count": 7}
    assert run("{ count size: count @include(if: true) }")["data"] == {"count": 7, "size": 7}
    assert run("{ count size: count @include(if: false) }")["data"] == {"count": 7}


def test_a_directive_value_may_be_a_variable():
    result = run("query Q($s: Boolean = true) { count size: count @skip(if: $s) }")
    assert result["data"] == {"count": 7}


def test_any_other_directive_is_refused():
    with pytest.raises(GraphQLSyntaxError, match="only @skip and @include"):
        parse("{ count @deprecated }")
    with pytest.raises(GraphQLSyntaxError, match="only the 'if' argument"):
        parse("{ count @skip(unless: true) }")
    with pytest.raises(GraphQLSyntaxError, match="exactly one 'if' argument"):
        parse("{ count @skip }")


def test_a_non_boolean_directive_value_is_refused_at_parse_time():
    with pytest.raises(GraphQLSyntaxError, match="needs true or false"):
        parse('{ count @skip(if: "yes") }')
    with pytest.raises(GraphQLSyntaxError, match="needs true or false"):
        parse("{ count @skip(if: 1) }")


def test_skip_on_a_fragment_spread_is_honoured():
    result = run("{ count ...More @skip(if: true) } fragment More on X { size: count }")
    assert result["data"] == {"count": 7}


# ------------------------------------------------------------- limits ------ #

def test_a_list_beyond_the_limit_is_truncated_and_says_so():
    wide = {"rows": [{"n": i} for i in range(300)]}
    result = execute(parse("{ rows { n } }"), wide)
    assert len(result["data"]["rows"]) == 200
    assert result["errors"][0]["extensions"]["code"] == "LIST_TRUNCATED"
    assert "first 200" in result["errors"][0]["message"]


def test_deep_nesting_is_refused_by_the_parser():
    query = "{ " + "a { " * (MAX_DEPTH + 2) + "b" + " }" * (MAX_DEPTH + 2) + " }"
    with pytest.raises(GraphQLSyntaxError, match="nested deeper than"):
        parse(query)


def test_a_query_with_too_many_fields_is_refused():
    query = "{ " + " ".join(f"f{i}" for i in range(MAX_FIELDS + 5)) + " }"
    with pytest.raises(GraphQLSyntaxError, match="more than 500 fields"):
        parse(query)


def test_an_over_long_document_is_refused():
    with pytest.raises(GraphQLSyntaxError, match="longer than"):
        parse("{ " + "count " * 20000 + " }")


# ---------------------------------------------------------- execution ------ #

def test_a_field_that_is_not_in_the_schema_is_an_error_with_its_path():
    result = run("{ count thing { missing } }")
    assert result["data"]["count"] == 7
    assert result["data"]["thing"] == {"missing": None}
    assert result["errors"][0]["path"] == ["thing", "missing"]
    assert result["errors"][0]["extensions"]["code"] == "FIELD_NOT_IN_SCHEMA"


def test_a_resolver_that_raises_only_loses_its_own_field():
    def boom(args, ctx):
        raise RuntimeError("the artifact store is not readable")

    result = execute(parse("{ count thing { name } }"), {**TREE, "count": boom})
    assert result["data"]["count"] is None
    assert result["data"]["thing"]["name"] == "thing-1"
    assert result["errors"][0]["extensions"]["code"] == "RESOLVER_ERROR"
    assert "artifact store" in result["errors"][0]["message"]


def test_a_null_object_stays_null_through_nesting():
    result = run("{ nothing { name } }")
    assert result["data"] == {"nothing": None}
    assert result["errors"] is None


def test_typename_reports_the_object_type_a_resolver_declares():
    tree = {"obj": {"__type__": "Thing", "name": "x"}}
    result = execute(parse("{ obj { __typename name } }"), tree)
    assert result["data"]["obj"] == {"__typename": "Thing", "name": "x"}


def test_extensions_always_report_the_limits_and_what_resolved():
    result = run("{ count thing { name } }")
    assert result["extensions"]["limits"] == {"depth": 12, "fields": 500, "list": 200}
    assert result["extensions"]["fields_resolved"] == 3
    assert result["extensions"]["read_only"] is True


def test_a_syntax_error_in_the_executor_still_returns_the_envelope():
    result = execute(parse("{ count }"), {})
    assert result["data"] == {"count": None}
    assert result["errors"][0]["extensions"]["code"] == "FIELD_NOT_IN_SCHEMA"
