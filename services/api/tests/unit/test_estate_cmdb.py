"""Read-only ServiceNow CMDB plane (spec 67 §4; spec 93 §13).

The properties that keep a CMDB read honest:

* everything it emits is ``IMPORTED`` (declared), so a CMDB row can never be read
  as a crypto observation;
* a refused table (401/403) or a table the instance does not model (404) is
  ``blocked`` + ``PARTIAL``, never an empty estate;
* a row limit is reported as truncation;
* a relationship type with no agreed mapping is counted, not coerced.
"""

from __future__ import annotations

import json
from urllib.parse import parse_qs, urlparse

import pytest

from api import estate_cmdb, estate_discovery

CONFIG = {
    "instance_url": "https://bank.service-now.com",
    "token": "oauth-token",
    "username": None,
    "password": None,
    "ca_file": None,
    "max_rows": 100,
    "query": None,
    "source": "INJECTED",
}

SERVERS = [
    {"sys_id": "srv-1", "name": "payments-api-01", "sys_class_name": "cmdb_ci_linux_server",
     "ip_address": "10.20.10.11", "os": "Linux", "os_version": "9.4", "install_status": "Installed",
     "operational_status": "Operational", "owned_by": {"value": "u1", "display_value": "Payments Team"},
     "location": {"value": "l1", "display_value": "Coimbatore DC1"}, "environment": "Production"},
    {"sys_id": "srv-2", "name": "payments-db-01", "sys_class_name": "cmdb_ci_db_pgsql",
     "ip_address": "10.20.10.40", "os": "Linux", "install_status": "Installed",
     "operational_status": "Operational", "environment": "Production"},
]
SERVICES = [
    {"sys_id": "svc-1", "name": "Payments Processing", "sys_class_name": "cmdb_ci_service",
     "operational_status": "Operational", "business_unit": "Retail Banking",
     "owned_by": {"value": "u2", "display_value": "Core Banking"}, "environment": "Production"},
]
APPLICATIONS = [
    {"sys_id": "app-1", "name": "payments-api", "sys_class_name": "cmdb_ci_appl", "version": "1.4.2",
     "install_status": "Installed", "manufacturer": "In-house", "environment": "Production"},
]
RELATIONSHIPS = [
    {"sys_id": "rel-1", "parent": {"value": "app-1"}, "child": {"value": "srv-1"},
     "type": {"value": "t1", "display_value": "Runs on::Runs"}},
    {"sys_id": "rel-2", "parent": {"value": "svc-1"}, "child": {"value": "app-1"},
     "type": {"value": "t2", "display_value": "Depends on::Used by"}},
    {"sys_id": "rel-3", "parent": {"value": "srv-1"}, "child": {"value": "srv-2"},
     "type": {"value": "t3", "display_value": "Connects to::Connected from"}},
]


def _transport(tables: dict[str, list] | None = None, *, forbidden: set[str] | None = None,
               seen: list[dict] | None = None, total: int | None = None):
    tables = tables if tables is not None else {
        "cmdb_ci_server": SERVERS, "cmdb_ci_service": SERVICES, "cmdb_ci_appl": APPLICATIONS,
        "cmdb_rel_ci": RELATIONSHIPS,
    }
    forbidden = forbidden or set()

    def transport(url, headers, timeout):
        parsed = urlparse(url)
        table = parsed.path.rsplit("/", 1)[-1]
        if seen is not None:
            seen.append({"url": url, "headers": dict(headers),
                         "params": parse_qs(parsed.query)})
        if table in forbidden:
            return 403, b'{"error": {"message": "ACL restricted"}}', {}
        if table not in tables:
            return 404, b'{"error": {"message": "no such table"}}', {}
        response_headers = {"X-Total-Count": str(total)} if total is not None else {}
        return 200, json.dumps({"result": tables[table]}).encode(), response_headers

    return transport


# --------------------------------------------------------------------------- #
# configuration
# --------------------------------------------------------------------------- #
def test_no_instance_is_not_attempted():
    with pytest.raises(estate_cmdb.PlaneNotConfigured):
        estate_cmdb.cmdb_config({})

    def boom(_db, **_kwargs):
        raise estate_cmdb.PlaneNotConfigured("no CMDB configured")

    report = estate_discovery.run(None, persist=False, collectors={"CMDB": boom})
    cmdb = next(item for item in report["collectors"] if item["plane"] == "CMDB")
    assert cmdb["status"] == "NOT_ATTEMPTED"
    assert "NOT_OBSERVED" in cmdb["impact"]


def test_plaintext_instance_url_is_refused():
    with pytest.raises(estate_cmdb.PlaneNotConfigured) as caught:
        estate_cmdb.cmdb_config({"SERVICENOW_INSTANCE_URL": "http://bank.service-now.com"})
    assert "https" in str(caught.value)


def test_credentials_resolve_to_basic_or_bearer():
    bearer = estate_cmdb.cmdb_config({
        "SERVICENOW_INSTANCE_URL": "https://bank.service-now.com/",
        "SERVICENOW_TOKEN": "abc",
    })
    assert bearer["instance_url"] == "https://bank.service-now.com"
    bearer_headers = estate_cmdb._auth_headers(bearer)
    assert bearer_headers["Authorization"] == "Bearer abc"

    basic = estate_cmdb.cmdb_config({
        "SERVICENOW_INSTANCE_URL": "https://bank.service-now.com",
        "SERVICENOW_USERNAME": "svc_cryptoscan",
        "SERVICENOW_PASSWORD": "secret",
    })
    headers = estate_cmdb._auth_headers(basic)
    assert headers["Authorization"].startswith("Basic ")
    assert "secret" not in headers["Authorization"], "basic auth is encoded, never echoed in clear"


def test_instance_without_a_credential_is_refused():
    with pytest.raises(estate_cmdb.PlaneNotConfigured) as caught:
        estate_cmdb.cmdb_config({"SERVICENOW_INSTANCE_URL": "https://bank.service-now.com"})
    assert "no credential" in str(caught.value)


# --------------------------------------------------------------------------- #
# collecting
# --------------------------------------------------------------------------- #
def test_configuration_items_become_imported_assets():
    result = estate_cmdb.collect_cmdb(None, transport=_transport(), config=CONFIG)
    assert result["collected"] == result["expected"] == 4
    assert all(record["evidence_type"] == "IMPORTED" for record in result["evidence"])
    assert all(record["confidence"] == "LOW" for record in result["evidence"])

    types = {asset["type"] for asset in result["assets"]}
    assert {"HOST", "SERVICE", "APPLICATION"} <= types

    api = next(asset for asset in result["assets"] if asset["name"] == "payments-api")
    assert api["owner"] is None or isinstance(api["owner"], str)
    server = next(asset for asset in result["assets"] if asset["name"] == "payments-api-01")
    assert server["owner"] == "Payments Team", "the CMDB's owned_by display value is the owner"
    assert server["location"] == "Coimbatore DC1"
    assert server["attributes"]["sys_class_name"] == "cmdb_ci_linux_server"
    assert "belongs-to-a-domain-controller" not in server["attributes"]


def test_every_read_is_a_get_with_fields_and_a_limit():
    seen: list[dict] = []
    estate_cmdb.collect_cmdb(None, transport=_transport(seen=seen), config=CONFIG)
    assert len(seen) == 4
    for call in seen:
        assert "/api/now/table/" in call["url"]
        assert call["params"]["sysparm_fields"], "a CMDB read asks for named fields, never SELECT *"
        assert call["params"]["sysparm_limit"] == ["100"]
        assert call["headers"]["Authorization"] == "Bearer oauth-token"


def test_a_relationship_type_with_no_mapping_is_counted_not_guessed():
    result = estate_cmdb.collect_cmdb(None, transport=_transport(), config=CONFIG)
    predicates = {(edge["subject"], edge["predicate"]) for edge in result["relationships"]}
    assert any(predicate == "runs_on" for _subject, predicate in predicates)
    assert any(predicate == "depends_on" for _subject, predicate in predicates)
    assert result["unmapped_relationships"] == 1, "'Connects to' has no agreed predicate"
    assert "no agreed mapping" in " ".join(result["limitations"])
    for edge in result["relationships"]:
        assert edge["basis"] == "IMPORTED"
        assert edge["attributes"]["observed"] is False


def test_imported_edges_cannot_establish_usage():
    """The whole point of the IMPORTED basis: a CMDB dependency is not a crypto path."""
    from shared_models.estate_graph import USAGE_BASES

    assert "IMPORTED" not in USAGE_BASES


def test_a_forbidden_table_is_partial_not_empty():
    result = estate_cmdb.collect_cmdb(None, transport=_transport(forbidden={"cmdb_ci_server"}), config=CONFIG)
    assert result["collected"] == 3
    assert any("cmdb_ci_server" in item for item in result["blocked"])
    assert "NOT_OBSERVED, not an empty table" in " ".join(result["limitations"])

    outcome = estate_discovery._collect("CMDB", lambda _db, **_: result, None)
    assert outcome["status"] == "PARTIAL"
    assert "NOT_OBSERVED" in outcome["impact"]


def test_a_missing_table_is_reported_as_unmodelled():
    tables = {"cmdb_ci_server": SERVERS, "cmdb_ci_service": SERVICES, "cmdb_rel_ci": RELATIONSHIPS}
    result = estate_cmdb.collect_cmdb(None, transport=_transport(tables), config=CONFIG)
    assert any("cmdb_ci_appl" in item for item in result["blocked"])
    assert "does not model it" in " ".join(result["limitations"])


def test_a_row_limit_is_reported_as_truncation():
    result = estate_cmdb.collect_cmdb(None, transport=_transport(total=5000), config=CONFIG)
    limitations = " ".join(result["limitations"])
    assert "were not read" in limitations
    assert "PARTIAL" in limitations


def test_cmdb_query_narrows_the_read():
    config = dict(CONFIG, query="install_status=1")
    seen: list[dict] = []
    estate_cmdb.collect_cmdb(None, transport=_transport(seen=seen), config=config)
    assert all(call["params"]["sysparm_query"] == ["install_status=1"] for call in seen)


def test_cmdb_assets_flow_into_the_estate_graph():
    result = estate_cmdb.collect_cmdb(None, transport=_transport(), config=CONFIG)
    report = estate_discovery.run(None, persist=False, collectors={"CMDB": lambda _db, **_: result})
    assert report["summary"]["assets"] >= 4
    cmdb = next(item for item in report["collectors"] if item["plane"] == "CMDB")
    assert cmdb["status"] in {"COMPLETE", "PARTIAL"}
    assert report["bom_counts"]["TECHBOM"] >= 1


def test_relationship_direction_follows_the_servicenow_type_name():
    # "Parent side::Child side" — a service that is *used by* an app means the app
    # depends on the service, so the edge is reversed, not silently drawn backwards
    assert estate_cmdb.relationship_mapping("Runs on::Runs") == ("runs_on", False)
    assert estate_cmdb.relationship_mapping("Depends on::Used by") == ("depends_on", False)
    assert estate_cmdb.relationship_mapping("Used by::Uses") == ("depends_on", True)
    assert estate_cmdb.relationship_mapping("Contains::Contained by") == ("contains", False)
    assert estate_cmdb.relationship_mapping("Contains::Contained by") == ("contains", False)
    assert estate_cmdb.relationship_mapping("Hosted on::Hosts") == ("hosted_on", False)
    assert estate_cmdb.relationship_mapping("Connects to::Connected from") == (None, False)
    assert estate_cmdb.relationship_mapping("") == (None, False)
