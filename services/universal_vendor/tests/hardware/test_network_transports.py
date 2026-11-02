"""NETCONF and RESTCONF: the two doors that are not SNMP.

No device is contacted. NETCONF is driven through an injected ``exchange`` that
speaks the wire format, RESTCONF through an injected ``fetch`` that returns the
JSON a device would return — both on the production code path, including the
ssh argv builder that would be used on a real host.
"""

from __future__ import annotations

import json

import pytest

from universal_vendor.hardware.discovery import NetworkBasedDiscovery
from universal_vendor.hardware.host.credentials import (
    CredentialLeakRefused,
    refuse_credential_echo,
    refuse_secret_shapes,
)
from universal_vendor.hardware.host.device_observation import to_observation
from universal_vendor.hardware.host.netconf import (
    BASE_10,
    BASE_11,
    NetconfCollector,
    NetconfError,
    SshNetconfTransport,
    TransportUnavailable,
    build_get,
    build_hello,
    parse_hello,
    parse_rpc_reply,
    select_chassis,
)
from universal_vendor.hardware.host.restconf import (
    HARDWARE_PATH,
    SYSTEM_PATH,
    HttpsRestconfTransport,
    RestconfCollector,
    RestconfError,
    authorization_header,
    parse_hardware,
    parse_system,
    strip_prefix,
)

HELLO = (
    '<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities>'
    f"<capability>{BASE_10}</capability>"
    f"<capability>{BASE_11}</capability>"
    "<capability>urn:ietf:params:xml:ns:yang:ietf-hardware</capability>"
    "</capabilities><session-id>42</session-id></hello>"
)

REPLY = """<rpc-reply message-id="1" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <data>
    <system xmlns="urn:ietf:params:xml:ns:yang:ietf-system">
      <hostname>core-fw-01</hostname>
      <location>DXB-DC1-ROW3</location>
    </system>
    <hardware xmlns="urn:ietf:params:xml:ns:yang:ietf-hardware">
      <component>
        <name>Chassis</name><class>chassis</class>
        <serial-num>FDO2140A1B2</serial-num><model-name>C9300-48P</model-name>
        <firmware-rev>17.9.4a</firmware-rev><manufacturer>Cisco</manufacturer>
      </component>
      <component>
        <name>Fan tray 1</name><class>module</class><serial-num>FAN-0001</serial-num>
      </component>
    </hardware>
  </data>
</rpc-reply>"""

ERROR_REPLY = """<rpc-reply message-id="1" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <rpc-error><error-type>protocol</error-type>
    <error-tag>access-denied</error-tag>
    <error-message>access denied for user netops</error-message></rpc-error>
</rpc-reply>"""

HARDWARE_JSON = {"ietf-hardware:hardware": {"component": [
    {"name": "Chassis", "class": "chassis", "serial-num": "JNP-7788",
     "model-name": "EX4300-48T", "firmware-rev": "21.4R3", "manufacturer": "Juniper"},
    {"name": "Fan 1", "class": "module", "serial-num": "FAN-J1"},
]}}
SYSTEM_JSON = {"ietf-system:system": {"hostname": "edge-sw-02", "location": "DXB-DC2"}}


def netconf_replies(hello: str = HELLO, reply: str = REPLY):
    seen: list[str] = []

    def exchange(host, request):
        seen.append(request)
        return hello if "<hello" in request else reply

    exchange.seen = seen  # type: ignore[attr-defined]
    return exchange


def restconf_fetch(payloads=None):
    payloads = payloads or {SYSTEM_PATH: SYSTEM_JSON, HARDWARE_PATH: HARDWARE_JSON}
    calls: list[str] = []

    def fetch(base_url, path):
        calls.append(path)
        return payloads[path]

    fetch.calls = calls  # type: ignore[attr-defined]
    return fetch


# --------------------------------------------------------------------------- #
# NETCONF protocol
# --------------------------------------------------------------------------- #

def test_hello_is_parsed_and_a_common_base_is_found():
    capabilities = parse_hello(HELLO)
    assert BASE_11 in capabilities
    assert "urn:ietf:params:xml:ns:yang:ietf-hardware" in capabilities


def test_hello_that_is_not_hello_is_an_error():
    with pytest.raises(NetconfError):
        parse_hello("<rpc-reply/>")


def test_get_carries_no_edit_config():
    request = build_get()
    assert "<get>" in request
    assert "edit-config" not in request, "the collector is read-only by construction"


def test_reply_yields_system_and_components():
    reply = parse_rpc_reply(REPLY)
    assert reply.ok is True
    assert reply.data["system"]["hostname"] == "core-fw-01"
    assert len(reply.data["components"]) == 2
    assert reply.data["components"][0]["serial-num"] == "FDO2140A1B2"


def test_rpc_error_is_read_not_raised():
    reply = parse_rpc_reply(ERROR_REPLY)
    assert reply.ok is False
    assert reply.error == "access denied for user netops"
    assert reply.error_type == "protocol"


def test_empty_reply_is_a_closed_session():
    assert parse_rpc_reply("").ok is False


def test_chassis_beats_a_fan_tray():
    components = [
        {"class": "module", "serial-num": "FAN-0001"},
        {"class": "chassis", "serial-num": "FDO2140A1B2"},
    ]
    assert select_chassis(components)["serial-num"] == "FDO2140A1B2"
    assert select_chassis([]) is None


# --------------------------------------------------------------------------- #
# NETCONF collection
# --------------------------------------------------------------------------- #

def test_a_firewall_arrives_with_identity():
    facts = NetconfCollector(exchange=netconf_replies()).collect("core-fw-01")
    assert facts.reachable is True
    assert facts.transport == "netconf"
    assert facts.vendor == "Cisco"
    assert facts.model == "C9300-48P"
    assert facts.serial_reference == "FDO2140A1B2"
    assert facts.firmware == "17.9.4a"
    assert facts.sys_name == "core-fw-01"
    assert facts.context["asset_id"] == "core-fw-01"


def test_the_session_negotiates_before_it_asks():
    exchange = netconf_replies()
    NetconfCollector(exchange=exchange).collect("core-fw-01")
    assert "<hello" in exchange.seen[0]
    assert "<get>" in exchange.seen[1]


def test_an_rpc_error_is_a_reason_not_an_empty_device():
    facts = NetconfCollector(exchange=netconf_replies(reply=ERROR_REPLY)).collect("core-fw-01")
    assert facts.reachable is False
    assert "access denied" in facts.unavailable[0]
    assert "not an empty device" in facts.unavailable[0]


def test_no_common_base_capability_is_refused():
    hello = '<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities>' \
            '<capability>urn:example:vendor-only</capability></capabilities></hello>'
    facts = NetconfCollector(exchange=netconf_replies(hello=hello)).collect("core-fw-01")
    assert facts.reachable is False
    assert "no common NETCONF base capability" in facts.unavailable[0]


def test_a_broken_session_is_a_fact():
    def broken(host, request):
        raise NetconfError("connection reset by peer")

    facts = NetconfCollector(exchange=broken).collect("core-fw-01")
    assert facts.unavailable == ["netconf core-fw-01: connection reset by peer"]


def test_ssh_argv_is_fixed_and_host_is_validated():
    argv = SshNetconfTransport.build_argv("core-fw-01")
    assert argv[0] == "ssh"
    assert argv[-2:] == ["-s", "netconf"]
    assert "--" in argv, "the positional must come after --"
    for bad in ("host; rm -rf /", "-oProxyCommand=touch /tmp/x", "host name", ""):
        with pytest.raises(NetconfError):
            SshNetconfTransport.build_argv(bad)


def test_ssh_runs_a_list_not_a_string(monkeypatch):
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs

        class Done:
            returncode = 0
            stdout = HELLO
            stderr = ""

        return Done()

    monkeypatch.setattr("subprocess.run", fake_run)
    monkeypatch.setattr("shutil.which", lambda _binary: "/usr/bin/ssh")
    transport = SshNetconfTransport()
    transport("core-fw-01", build_hello())
    assert isinstance(captured["argv"], list)
    assert captured["kwargs"]["shell"] is False
    assert captured["argv"][0] == "/usr/bin/ssh"


def test_a_missing_ssh_client_is_stated(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _binary: None)
    with pytest.raises(TransportUnavailable):
        SshNetconfTransport()("core-fw-01", build_hello())


# --------------------------------------------------------------------------- #
# RESTCONF
# --------------------------------------------------------------------------- #

def test_restconf_prefixes_are_stripped():
    assert strip_prefix({"ietf-system:system": {"hostname": "x"}}) == \
        {"system": {"hostname": "x"}}
    assert parse_system(SYSTEM_JSON)["hostname"] == "edge-sw-02"


def test_restconf_accepts_one_component_or_many():
    one = {"ietf-hardware:hardware": {"component": {"class": "chassis",
                                                    "serial-num": "S1"}}}
    assert len(parse_hardware(one)) == 1
    assert len(parse_hardware(HARDWARE_JSON)) == 2
    assert parse_hardware({}) == []


def test_a_switch_arrives_over_restconf_too():
    facts = RestconfCollector(fetch=restconf_fetch()).collect("https://10.0.0.5")
    assert facts.reachable is True
    assert facts.transport == "restconf"
    assert facts.vendor == "Juniper"
    assert facts.model == "EX4300-48T"
    assert facts.serial_reference == "JNP-7788"
    assert facts.firmware == "21.4R3"
    assert facts.context["asset_id"] == "edge-sw-02"


def test_both_transports_produce_the_same_observation_shape():
    netconf_facts = NetconfCollector(exchange=netconf_replies()).collect("core-fw-01")
    restconf_facts = RestconfCollector(fetch=restconf_fetch()).collect("https://10.0.0.5")
    netconf_observation = to_observation(netconf_facts)
    restconf_observation = to_observation(restconf_facts)
    assert netconf_observation.device_type == restconf_observation.device_type == "switch"
    assert netconf_observation.serial_reference == "FDO2140A1B2"
    assert restconf_observation.serial_reference == "JNP-7788"
    assert netconf_observation.vendor_specific["transport"] == "netconf"
    assert restconf_observation.vendor_specific["transport"] == "restconf"


def test_the_context_feeds_network_discovery_for_both():
    for facts in (
        NetconfCollector(exchange=netconf_replies()).collect("core-fw-01"),
        RestconfCollector(fetch=restconf_fetch()).collect("https://10.0.0.5"),
    ):
        records = NetworkBasedDiscovery().collect(facts.context)
        assert len(records) == 1
        assert records[0]["vendor_specific"]["protocol"] in {"netconf", "restconf"}


def test_cleartext_is_refused():
    with pytest.raises(RestconfError):
        HttpsRestconfTransport._url("http://10.0.0.5")
    assert HttpsRestconfTransport._url("https://10.0.0.5") == "https://10.0.0.5"


def test_a_device_without_ietf_hardware_says_so():
    facts = RestconfCollector(fetch=restconf_fetch(payloads={
        SYSTEM_PATH: SYSTEM_JSON, HARDWARE_PATH: {}})).collect("https://10.0.0.5")
    assert facts.reachable is True
    assert facts.serial_reference is None
    assert "no components" in facts.unavailable[0]


def test_a_restconf_failure_is_a_reason():
    def broken(base_url, path):
        raise RestconfError("HTTP 401 on /restconf/data/ietf-system:system")

    facts = RestconfCollector(fetch=broken).collect("https://10.0.0.5")
    assert facts.reachable is False
    assert "HTTP 401" in facts.unavailable[0]


def test_basic_auth_is_encoded_and_bearer_is_sent_as_is():
    assert authorization_header("user:pass")["Authorization"].startswith("Basic ")
    assert authorization_header("token-value")["Authorization"] == "Bearer token-value"
    with pytest.raises(RestconfError):
        authorization_header("")


def test_the_credential_is_applied_to_the_request_not_the_facts():
    seen = {}

    class Response:
        def read(self):
            return json.dumps(SYSTEM_JSON).encode()

    def opener(request):
        seen["headers"] = dict(request.headers)
        seen["url"] = request.full_url
        return Response()

    transport = HttpsRestconfTransport(opener=opener, credential="topsecret-token")
    transport("https://10.0.0.5", SYSTEM_PATH)
    assert seen["headers"]["Authorization"] == "Bearer topsecret-token"
    assert seen["url"].startswith("https://10.0.0.5/restconf")


# --------------------------------------------------------------------------- #
# the shared credential rule
# --------------------------------------------------------------------------- #

def test_a_device_that_echoes_the_credential_is_refused():
    """NETCONF: the credential reference must not come back in a device field."""
    # The echo has to land in a field the collector carries, or the test proves
    # nothing: <name> is dropped, <model-name> is inventoried.
    device_echo = REPLY.replace("<model-name>C9300-48P</model-name>",
                                "<model-name>topsecret-token</model-name>")
    with pytest.raises(CredentialLeakRefused):
        NetconfCollector(exchange=netconf_replies(reply=device_echo)).collect(
            "core-fw-01", credential_ref="topsecret-token")


def test_the_restconf_side_refuses_it_too():
    echoed = {"ietf-hardware:hardware": {"component": [{
        "class": "chassis", "serial-num": "S1", "model-name": "topsecret-token"}]}}
    with pytest.raises(CredentialLeakRefused):
        RestconfCollector(fetch=restconf_fetch(payloads={
            SYSTEM_PATH: SYSTEM_JSON, HARDWARE_PATH: echoed})).collect(
                "https://10.0.0.5", credential_ref="topsecret-token")


def test_secret_shaped_fields_are_refused_whatever_the_transport():
    with pytest.raises(CredentialLeakRefused):
        refuse_secret_shapes({"config": {"password": "x"}}, host="h")
    refuse_secret_shapes({"config": {"hostname": "x"}}, host="h")


def test_a_short_credential_is_not_echo_matched():
    """Matching a 1-character credential would refuse every honest device."""
    refuse_credential_echo({"descr": "a"}, "a", host="h")
