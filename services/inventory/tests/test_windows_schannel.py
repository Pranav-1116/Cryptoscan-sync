"""Schannel policy evaluation is portable; the native registry read is not.

The evaluation logic is the part that must be right, and it is testable on the
platform the whole suite runs on. These tests pin the distinctions that make a
policy read useful instead of misleading:

* an absent key means Windows' built-in default, not "disabled" and not "unknown";
* ``DisabledByDefault`` is its own state, not the same as ``Enabled=0``;
* the floor is derived from what is offered, and a deprecated version that is
  offered is named;
* the report never claims a negotiation happened.
"""

from __future__ import annotations

import pytest

from inventory import windows_schannel as schannel


def reader(mapping: dict[str, dict[str, object]]):
    def read(path: str):
        return mapping.get(path)

    return read


def _protocol_key(subkey: str) -> str:
    return f"{schannel.PROTOCOLS_KEY}\\{subkey}"


def _with_role(subkey: str, role: str, **values) -> dict[str, dict[str, object]]:
    return {_protocol_key(subkey): {"__subkeys__": {role: values}}}


def _both_roles(subkey: str, **values) -> dict[str, dict[str, object]]:
    """One protocol key with Server and Client configured the same way.

    Building the two roles in a single mapping matters: merging two
    ``_with_role`` results would replace the key and silently leave one role
    unconfigured — which correctly reads as Windows' default, not as disabled.
    """
    return {_protocol_key(subkey): {"__subkeys__": {"Server": values, "Client": values}}}


def test_absent_keys_are_unknown_not_enabled_and_not_disabled():
    report = schannel.evaluate(reader({}))
    # nothing configured: every protocol is on Windows' default, which this build
    # does not restate as a floor
    assert report["protocols"]["TLSv1.2"]["server"]["state"] == "DEFAULT"
    assert report["protocols"]["TLSv1.2"]["server"]["enabled"] is None
    assert report["protocols"]["TLSv1.2"]["offered"] is None
    assert report["offered_versions"] == []
    assert report["tls_floor"] is None
    assert len(report["unconfigured_versions"]) == len(schannel.PROTOCOL_KEYS)
    assert "does not reproduce that default" in report["tls_floor_basis"]
    assert any(item["id"] == "BUILTIN_POLICY_APPLIES" for item in report["findings"])
    assert not any(item["id"] == "DEPRECATED_PROTOCOL_ENABLED" for item in report["findings"])


def test_explicitly_disabled_versions_lower_the_floor_and_remove_the_finding():
    state: dict[str, dict[str, object]] = {}
    for subkey in ("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"):
        state.update(_both_roles(subkey, Enabled=0))
    state.update(_both_roles("TLS 1.2", Enabled=1))
    report = schannel.evaluate(reader(state))

    assert report["tls_floor"] == "TLSv1.2"
    assert report["disabled_versions"][:4] == ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]
    assert report["deprecated_versions_enabled"] == []
    assert report["protocols"]["SSLv3"]["server"]["state"] == "DISABLED"
    assert not any(item["id"] == "DEPRECATED_PROTOCOL_ENABLED" for item in report["findings"])


def test_disabled_by_default_is_its_own_state():
    state = _with_role("TLS 1.0", "Server", Enabled=1, DisabledByDefault=1)
    report = schannel.evaluate(reader(state))
    server = report["protocols"]["TLSv1.0"]["server"]
    assert server["state"] == "DISABLED_BY_DEFAULT"
    assert server["enabled"] is True
    assert "explicitly asks" in server["reason"]
    # it is still offered because a role may ask for it
    assert report["protocols"]["TLSv1.0"]["offered"] is True


def test_dword_and_string_values_both_parse():
    dword = schannel.evaluate(reader(_with_role("TLS 1.0", "Server", Enabled=0)))
    assert dword["protocols"]["TLSv1.0"]["server"]["enabled"] is False
    text = schannel.evaluate(reader(_with_role("TLS 1.0", "Server", Enabled="false")))
    assert text["protocols"]["TLSv1.0"]["server"]["enabled"] is False
    unknown = schannel.evaluate(reader(_with_role("TLS 1.0", "Server", Enabled="maybe")))
    assert unknown["protocols"]["TLSv1.0"]["server"]["state"] == "DEFAULT"
    assert unknown["protocols"]["TLSv1.0"]["server"]["enabled"] is None


def test_server_and_client_roles_are_read_separately():
    state = {
        _protocol_key("TLS 1.0"): {"__subkeys__": {"Server": {"Enabled": 0}, "Client": {"Enabled": 1}}}
    }
    report = schannel.evaluate(reader(state))
    protocol = report["protocols"]["TLSv1.0"]
    assert protocol["server"]["state"] == "DISABLED"
    assert protocol["client"]["state"] == "ENABLED"
    assert protocol["offered"] is True


def test_cipher_suite_order_is_read_from_the_policy_key_first():
    state = {
        schannel.CIPHER_ORDER_KEY: {"Functions": "TLS_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
        schannel.CIPHER_PREFERENCE_KEY: {"Functions": "TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
    }
    report = schannel.evaluate(reader(state))
    assert report["cipher_suite_order_source"] == schannel.CIPHER_ORDER_KEY
    assert report["cipher_suite_count"] == 2
    assert report["weak_suites_in_order"] == []

    state[schannel.CIPHER_ORDER_KEY] = {"Functions": "TLS_RSA_WITH_3DES_EDE_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA"}
    report = schannel.evaluate(reader(state))
    assert report["weak_suites_in_order"] == ["TLS_RSA_WITH_3DES_EDE_CBC_SHA"]
    assert any(item["id"] == "WEAK_SUITE_IN_ORDER" for item in report["findings"])


def test_no_order_policy_is_reported_rather_than_invented():
    report = schannel.evaluate(reader({}))
    assert report["cipher_suite_order"] == []
    assert report["cipher_suite_order_source"] is None
    finding = next(item for item in report["findings"] if item["id"] == "NO_CIPHER_SUITE_ORDER_POLICY")
    # the platform refuses to reproduce Windows' built-in list from documentation
    assert "version-specific" in finding["detail"]


def test_the_report_never_claims_a_negotiation():
    report = schannel.evaluate(reader({}))
    assert "policy" in report["meaning"]
    assert "not a record of what any application negotiated" in report["meaning"]


def test_native_reader_refuses_off_windows():
    from inventory.host import Refused

    if __import__("sys").platform == "win32":
        pytest.skip("native reader is available here")
    with pytest.raises(Refused) as refusal:
        schannel.windows_reader()(schannel.PROTOCOLS_KEY)
    assert refusal.value.reason == "PLATFORM"


def test_collect_charges_the_run_budget(monkeypatch):
    charged: list[int] = []
    monkeypatch.setattr(schannel, "windows_reader", lambda: reader({}))
    report = schannel.collect(None, limit=64, charge=charged.append)
    assert charged and sum(charged) > 0
    assert report["schema"] == schannel.SCHEMA
    assert report["tls_floor"] is None
