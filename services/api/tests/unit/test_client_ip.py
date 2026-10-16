"""The proxy-trust boundary for client-IP resolution (§4.8, round 70).

Before this, the API-key IP allowlist read X-Forwarded-For's FIRST entry
unconditionally — a header any client can write — so a key restricted to
one address was satisfied by sending that address in the header: the
network restriction was decorative. Rate limiting and login-lockout
buckets used the raw socket, which behind a real proxy lumps every user
into one bucket. These tests pin the boundary in both directions:

* unconfigured (default): the header is fiction; only the socket counts;
* configured: the OUTERMOST trusted hop wins — everything the client
  wrote to the left of it stays untrusted;
* fewer hops than declared, or an untrusted socket with CIDRs set: the
  socket wins.
"""

from __future__ import annotations

import pytest
from starlette.requests import Request


def _request(forwarded: str | None, socket_ip: str = "203.0.113.9") -> Request:
    headers = [("x-forwarded-for", forwarded)] if forwarded is not None else []
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [(k.encode(), v.encode()) for k, v in headers],
        "query_string": b"",
        "client": (socket_ip, 51234),
    }
    return Request(scope)


class _Settings:
    def __init__(self, count=0, cidrs=""):
        self.TRUSTED_PROXY_COUNT = count
        self.TRUSTED_PROXY_CIDRS = cidrs


# --------------------------------------------------------------------------- #
# the resolution rule itself
# --------------------------------------------------------------------------- #

def test_unconfigured_ignores_the_header_entirely():
    from api.security.client_ip import client_ip

    r = _request(forwarded="10.0.0.5, 198.51.100.7")
    assert client_ip(r, trusted_proxy_count=0) == "203.0.113.9"
    # the default (no explicit count) is the same secure posture
    assert client_ip(r, trusted_proxy_count=None, trusted_proxy_cidrs="") == "203.0.113.9"


def test_configured_proxy_takes_the_outermost_trusted_hop():
    from api.security.client_ip import client_ip

    # one trusted proxy: the rightmost entry is what nginx observed
    r = _request(forwarded="10.0.0.5, 198.51.100.7")
    assert client_ip(r, trusted_proxy_count=1) == "198.51.100.7"
    # two: the second from the right is what the outermost proxy observed
    assert client_ip(r, trusted_proxy_count=2) == "10.0.0.5"


def test_a_prepended_spoof_stays_left_of_the_trusted_hop():
    """THE bug: the old code took the FIRST entry, so a client could
    prepend an allowed address in front of its real one."""
    from api.security.client_ip import client_ip

    # the client sent 'X-Forwarded-For: 10.0.0.5' and nginx appended the
    # client's real address — the spoof is left of the trusted hop
    r = _request(forwarded="10.0.0.5, 203.0.113.9")
    assert client_ip(r, trusted_proxy_count=1) == "203.0.113.9"


def test_fewer_entries_than_the_declared_topology_falls_back_to_the_socket():
    from api.security.client_ip import client_ip

    r = _request(forwarded="10.0.0.5")  # one entry, but two proxies declared
    assert client_ip(r, trusted_proxy_count=2) == "203.0.113.9"
    r = _request(forwarded=None)
    assert client_ip(r, trusted_proxy_count=1) == "203.0.113.9"


def test_garbage_headers_degrade_to_the_socket():
    from api.security.client_ip import client_ip

    for garbage in ("", "   ", ",", " , , "):
        assert client_ip(_request(forwarded=garbage), trusted_proxy_count=1) == "203.0.113.9"


def test_cidrs_gate_the_header_on_the_socket_peer():
    from api.security.client_ip import client_ip

    r = _request(forwarded="10.0.0.5, 198.51.100.7", socket_ip="203.0.113.9")
    # peer outside the trusted network: header is fiction, socket wins
    assert client_ip(r, trusted_proxy_count=1,
                     trusted_proxy_cidrs="10.0.0.0/8") == "203.0.113.9"
    # peer inside it: the trusted hop is honored
    r2 = _request(forwarded="10.0.0.5, 198.51.100.7", socket_ip="10.1.2.3")
    assert client_ip(r2, trusted_proxy_count=1,
                     trusted_proxy_cidrs="10.0.0.0/8") == "198.51.100.7"
    # an exact proxy address matches too
    r3 = _request(forwarded="10.0.0.5, 198.51.100.7", socket_ip="10.1.2.3")
    assert client_ip(r3, trusted_proxy_count=1,
                     trusted_proxy_cidrs="10.1.2.3") == "198.51.100.7"
    # unparseable CIDR list fails closed
    assert client_ip(r2, trusted_proxy_count=1,
                     trusted_proxy_cidrs="not-a-cidr") == "10.1.2.3"


def test_settings_are_the_default_source_when_not_overridden(monkeypatch):
    from api.config.settings import get_settings
    from api.security.client_ip import client_ip

    get_settings.cache_clear()
    monkeypatch.setenv("TRUSTED_PROXY_COUNT", "1")
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS", "")
    r = _request(forwarded="10.0.0.5, 198.51.100.7")
    assert client_ip(r) == "198.51.100.7"
    get_settings.cache_clear()
    monkeypatch.setenv("TRUSTED_PROXY_COUNT", "0")
    assert client_ip(r) == "203.0.113.9"
    get_settings.cache_clear()


# --------------------------------------------------------------------------- #
# the security-critical consumer: the API-key IP allowlist
# --------------------------------------------------------------------------- #

class _KeyRow:
    def __init__(self, allowed):
        self.allowed_ips = allowed
        self.id = "key-1"


@pytest.mark.parametrize(
    "forwarded,allowed,expected",
    [
        # the allowlist is satisfied ONLY by the socket when unconfigured
        (None, "203.0.113.9", True),
        # the old bug: a header carrying the allowed address satisfied it
        ("10.0.0.5", "10.0.0.5", False),
        # ...also when the spoof is prepended in front of the real client
        ("10.0.0.5, 203.0.113.9", "10.0.0.5", False),
        # the socket matching the allowlist is allowed regardless of the header
        ("10.0.0.5", "203.0.113.9", True),
    ],
)
def test_api_key_allowlist_cannot_be_satisfied_by_a_header(forwarded, allowed, expected):
    """End-to-end through _authorize_key_policy with the default (direct)
    posture: whatever the client writes in X-Forwarded-For, the allowlist
    sees the socket address."""
    from api.security.client_ip import client_ip
    from identity.api_key_guard import ip_allowed

    r = _request(forwarded=forwarded, socket_ip="203.0.113.9")
    assert ip_allowed(client_ip(r), allowed) is expected


def test_configured_topology_still_enforces_against_the_real_client():
    from api.security.client_ip import client_ip
    from identity.api_key_guard import ip_allowed

    # deployed shape: one nginx hop, the client's real address is the
    # rightmost entry, and a prepended spoof must NOT pass
    r = _request(forwarded="10.0.0.5, 198.51.100.7")
    resolved = client_ip(r, trusted_proxy_count=1)
    assert resolved == "198.51.100.7"
    assert ip_allowed(resolved, "198.51.100.7") is True
    assert ip_allowed(resolved, "10.0.0.5") is False


# --------------------------------------------------------------------------- #
# the rate-limit identity bucket uses the same boundary
# --------------------------------------------------------------------------- #

def test_rate_limit_ip_bucket_follows_the_boundary(monkeypatch):
    from api.config.settings import get_settings
    from api.middleware.rate_limit import _identity

    get_settings.cache_clear()
    monkeypatch.setenv("TRUSTED_PROXY_COUNT", "0")
    r = _request(forwarded="1.2.3.4")
    assert _identity(r) == "ip:203.0.113.9"

    get_settings.cache_clear()
    monkeypatch.setenv("TRUSTED_PROXY_COUNT", "1")
    r2 = _request(forwarded="spoofed, 198.51.100.7")
    assert _identity(r2) == "ip:198.51.100.7"
    get_settings.cache_clear()
