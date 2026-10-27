"""Client-IP resolution behind an explicit, configured proxy-trust boundary
(§4.8, round 70).

Before this module, the API-key IP allowlist read ``X-Forwarded-For`` and
took its FIRST entry unconditionally — a header any client can write.
A key restricted to ``10.0.0.5`` was satisfied by merely sending
``X-Forwarded-For: 10.0.0.5``: the network restriction was decorative.
The first entry is also the wrong end even behind a real proxy: nginx
($proxy_add_x_forwarded_for) APPENDS the address it observed, so the
client-controlled part is everything to the LEFT of the hops you own.

The rule here is the standard one:

* ``TRUSTED_PROXY_COUNT = 0`` (default, secure): the client IP is the
  socket address. Forwarded headers are client-supplied fiction and are
  ignored entirely.
* ``TRUSTED_PROXY_COUNT = N >= 1``: the rightmost N entries were appended
  by proxies you own; the client is the address the OUTERMOST trusted
  proxy observed — entry ``-N``. Anything left of that is untrusted.
  Fewer entries than N means the request did not come through the
  declared topology (direct connection, misconfigured LB): the socket
  wins.
* ``TRUSTED_PROXY_CIDRS`` (optional, closes the last hole): when set,
  forwarded headers are honored only if the socket peer itself is inside
  a trusted network. Without it, ``COUNT >= 1`` trusts the header from
  ANY peer — correct when the API is only reachable through the proxy
  (the deployed topology: the API service exposes no ports), wrong if a
  client can reach the API directly and knows to send a header.

One function is the authority; restating its logic elsewhere is how the
first-entry bug happened.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from starlette.requests import Request


def _effective_count(settings: Any = None) -> int:
    """The configured trusted-proxy hop count, clamped to >= 0."""
    if settings is None:
        try:
            from api.config.settings import get_settings

            settings = get_settings()
        except Exception:  # pragma: no cover - settings unavailable in odd harnesses
            return 0
    try:
        count = int(getattr(settings, "TRUSTED_PROXY_COUNT", 0) or 0)
    except (TypeError, ValueError):
        return 0
    return max(count, 0)


def _socket_allowed(socket_ip: str | None, cidrs: str) -> bool:
    """True when the peer is inside a configured trusted network.

    An empty CIDR list means "no restriction" (the header may be honored
    from any peer — see the module docstring for when that is and is not
    sound). A present-but-unparseable list fails closed: the socket wins.
    """
    if not cidrs:
        return True
    if not socket_ip:
        return False
    try:
        peer = ipaddress.ip_address(socket_ip)
    except ValueError:
        return False
    for token in str(cidrs).split(","):
        token = token.strip()
        if not token:
            continue
        try:
            if "/" in token:
                if peer in ipaddress.ip_network(token, strict=False):
                    return True
            elif peer == ipaddress.ip_address(token):
                return True
        except ValueError:
            continue
    return False


def client_ip(request: Request, *, trusted_proxy_count: int | None = None,
              trusted_proxy_cidrs: str | None = None) -> str | None:
    """The client IP for this request under the configured trust boundary.

    Never raises: an unparseable header, a missing socket or a broken
    configuration all degrade to the socket address (the address you
    actually accepted the connection from), which is the only value that
    cannot be forged by header content.
    """
    socket_ip = request.client.host if request.client else None
    count = _effective_count() if trusted_proxy_count is None else max(int(trusted_proxy_count or 0), 0)
    if count <= 0:
        return socket_ip

    if trusted_proxy_cidrs is None:
        try:
            from api.config.settings import get_settings

            trusted_proxy_cidrs = str(getattr(get_settings(), "TRUSTED_PROXY_CIDRS", "") or "")
        except Exception:  # pragma: no cover - settings unavailable in odd harnesses
            trusted_proxy_cidrs = ""
    if not _socket_allowed(socket_ip, trusted_proxy_cidrs):
        return socket_ip

    forwarded = request.headers.get("x-forwarded-for", "")
    entries = [e.strip() for e in forwarded.split(",") if e.strip()]
    if len(entries) < count:
        # fewer hops than the declared topology — direct or misrouted;
        # the socket is the only trustworthy address
        return socket_ip
    return entries[-count]
