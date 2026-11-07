"""Read-only transports: the only place this integration touches a live device.

Guide 181 built the contract and fed it recorded fixtures; a vendor's ``endpoints`` were
documentation. This module makes them executable, and it is deliberately the *only* code that
opens a socket or a file on a device.

Four promises, each one a mechanism rather than a convention:

**1. Read-only at the transport, not at the adapter.** :meth:`HttpTransport.request` accepts
``GET`` and ``HEAD`` and nothing else. The adapter's declaration is already checked when its
spec is built (:class:`~cbom.security_controls.base.AdapterSpec`); this is the second lock, on
the code path that actually sends bytes. A test aims a ``POST`` at it and expects a refusal.

**2. Credentials come from a secret manager, never from code.** A caller passes a
:class:`SecretSource` — an absolute path to an operator-owned file (``*_FILE``), an environment
variable, or a vault reference that resolves through the same files. The resolved value lives
in :class:`Credential`, whose ``repr`` and ``__str__`` are redacted, so a token cannot reach a
log line, a traceback or an evidence record by being formatted.

**3. The taxonomy is part of the answer.** A device that answered ``401`` is not a device that
was down; a device that answered three of seven sections is not a device that was read.
:class:`TransportResult.state` is one of ``OK``, ``AUTH_FAILED``, ``UNREACHABLE``,
``RATE_LIMITED``, ``BAD_RESPONSE``, ``PARTIAL_READ``, and ``REFUSED``, and the caller must
carry it into the snapshot rather than reduce it to an exception.

**4. TLS is verified unless a deployment says otherwise, out loud.** ``verify`` takes ``True``
or a CA bundle path. ``verify=False`` raises unless ``allow_insecure=True`` is passed *and* the
health record reports ``tls_verified: False``, so an unverified read can never look like a
verified one.
"""

from __future__ import annotations

import json
import os
import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Protocol
from urllib.parse import urljoin, urlsplit

from .base import ControlRefused, _norm, scrub

# --------------------------------------------------------------------------- #
# States
# --------------------------------------------------------------------------- #

OK = "OK"
AUTH_FAILED = "AUTH_FAILED"
UNREACHABLE = "UNREACHABLE"
RATE_LIMITED = "RATE_LIMITED"
BAD_RESPONSE = "BAD_RESPONSE"
PARTIAL_READ = "PARTIAL_READ"
REFUSED = "REFUSED"

#: the states a caller may be told about, strongest first
STATES: tuple[str, ...] = (OK, PARTIAL_READ, AUTH_FAILED, RATE_LIMITED, BAD_RESPONSE,
                           UNREACHABLE, REFUSED)

#: methods the transport will send. Not a preference list — an allow-list.
READ_METHODS: frozenset[str] = frozenset({"GET", "HEAD"})

#: HTTP statuses, mapped rather than lumped into "error"
_STATUS_STATE: dict[int, str] = {
    401: AUTH_FAILED, 403: AUTH_FAILED, 407: AUTH_FAILED,
    429: RATE_LIMITED,
    408: UNREACHABLE, 502: UNREACHABLE, 503: UNREACHABLE, 504: UNREACHABLE,
}


# --------------------------------------------------------------------------- #
# Credentials
# --------------------------------------------------------------------------- #

class Credential:
    """A secret that refuses to be printed, logged or serialised into evidence."""

    __slots__ = ("_value", "source", "key")

    def __init__(self, value: str, *, source: str, key: str = "") -> None:
        self._value = str(value or "")
        self.source = source
        self.key = key

    def reveal(self) -> str:
        """The only accessor. Named so that its call sites are greppable in a review."""
        return self._value

    def __repr__(self) -> str:  # pragma: no cover — prove-by-test
        return f"Credential(source={self.source!r}, value=[REDACTED])"

    __str__ = __repr__

    def __format__(self, _spec: str) -> str:
        return repr(self)

    def __bool__(self) -> bool:
        return bool(self._value)

    def fingerprint(self) -> str:
        """A stable, non-reversible tag for correlating two uses of one credential."""
        import hashlib

        if not self._value:
            return ""
        return "sha256:" + hashlib.sha256(self._value.encode("utf-8")).hexdigest()[:16]


class SecretSource:
    """Resolve a credential from the bank's secret manager — never from this repository.

    ``kind`` is ``file`` (an absolute, operator-owned path, mode 0600, not a symlink),
    ``env`` (a variable the deployment injects) or ``vault`` (a reference resolved by the
    site's own agent into a file, which is all this process is allowed to see).
    """

    def __init__(self, *, kind: str, reference: str) -> None:
        self.kind = _norm(kind).lower()
        self.reference = _norm(reference)
        if self.kind not in {"file", "env", "vault"}:
            raise ControlRefused("UNKNOWN_SECRET_SOURCE",
                                 f"{self.kind or '(none)'} is not a secret source; use file, "
                                 "env or vault")

    def resolve(self, *, required: bool = True) -> Credential:
        if not self.reference:
            if required:
                raise ControlRefused("SECRET_NOT_CONFIGURED",
                                     "a credential reference is required and none was given")
            return Credential("", source=self.kind)
        if self.kind == "env":
            value = os.environ.get(self.reference, "")
            if required and not value:
                raise ControlRefused("SECRET_NOT_CONFIGURED",
                                     f"environment variable {self.reference} is empty")
            return Credential(value, source=f"env:{self.reference}", key=self.reference)
        path = Path(self.reference)
        if not path.is_absolute():
            raise ControlRefused(
                "SECRET_PATH_NOT_ABSOLUTE",
                f"{self.reference!r} must be an absolute path owned by the operator; a "
                "relative path is a file next to the code, which is where secrets leak from")
        if not path.is_file() or path.is_symlink():
            if required:
                raise ControlRefused("SECRET_NOT_CONFIGURED",
                                     f"{self.reference} is not a readable regular file")
            return Credential("", source=f"{self.kind}:{self.reference}")
        mode = path.stat().st_mode & 0o777
        if mode & 0o077:
            raise ControlRefused(
                "SECRET_FILE_PERMISSIONS",
                f"{self.reference} is mode {mode:o}; a credential file must not grant "
                "group or other access (use 0600)")
        return Credential(path.read_text(encoding="utf-8").strip(),
                          source=f"{self.kind}:{self.reference}", key=self.reference)

    @classmethod
    def from_env(cls, variable: str, *, required: bool = True) -> Credential:
        """The common case: ``..._TOKEN_FILE`` next to ``..._TOKEN`` in the deployment."""
        file_variable = f"{variable}_FILE"
        if os.environ.get(file_variable):
            return cls(kind="file", reference=os.environ[file_variable]).resolve(
                required=required)
        return cls(kind="env", reference=variable).resolve(required=required)


# --------------------------------------------------------------------------- #
# Results
# --------------------------------------------------------------------------- #

@dataclass
class TransportResult:
    """One read attempt, with the state a reviewer needs to judge it."""

    url: str
    method: str = "GET"
    status: int = 0
    state: str = OK
    body: Any = None
    reason: str = ""
    attempts: int = 0
    elapsed_ms: int = 0
    retry_after: float | None = None
    pages: int = 1
    link: str | None = None

    @property
    def ok(self) -> bool:
        return self.state in {OK, PARTIAL_READ}

    def as_dict(self) -> dict[str, Any]:
        return {
            "url": self.url, "method": self.method, "status": self.status,
            "state": self.state, "reason": self.reason, "attempts": self.attempts,
            "elapsed_ms": self.elapsed_ms, "pages": self.pages,
        }


def worst_state(states: Iterable[str]) -> str:
    """The state a set of reads deserves: never ``OK`` if any one of them was not."""
    found = [state for state in states if state]
    for state in (REFUSED, AUTH_FAILED, UNREACHABLE, RATE_LIMITED, BAD_RESPONSE, PARTIAL_READ):
        if state in found:
            return state
    return OK if found else UNREACHABLE


# --------------------------------------------------------------------------- #
# The transport contract
# --------------------------------------------------------------------------- #

class ReadOnlyTransport(Protocol):
    """What a driver may call. Two read verbs, and a health record."""

    def get(self, path: str, *, params: Mapping[str, Any] | None = None) -> TransportResult:
        ...

    def health(self) -> dict[str, Any]:
        ...


# --------------------------------------------------------------------------- #
# Where a credential-bearing request is allowed to go
# --------------------------------------------------------------------------- #

def _origin(url: str) -> tuple[str, str, int]:
    """The ``(scheme, host, port)`` a URL points at. The port defaults per scheme, never guesses."""
    parts = urlsplit(url)
    scheme = (parts.scheme or "").lower()
    host = (parts.hostname or "").lower()
    try:
        port = parts.port
    except ValueError:
        port = -1
    if port is None:
        port = 443 if scheme == "https" else 80 if scheme == "http" else 0
    return scheme, host, port


def _url_userinfo(url: str) -> bool:
    """True when a URL smuggles ``user:pass@`` in its netloc."""
    parts = urlsplit(url)
    return bool(parts.username or parts.password) or "@" in (parts.netloc or "")


def _redact_url(url: str) -> str:
    """A URL safe to record: user-info (if any) is stripped before it reaches a log line."""
    parts = urlsplit(url)
    if not (parts.username or parts.password):
        return url
    host = parts.hostname or ""
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme}://***@{host}{port}{parts.path}"


@dataclass
class HttpTransport:
    """HTTPS with TLS verification, bounded retries and an allow-listed method set.

    ``base_url`` must be ``https://``. The one exception is loopback, for a device driver
    behind a local proxy, and it is recorded in :meth:`health` so the read is never presented
    as a network read when it was a socket read on the same host.
    """

    base_url: str
    credential: Credential | None = None
    scheme: str = "bearer"
    verify: bool | str = True
    timeout: float = 30.0
    max_retries: int = 2
    backoff: float = 0.35
    max_pages: int = 25
    allow_insecure: bool = False
    header_name: str = "Authorization"
    page_param: str | None = None
    page_size_param: str | None = None
    page_size: int = 100
    next_link_header: str | None = "link"
    _client_factory: Callable[[], Any] | None = None
    _sleep: Callable[[float], None] = field(default=time.sleep, repr=False)

    def __post_init__(self) -> None:
        base = _norm(self.base_url).rstrip("/")
        if not base.startswith(("https://", "http://")):
            raise ControlRefused("NOT_A_URL", f"{base!r} is not an http(s) endpoint")
        if base.startswith("http://") and not self.allow_insecure:
            raise ControlRefused(
                "TLS_REQUIRED",
                f"{base} is plaintext; a control plane is read over TLS or not at all "
                "(pass allow_insecure=True only for a loopback test double)")
        if self.verify is False and not self.allow_insecure:
            raise ControlRefused(
                "TLS_VERIFICATION_REQUIRED",
                "verify=False disables certificate checking; that is not a read-only "
                "integration, it is an unauthenticated one")
        self.base_url = base

    # -- the one place a request leaves ------------------------------------- #
    def request(self, method: str, path: str, *,
                params: Mapping[str, Any] | None = None) -> TransportResult:
        verb = _norm(method).upper()
        if verb not in READ_METHODS:
            raise ControlRefused(
                "NOT_READ_ONLY",
                f"{verb} would change the device; this integration sends "
                f"{', '.join(sorted(READ_METHODS))} and refuses everything else at the "
                "transport, not only in the adapter's declaration")
        started = time.monotonic()
        try:
            url = self._resolve(path)
        except ControlRefused as exc:
            # a refusal is a result, not a crash: the caller learns the read was refused and
            # why, and no credential-bearing packet left this process
            return TransportResult(url=_redact_url(path)[:200], method=verb, state=REFUSED,
                                   attempts=0, reason=_scrub_text(exc)[:300],
                                   elapsed_ms=int((time.monotonic() - started) * 1000))
        headers = {"Accept": "application/json"}
        if self.credential is not None and self.credential:
            # only reachable for a same-origin url — _resolve refused every other destination
            secret = self.credential.reveal()
            headers[self.header_name] = (f"Bearer {secret}" if self.scheme == "bearer"
                                         else secret)
        attempts = 0
        last: TransportResult | None = None
        for attempt in range(self.max_retries + 1):
            attempts = attempt + 1
            try:
                response = self._send(verb, url, headers=headers, params=params)
            except Exception as exc:  # noqa: BLE001 — the taxonomy is the point
                last = TransportResult(
                    url=url, method=verb, state=UNREACHABLE, attempts=attempts,
                    reason=f"{type(exc).__name__}: {_scrub_text(exc)[:200]}",
                    elapsed_ms=int((time.monotonic() - started) * 1000))
                if attempt < self.max_retries:
                    self._sleep(self._delay(attempt))
                    continue
                return last
            status = int(getattr(response, "status_code", 0) or 0)
            if 300 <= status < 400:
                # redirects are refused at this layer and httpx is configured never to follow
                # them: a 302 to a host nobody approved is the classic credential-stealing
                # move, and an auto-following client would send the token along
                return TransportResult(
                    url=url, method=verb, status=status, state=REFUSED, attempts=attempts,
                    reason=(f"HTTP {status} redirect refused — this transport never follows "
                            "a redirect, so the credential cannot be carried to a "
                            "destination nobody approved"),
                    elapsed_ms=int((time.monotonic() - started) * 1000))
            if status >= 500 or status in (408, 429):
                state = _STATUS_STATE.get(status, UNREACHABLE)
                last = TransportResult(
                    url=url, method=verb, status=status, state=state, attempts=attempts,
                    retry_after=_retry_after(response),
                    reason=f"HTTP {status}", elapsed_ms=int((time.monotonic() - started) * 1000))
                if attempt < self.max_retries:
                    self._sleep(last.retry_after or self._delay(attempt))
                    continue
                return last
            if status in (401, 403, 407):
                return TransportResult(url=url, method=verb, status=status,
                                       state=AUTH_FAILED, attempts=attempts,
                                       reason="the device rejected the credential",
                                       elapsed_ms=int((time.monotonic() - started) * 1000))
            if status >= 400:
                return TransportResult(url=url, method=verb, status=status,
                                       state=BAD_RESPONSE, attempts=attempts,
                                       reason=f"HTTP {status}",
                                       elapsed_ms=int((time.monotonic() - started) * 1000))
            try:
                body = _json_or_text(response)
            except ValueError as exc:
                return TransportResult(url=url, method=verb, status=status, state=BAD_RESPONSE,
                                       attempts=attempts,
                                       reason=f"device response body is unreadable: {type(exc).__name__}",
                                       elapsed_ms=int((time.monotonic() - started) * 1000))
            return TransportResult(url=url, method=verb, status=status, state=OK, body=body,
                                   attempts=attempts, link=_header(response, "link"),
                                   elapsed_ms=int((time.monotonic() - started) * 1000))
        return last or TransportResult(url=url, method=verb, state=UNREACHABLE,
                                       reason="no attempt was made")

    def get(self, path: str, *, params: Mapping[str, Any] | None = None) -> TransportResult:
        return self.request("GET", path, params=params)

    # -- pagination --------------------------------------------------------- #
    def get_all(self, path: str, *,
                params: Mapping[str, Any] | None = None) -> tuple[list[Any], TransportResult]:
        """Every page, or the first state that says the read did not finish.

        Two pagination styles are supported because the dialects use two: a page/size pair
        (``?start=0&count=100`` on FortiOS, offsets elsewhere) and a ``Link: rel="next"``
        header. A device that returns a next link forever is stopped by ``max_pages`` and
        reported as ``PARTIAL_READ`` — a truncated list is a finding, not an empty one.
        """
        rows: list[Any] = []
        base_params = dict(params or {})
        pages = 0
        next_path: str | None = path
        next_params: Mapping[str, Any] | None = base_params
        while next_path and pages < self.max_pages:
            result = self.get(next_path, params=next_params)
            pages += 1
            if not result.ok:
                result.pages = pages
                return rows, result
            rows.extend(_rows_of(result.body))
            follow = _next_link(result, self.next_link_header) if self.next_link_header else None
            if follow:
                next_path, next_params = follow, None
                continue
            if self.page_param:
                if len(_rows_of(result.body)) < self.page_size:
                    next_path = None
                    continue
                base_params[self.page_param] = int(base_params.get(self.page_param, 0)) + self.page_size
                next_path, next_params = path, base_params
                continue
            next_path = None
        if next_path:
            return rows, TransportResult(url=path, state=PARTIAL_READ, pages=pages,
                                         reason=f"stopped after {self.max_pages} pages; the "
                                                "device has more rows than this read followed")
        final = TransportResult(url=path, state=OK, pages=pages, body=None)
        return rows, final

    # -- health ------------------------------------------------------------- #
    def health(self) -> dict[str, Any]:
        return {
            "transport": "https",
            "base_url": self.base_url,
            "read_methods": sorted(READ_METHODS),
            "tls_verified": self.verify is not False,
            "verify": self.verify if isinstance(self.verify, str) else self.verify is not False,
            "plaintext": self.base_url.startswith("http://"),
            "credential_source": self.credential.source if self.credential else None,
            "credential_fingerprint": self.credential.fingerprint() if self.credential else None,
            "timeout_seconds": self.timeout,
            "max_retries": self.max_retries,
        }

    # -- internals ---------------------------------------------------------- #
    def _resolve(self, path: str) -> str:
        """Resolve a request or pagination target, and enforce where the credential may go.

        The ``Authorization`` header this transport carries is the device's credential. It
        goes to exactly one origin — the origin of ``base_url`` (scheme + host + port) — and
        nowhere else. Absolute targets are how a device, or an attacker shaping one's
        answers, points a credential-bearing client at a foreign host:

        * a relative target resolves against the base URL and is allowed;
        * an absolute target is allowed only when scheme, host **and** port all match the
          base origin;
        * an ``https`` base never follows a target down to ``http`` (downgrade refused);
        * a URL carrying user-info (``user:pass@host``) is refused outright — a credential
          in a URL is a credential in a log line.

        Nothing is silently rewritten and nothing is followed: a cross-origin target raises
        :class:`ControlRefused`, and :meth:`request` turns that into a ``REFUSED`` result
        naming the destination.
        """
        text = _norm(path)
        target = (text if text.startswith(("http://", "https://"))
                  else urljoin(self.base_url + "/", text))
        if _url_userinfo(target):
            raise ControlRefused(
                "CREDENTIAL_IN_URL",
                f"{_redact_url(target)} carries user-info in the URL; credentials belong in "
                "the credential source, not in an address that ends up in every log line")
        base_origin = _origin(self.base_url)
        target_origin = _origin(target)
        if target_origin != base_origin:
            if base_origin[0] == "https" and target_origin[0] == "http":
                raise ControlRefused(
                    "CROSS_ORIGIN_REFUSED",
                    f"refusing an https→http downgrade to {_redact_url(target)}: the device "
                    f"credential for {self.base_url} never travels in plaintext")
            raise ControlRefused(
                "CROSS_ORIGIN_REFUSED",
                f"refusing to send the credential for {self.base_url} to "
                f"{_redact_url(target)}: scheme, host and port must all match the approved "
                "origin (pagination links included)")
        return target

    def _send(self, method: str, url: str, *, headers: Mapping[str, str],
              params: Mapping[str, Any] | None) -> Any:
        if self._client_factory is not None:
            # An injected client is how the read path is tested *and* how a site plugs in its
            # own mTLS session. It was declared and never used, which made it a promise the
            # code did not keep — and a test that injects a client which refuses to send
            # anything is the only way to prove a write never leaves.
            client = self._client_factory()
            try:
                return client.request(method, url, headers=dict(headers),
                                      params=dict(params or {}))
            finally:
                closer = getattr(client, "close", None)
                if callable(closer):
                    closer()
        import httpx  # imported here so the module loads without the dependency

        with httpx.Client(timeout=self.timeout, verify=self.verify,
                          follow_redirects=False) as client:
            return client.request(method, url, headers=dict(headers), params=dict(params or {}))

    def _delay(self, attempt: int) -> float:
        return self.backoff * (2 ** attempt) + random.uniform(0, self.backoff)


def _header(response: Any, name: str) -> str | None:
    try:
        value = response.headers.get(name)
        return str(value) if value else None
    except (AttributeError, TypeError):
        return None


def _retry_after(response: Any) -> float | None:
    try:
        value = response.headers.get("retry-after")
        return float(value) if value else None
    except (AttributeError, TypeError, ValueError):
        return None


def _json_or_text(response: Any) -> Any:
    try:
        return response.json()
    except Exception:  # noqa: BLE001 — a device may answer XML or plain text
        try:
            return response.text
        except Exception as exc:  # noqa: BLE001 — neither JSON nor text could be read
            raise ValueError("device response body is neither readable JSON nor text") from exc


def _rows_of(body: Any) -> list[Any]:
    if body is None:
        return []
    if isinstance(body, list):
        return body
    if isinstance(body, Mapping):
        for key in ("results", "data", "objects", "items", "value"):
            candidate = body.get(key)
            if isinstance(candidate, list):
                return candidate
    return [body] if body else []


def _next_link(result: TransportResult, header: str) -> str | None:
    """The ``rel="next"`` URL from a Link header, if the device sent one.

    FortiOS pages with ``?start=&count=`` and F5 with ``$skip``; both also offer Link headers
    on some endpoints. Parsing the header where it exists means one pager covers both.
    """
    value = result.link
    if not value:
        return None
    for part in value.split(","):
        section = part.strip()
        if 'rel="next"' not in section and "rel=next" not in section:
            continue
        start = section.find("<")
        end = section.find(">", start + 1)
        if start == -1 or end == -1:
            continue
        return section[start + 1:end]
    return None


def _scrub_text(exc: BaseException) -> str:
    text = f"{exc}"
    clean, _ = scrub({"detail": text})
    return str(clean.get("detail", text))


# --------------------------------------------------------------------------- #
# A read-only file tail — for the sensors that have no API worth trusting
# --------------------------------------------------------------------------- #

@dataclass
class FileTail:
    """Bounded, read-only reads of an append-only log (Suricata ``eve.json``, Snort fast).

    A sensor logs one JSON object per line. The driver needs the lines since the last read and
    nothing else, so this transport keeps an in-memory offset, never writes, never follows a
    symlink out of the operator's directory, and caps both the bytes read and the lines parsed
    per call. A line that is not JSON is counted, not raised: a truncated last line is normal
    at the tail of a live file.
    """

    path: str
    max_bytes: int = 4 * 1024 * 1024
    max_lines: int = 5000
    #: a durable cursor returned by a previous :meth:`durable_cursor` — resume is exact
    cursor: Mapping[str, Any] | None = None
    _offset: int = field(default=0, repr=False)      # first byte not yet consumed
    _pending: bytes = field(default=b"", repr=False)  # read ahead, not yet a whole record
    _rotated: bool = field(default=False, repr=False)
    _identity: tuple[int, int] | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        target = Path(_norm(self.path))
        if not target.is_absolute():
            raise ControlRefused("LOG_PATH_NOT_ABSOLUTE",
                                 f"{self.path!r} must be an absolute path")
        self.path = str(target)
        if self.cursor is not None:
            self._offset = max(0, int(self.cursor.get("offset", 0) or 0))
            try:
                self._identity = (int(self.cursor["device"]), int(self.cursor["inode"]))
            except (KeyError, TypeError, ValueError):
                self._identity = None

    def durable_cursor(self) -> dict[str, Any]:
        """The resume point: the first byte not yet consumed as a record.

        Persist this next to whatever the records feed; rebuilding a tail from it continues
        at the exact byte boundary the last read finished on. ``pending_bytes`` counts bytes
        already read from disk but not yet consumed — they are re-read from the file on
        resume, so only the offset and the file identity need to survive a restart.
        """
        device, inode = self._identity if self._identity else (None, None)
        return {"offset": self._offset, "device": device, "inode": inode,
                "pending_bytes": len(self._pending)}

    def read_lines(self, *, flush_tail: bool = False) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """Consume complete JSON records since the last read, and nothing else.

        Three rules, each one a cursor rule:

        * **a partial line is never skipped** — the bytes after the last newline stay in an
          in-memory tail and are prepended to the next read, so a line written in two
          ``write()`` calls still arrives as one record;
        * **the durable cursor only advances through consumed records** — it stops at the
          last record this call returned, never at ``tell()``. Unread complete lines (beyond
          ``max_lines``) and the unfinished tail stay for the next read;
        * **rotation is detected, not guessed** — the file's ``(device, inode)`` is tracked;
          when the file under the path is a different file, or it shrank below the cursor,
          the read restarts at byte 0 and says ``rotated``.

        A final unterminated line is reported as ``pending_bytes`` — never lost, never
        invented. ``flush_tail=True`` consumes it as a final record for a caller that knows
        the file is finished; on a live log it would truncate a line mid-write.
        """
        target = Path(self.path)
        detail: dict[str, Any] = {"path": self.path, "offset_before": self._offset}
        if not target.is_file() or target.is_symlink():
            return [], {**detail, "state": UNREACHABLE,
                        "reason": "the log file is missing or is a symlink"}
        stat = target.stat()
        identity = (stat.st_dev, stat.st_ino)
        if self._identity is not None and identity != self._identity:
            # a different file under the same path: the old one rotated away
            self._rotated = True
            self._offset = 0
            self._pending = b""
        self._identity = identity
        if stat.st_size < self._offset:  # truncated under us
            self._rotated = True
            self._offset = 0
            self._pending = b""
        with target.open("rb") as handle:
            handle.seek(self._offset + len(self._pending))
            chunk = handle.read(self.max_bytes)
        data = self._pending + chunk
        if flush_tail:
            complete_end = len(data)
        else:
            complete_end = data.rfind(b"\n") + 1
        if complete_end == 0:
            # nothing complete yet: the durable cursor does not move past unread content
            self._pending = data
            if len(self._pending) > self.max_bytes:
                # one "line" larger than the byte cap is not a sensor record; counting it and
                # refusing to grow without bound is the honest trade
                self._pending = b""
                self._offset = stat.st_size
                return [], {**detail, "offset_after": self._offset, "size": stat.st_size,
                            "rotated": self._rotated, "lines": 0, "malformed": 1,
                            "truncated": False, "pending_bytes": 0, "oversize_line": True,
                            "cursor": self.durable_cursor(), "state": OK}
            return [], {**detail, "offset_after": self._offset, "size": stat.st_size,
                        "rotated": self._rotated, "lines": 0, "malformed": 0,
                        "truncated": False, "pending_bytes": len(self._pending),
                        "cursor": self.durable_cursor(), "state": OK}
        pieces = data[:complete_end].splitlines(keepends=True)
        over = len(pieces) > self.max_lines
        chosen = pieces[: self.max_lines]
        consumed = sum(len(piece) for piece in chosen)
        self._pending = data[consumed:]
        self._offset += consumed
        rows: list[dict[str, Any]] = []
        malformed = 0
        for raw in chosen:
            text = raw.decode("utf-8", "replace").strip()
            if not text:
                continue
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                malformed += 1
                continue
            if isinstance(payload, Mapping):
                rows.append(dict(payload))
        return rows, {
            **detail, "offset_after": self._offset, "size": stat.st_size,
            "rotated": self._rotated, "lines": len(rows), "malformed": malformed,
            "truncated": over, "pending_bytes": len(self._pending),
            "cursor": self.durable_cursor(), "state": OK,
        }

    def health(self) -> dict[str, Any]:
        target = Path(self.path)
        exists = target.is_file()
        return {
            "transport": "file",
            "path": self.path,
            "read_only": True,
            "exists": exists,
            "size": target.stat().st_size if exists else None,
            "offset": self._offset,
            "max_bytes": self.max_bytes,
            "state": OK if exists else UNREACHABLE,
        }


# --------------------------------------------------------------------------- #
# An in-process double — how the guides and the tests exercise a driver
# --------------------------------------------------------------------------- #

@dataclass
class RecordedTransport:
    """A transport backed by recorded answers: same interface, no socket.

    This is what makes the live path testable without a device, and it is the same object the
    drivers use in the guide harness, so the code under test is the shipping code.
    """

    routes: Mapping[str, Any]
    page_size: int = 100
    _calls: list[dict[str, Any]] = field(default_factory=list, repr=False)

    def get(self, path: str, *, params: Mapping[str, Any] | None = None) -> TransportResult:
        self._calls.append({"path": path, "params": dict(params or {})})
        key = path
        if key not in self.routes:
            return TransportResult(url=path, state=BAD_RESPONSE, status=404,
                                   reason="no recorded answer for this path")
        value = self.routes[key]
        if isinstance(value, TransportResult):
            return value
        if callable(value):
            value = value(params or {})
        return TransportResult(url=path, status=200, state=OK, body=value)

    def get_all(self, path: str, *,
                params: Mapping[str, Any] | None = None) -> tuple[list[Any], TransportResult]:
        result = self.get(path, params=params)
        return _rows_of(result.body), result

    def request(self, method: str, path: str, *,
                params: Mapping[str, Any] | None = None) -> TransportResult:
        if _norm(method).upper() not in READ_METHODS:
            raise ControlRefused("NOT_READ_ONLY", f"{method} is not a read")
        return self.get(path, params=params)

    def health(self) -> dict[str, Any]:
        return {"transport": "recorded", "routes": sorted(self.routes), "read_only": True,
                "calls": [call["path"] for call in self._calls]}

    @property
    def calls(self) -> list[dict[str, Any]]:
        return list(self._calls)
