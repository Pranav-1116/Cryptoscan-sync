"""Production live vendor sources.

The live engine deliberately has no demo source.  These connectors are small,
read-only adapters around operator-configured management APIs and event
streams.  A connector is created only when its endpoint/path, vendor identity,
and asset identity are present in persisted configuration.  Authentication is
resolved at collection time through a callback so a short-lived vault lease is
never placed in an event, snapshot, or log.

The HTTP adapter is suitable for vendor management APIs, RESTCONF, iControl,
telemetry gateways, and other polling endpoints that expose JSON or text.  The
JSON-lines adapter is for a deployed syslog/telemetry forwarder or agent spool;
it tails an operator-configured file and never treats an in-memory iterable as
an event source.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import select
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable, Mapping

from universal_vendor.live.events import (
    ChangeType,
    EventNormalizer,
    EventType,
    UniversalVendorEvent,
)
from universal_vendor.live.monitoring import LiveConnector, MonitorMode

CredentialResolver = Callable[[], str | None]

_SECRET_NAME = re.compile(
    r"(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|"
    r"preshared|passphrase|credential|access[_-]?key|client[_-]?secret|"
    r"key[_-]?material)", re.IGNORECASE,
)
_PRIVATE_BLOCK = re.compile(
    r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
    re.IGNORECASE | re.DOTALL,
)


def _scrub(value: Any) -> Any:
    """Recursively remove secret-bearing fields and private-key blocks."""
    if isinstance(value, str):
        return _PRIVATE_BLOCK.sub("<redacted-private-key>", value)
    if isinstance(value, Mapping):
        return {
            str(key): ("<redacted>" if _SECRET_NAME.search(str(key)) else _scrub(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_scrub(item) for item in value]
    if isinstance(value, tuple):
        return [_scrub(item) for item in value]
    return value


def _evidence_hash(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _safe_source(url: str) -> str:
    """Return a source identifier without query strings or userinfo."""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme and parsed.hostname:
        host = parsed.hostname
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        if parsed.port:
            host = f"{host}:{parsed.port}"
        return urllib.parse.urlunsplit((parsed.scheme, host, parsed.path, "", ""))
    return "configured-endpoint"


def _json_or_text(raw: bytes, content_type: str = "") -> Any:
    text = raw.decode("utf-8", errors="replace")
    if "json" in content_type.lower() or text.lstrip().startswith(("{", "[")):
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"source returned invalid JSON: {exc.msg}") from exc
    return text


def _canonical_hash(value: Any) -> str:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, default=str).encode("utf-8")
    except (TypeError, ValueError):
        encoded = repr(value).encode("utf-8", errors="replace")
    return _evidence_hash(encoded)


def _event_type(value: Any) -> EventType:
    """Classify an observed source change without inventing crypto detail."""
    if isinstance(value, Mapping):
        fields = {str(k).lower() for k in value}
        if fields & {"certificate", "certificates", "certificate_chain", "trust_chain"}:
            return EventType.TRUST_CHAIN_CHANGED
        if fields & {"key", "keys", "key_metadata", "key_inventory"}:
            return EventType.KEY_CHANGED
        if fields & {"tls", "tls_profiles", "cipher", "ciphers", "ssl"}:
            return EventType.TLS_CHANGED
        if fields & {"ipsec", "ike", "vpn"}:
            return EventType.IPSEC_CHANGED
        if fields & {"ssh", "ssh_config"}:
            return EventType.SSH_CHANGED
        if fields & {"firmware", "firmware_version"}:
            return EventType.FIRMWARE_CHANGED
        if fields & {"crypto", "cryptography", "algorithms", "protocols"}:
            return EventType.CRYPTO_CHANGED
    return EventType.CONFIG_CHANGED


class _SourceError(RuntimeError):
    """An unavailable source, safe to expose as a health event."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class HttpVendorConnector(LiveConnector):
    """Poll one real, read-only vendor HTTP management/telemetry endpoint."""

    mechanism = "management_api"
    modes = [
        MonitorMode.MANAGEMENT_API_MONITORING,
        MonitorMode.LIGHTWEIGHT_PERIODIC_POLLING,
        MonitorMode.CHANGE_TRIGGERED_DEEP_SCANNING,
    ]

    def __init__(
        self,
        *,
        endpoint: str,
        vendor: str,
        product: str,
        asset_id: str,
        asset_type: str = "vendor",
        source: str = "management_api",
        product_version: str | None = None,
        headers: Mapping[str, str] | None = None,
        auth_env: str | None = None,
        credential_resolver: CredentialResolver | None = None,
        timeout: float = 15.0,
        max_bytes: int = 10 * 1024 * 1024,
        tenant_id: str | None = None,
    ) -> None:
        if not endpoint or not urllib.parse.urlsplit(endpoint).scheme:
            raise ValueError("a configured HTTP(S) endpoint is required")
        parsed_endpoint = urllib.parse.urlsplit(endpoint)
        if parsed_endpoint.scheme not in {"http", "https"}:
            raise ValueError("vendor endpoint must use http or https")
        if parsed_endpoint.query or parsed_endpoint.fragment:
            raise ValueError("vendor endpoint query/fragment credentials are not permitted")
        if parsed_endpoint.username or parsed_endpoint.password:
            raise ValueError("credentials are not permitted in a vendor endpoint")
        for name, value in (("vendor", vendor), ("product", product), ("asset_id", asset_id)):
            if not str(value or "").strip():
                raise ValueError(f"{name} is required for a live vendor source")
        super().__init__(asset_id=asset_id)
        self.vendor = vendor
        self.product = product
        self._asset_type = asset_type or "vendor"
        self._endpoint = endpoint
        self._source = source or "management_api"
        self._product_version = product_version
        blocked_headers = {"authorization", "proxy-authorization", "cookie",
                           "set-cookie", "x-api-key", "api-key"}
        self._headers_config = {
            str(key): str(value) for key, value in (headers or {}).items()
            if str(key).lower() not in blocked_headers
        }
        self._auth_env = auth_env
        self._credential_resolver = credential_resolver
        self._timeout = max(1.0, float(timeout))
        self._max_bytes = max(1024, int(max_bytes))
        self._tenant_id = tenant_id
        self._last_fingerprint: str | None = None
        self._last_snapshot: dict[str, Any] = {}
        self._last_status: str = "NOT_COLLECTED"
        self._last_error: str | None = None
        self._etag: str | None = None
        self._last_modified: str | None = None

    def _headers(self) -> dict[str, str]:
        headers = {str(key): str(value) for key, value in self._headers_config.items()}
        headers.setdefault("Accept", "application/json, text/plain;q=0.9")
        headers.setdefault("User-Agent", "CryptoScan-live-monitor/1")
        if self._auth_env:
            token = os.environ.get(self._auth_env)
            if not token:
                raise _SourceError(f"authentication environment {self._auth_env!r} is unavailable")
            headers.setdefault("Authorization", f"Bearer {token}")
        if self._credential_resolver is not None:
            try:
                token = self._credential_resolver()
            except Exception as exc:  # never expose vault/provider detail
                raise _SourceError(
                    f"short-lived vendor credential lease failed: {type(exc).__name__}"
                ) from exc
            if not token:
                raise _SourceError("short-lived vendor credential lease is unavailable")
            headers.setdefault("Authorization", f"Bearer {token}")
        if self._etag:
            headers["If-None-Match"] = self._etag
        if self._last_modified:
            headers["If-Modified-Since"] = self._last_modified
        return headers

    def _fetch(self) -> tuple[Any, bytes, Mapping[str, str]] | None:
        request = urllib.request.Request(self._endpoint, method="GET", headers=self._headers())
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:  # noqa: S310
                raw = response.read(self._max_bytes + 1)
                if len(raw) > self._max_bytes:
                    raise _SourceError("vendor response exceeds configured evidence limit")
                headers = {str(key): str(value) for key, value in response.headers.items()}
                self._etag = headers.get("ETag") or headers.get("Etag")
                self._last_modified = headers.get("Last-Modified")
                return _json_or_text(raw, headers.get("Content-Type", "")), raw, headers
        except urllib.error.HTTPError as exc:
            if exc.code == 304:
                return None
            raise _SourceError(f"vendor source HTTP {exc.code}", status_code=exc.code) from exc
        except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
            raise _SourceError(f"vendor source unavailable: {type(exc).__name__}") from exc

    def collect(self) -> list[UniversalVendorEvent]:
        try:
            response = self._fetch()
            if response is None:
                self._last_status = "UNCHANGED"
                self._last_error = None
                return []
            artifact, raw, response_headers = response
            safe_artifact = _scrub(artifact)
            fingerprint = _canonical_hash(safe_artifact)
            first = self._last_fingerprint is None
            if not first and fingerprint == self._last_fingerprint:
                self._last_status = "UNCHANGED"
                self._last_error = None
                self._last_snapshot = {"fingerprint": fingerprint, "source": _safe_source(self._endpoint)}
                return []
            self._last_fingerprint = fingerprint
            self._last_status = "OBSERVED"
            self._last_error = None
            self._last_snapshot = {
                "fingerprint": fingerprint,
                "source": _safe_source(self._endpoint),
                "status": self._last_status,
            }
            metadata: dict[str, Any] = {
                "artifact": safe_artifact,
                "scan_context": self._scan_context(safe_artifact),
                "source_evidence": {
                    "kind": "http_response",
                    "content_type": response_headers.get("Content-Type", ""),
                    "bytes": len(raw),
                },
            }
            if isinstance(safe_artifact, Mapping):
                version = safe_artifact.get("product_version") or safe_artifact.get("version")
            else:
                version = None
            event = UniversalVendorEvent(
                vendor=self.vendor,
                product=self.product,
                product_version=str(version or self._product_version) if (version or self._product_version) else None,
                asset_id=self.asset_id,
                asset_type=self._asset_type,
                event_type=EventType.ASSET_DISCOVERED if first else _event_type(safe_artifact),
                change_type=ChangeType.CREATED if first else ChangeType.UPDATED,
                source=self._source,
                confidence=0.95,
                evidence_reference=_evidence_hash(raw),
                vendor_metadata=metadata,
                tenant_id=self._tenant_id,
            )
            return [event]
        except _SourceError as exc:
            self._last_status = "UNAVAILABLE"
            self._last_error = str(exc)
            metadata = {"availability": "UNAVAILABLE", "error": str(exc)}
            if exc.status_code is not None:
                metadata["status_code"] = exc.status_code
            return [UniversalVendorEvent(
                vendor=self.vendor, product=self.product, asset_id=self.asset_id,
                asset_type=self._asset_type, event_type=EventType.HEALTH_CHANGED,
                change_type=ChangeType.UPDATED, source=self._source,
                confidence=1.0, vendor_metadata=metadata, tenant_id=self._tenant_id,
            )]
        except (ValueError, OSError) as exc:
            self._last_status = "UNAVAILABLE"
            self._last_error = f"{type(exc).__name__}: {exc}"
            return [UniversalVendorEvent(
                vendor=self.vendor, product=self.product, asset_id=self.asset_id,
                asset_type=self._asset_type, event_type=EventType.HEALTH_CHANGED,
                change_type=ChangeType.UPDATED, source=self._source,
                confidence=1.0,
                vendor_metadata={"availability": "UNAVAILABLE", "error": self._last_error},
                tenant_id=self._tenant_id,
            )]

    @staticmethod
    def _scan_context(artifact: Any) -> dict[str, Any]:
        """Map real API evidence to scanner inputs; never add an empty config."""
        if isinstance(artifact, str):
            return {"config": artifact}
        if isinstance(artifact, Mapping):
            context: dict[str, Any] = {"api_metadata": artifact}
            if artifact.get("config") is not None:
                context["config"] = artifact["config"]
            if artifact.get("banner") is not None:
                context["banner"] = artifact["banner"]
            if artifact.get("version") is not None:
                context["version"] = artifact["version"]
            return context
        return {"api_metadata": artifact}

    def snapshot(self) -> dict[str, Any]:
        return dict(self._last_snapshot) if self._last_snapshot else {
            "source": _safe_source(self._endpoint), "status": self._last_status,
        }

    def heartbeat(self) -> dict[str, Any]:
        return {
            "vendor": self.vendor, "product": self.product,
            "mechanism": self.mechanism, "ok": self._last_status in {"OBSERVED", "UNCHANGED"},
            "status": self._last_status, "error": self._last_error,
        }


class JsonLinesEventConnector(LiveConnector):
    """Consume a real, append-only JSON-lines event spool or forwarder file."""

    mechanism = "event_stream"
    modes = [MonitorMode.REAL_TIME_TELEMETRY, MonitorMode.VENDOR_EVENT_MONITORING]

    def __init__(
        self,
        *,
        path: str,
        vendor: str,
        product: str,
        asset_id: str,
        asset_type: str = "vendor",
        source: str = "event_stream",
        tenant_id: str | None = None,
        max_line_bytes: int = 1024 * 1024,
    ) -> None:
        if not path or not str(path).strip():
            raise ValueError("a configured event stream path is required")
        for name, value in (("vendor", vendor), ("product", product), ("asset_id", asset_id)):
            if not str(value or "").strip():
                raise ValueError(f"{name} is required for a live vendor source")
        super().__init__(asset_id=asset_id)
        self.vendor, self.product = vendor, product
        self._asset_type = asset_type or "vendor"
        self._path = Path(path).expanduser()
        self._source = source or "event_stream"
        self._tenant_id = tenant_id
        self._offset = 0
        self._last_status = "NOT_COLLECTED"
        self._last_error: str | None = None
        self._max_line_bytes = max(1024, int(max_line_bytes))

    def collect(self) -> list[UniversalVendorEvent]:
        try:
            if not self._path.exists():
                raise _SourceError("configured event stream does not exist")
            if not self._path.is_file():
                raise _SourceError("configured event stream is not a file")
            size = self._path.stat().st_size
            if size < self._offset:
                # Rotation/truncation: resume from the beginning of the new file.
                self._offset = 0
            with self._path.open("rb") as stream:
                stream.seek(self._offset)
                lines = stream.readlines()
                self._offset = stream.tell()
            events: list[UniversalVendorEvent] = []
            for raw_line in lines:
                raw = raw_line.rstrip(b"\r\n")
                if not raw:
                    continue
                if len(raw) > self._max_line_bytes:
                    raise _SourceError("event stream line exceeds configured evidence limit")
                try:
                    payload = json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise _SourceError("event stream contains a non-JSON record") from exc
                if not isinstance(payload, Mapping):
                    raise _SourceError("event stream record must be a JSON object")
                safe = _scrub(dict(payload))
                safe.setdefault("vendor", self.vendor)
                safe.setdefault("product", self.product)
                safe.setdefault("asset_id", self.asset_id)
                safe.setdefault("asset_type", self._asset_type)
                safe.setdefault("source", self._source)
                safe["vendor_metadata"] = _scrub(dict(safe.get("vendor_metadata") or {}))
                # Keep source evidence in the canonical metadata while the hash
                # commits to the exact received record, not a generated default.
                safe["vendor_metadata"]["source_evidence"] = {"kind": "json_lines", "path": str(self._path)}
                safe["evidence_reference"] = _evidence_hash(raw)
                safe["tenant_id"] = self._tenant_id
                events.append(EventNormalizer.normalize(safe))
            self._last_status = "OBSERVED" if events else "UNCHANGED"
            self._last_error = None
            return events
        except _SourceError as exc:
            self._last_status = "UNAVAILABLE"
            self._last_error = str(exc)
            return [UniversalVendorEvent(
                vendor=self.vendor, product=self.product, asset_id=self.asset_id,
                asset_type=self._asset_type, event_type=EventType.HEALTH_CHANGED,
                change_type=ChangeType.UPDATED, source=self._source,
                confidence=1.0,
                vendor_metadata={"availability": "UNAVAILABLE", "error": str(exc)},
                tenant_id=self._tenant_id,
            )]
        except (OSError, TypeError, ValueError) as exc:
            self._last_status = "UNAVAILABLE"
            self._last_error = f"{type(exc).__name__}: {exc}"
            return [UniversalVendorEvent(
                vendor=self.vendor, product=self.product, asset_id=self.asset_id,
                asset_type=self._asset_type, event_type=EventType.HEALTH_CHANGED,
                change_type=ChangeType.UPDATED, source=self._source,
                confidence=1.0,
                vendor_metadata={"availability": "UNAVAILABLE", "error": self._last_error},
                tenant_id=self._tenant_id,
            )]

    def snapshot(self) -> dict[str, Any]:
        return {"source": str(self._path), "offset": self._offset, "status": self._last_status}

    def heartbeat(self) -> dict[str, Any]:
        return {
            "vendor": self.vendor, "product": self.product,
            "mechanism": self.mechanism, "ok": self._last_status in {"OBSERVED", "UNCHANGED"},
            "status": self._last_status, "error": self._last_error,
        }


class UdpJsonEventConnector(LiveConnector):
    """Read JSON-bearing datagrams from an operator-configured local stream.

    A deployed syslog/telemetry forwarder can send structured records to this
    read-only listener. Plain records that contain no JSON object are rejected
    as unavailable rather than classified from guessed text.
    """

    mechanism = "syslog"
    modes = [MonitorMode.REAL_TIME_TELEMETRY, MonitorMode.VENDOR_EVENT_MONITORING]

    def __init__(
        self,
        *,
        listen_host: str,
        listen_port: int,
        vendor: str,
        product: str,
        asset_id: str,
        asset_type: str = "vendor",
        source: str = "syslog",
        tenant_id: str | None = None,
        max_datagrams: int = 100,
    ) -> None:
        if not listen_host or not (1 <= int(listen_port) <= 65535):
            raise ValueError("a configured syslog/telemetry listen host and port are required")
        for name, value in (("vendor", vendor), ("product", product), ("asset_id", asset_id)):
            if not str(value or "").strip():
                raise ValueError(f"{name} is required for a live vendor source")
        super().__init__(asset_id=asset_id)
        self.vendor, self.product = vendor, product
        self._asset_type = asset_type or "vendor"
        self._source = source or "syslog"
        self._tenant_id = tenant_id
        self._max_datagrams = max(1, int(max_datagrams))
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind((str(listen_host), int(listen_port)))
        self._socket.setblocking(False)
        self._packets = 0
        self._last_status = "NOT_COLLECTED"
        self._last_error: str | None = None

    @staticmethod
    def _parse_datagram(raw: bytes) -> Mapping[str, Any]:
        text = raw.decode("utf-8", errors="replace").strip()
        try:
            value = json.loads(text)
        except json.JSONDecodeError:
            start, end = text.find("{"), text.rfind("}")
            if start < 0 or end <= start:
                raise _SourceError("syslog datagram contains no structured JSON record")
            try:
                value = json.loads(text[start:end + 1])
            except json.JSONDecodeError as exc:
                raise _SourceError("syslog datagram contains invalid JSON") from exc
        if not isinstance(value, Mapping):
            raise _SourceError("syslog record must be a JSON object")
        return value

    def collect(self) -> list[UniversalVendorEvent]:
        events: list[UniversalVendorEvent] = []
        try:
            readable, _, _ = select.select([self._socket], [], [], 0)
            for _ in range(self._max_datagrams):
                if not readable:
                    break
                raw, _address = self._socket.recvfrom(1024 * 1024)
                self._packets += 1
                safe = _scrub(dict(self._parse_datagram(raw)))
                safe.setdefault("vendor", self.vendor)
                safe.setdefault("product", self.product)
                safe.setdefault("asset_id", self.asset_id)
                safe.setdefault("asset_type", self._asset_type)
                safe.setdefault("source", self._source)
                safe["tenant_id"] = self._tenant_id
                safe["evidence_reference"] = _evidence_hash(raw)
                metadata = dict(safe.get("vendor_metadata") or {})
                metadata["source_evidence"] = {"kind": "udp_datagram", "bytes": len(raw)}
                safe["vendor_metadata"] = metadata
                events.append(EventNormalizer.normalize(safe))
                readable, _, _ = select.select([self._socket], [], [], 0)
            self._last_status = "OBSERVED" if events else "UNCHANGED"
            self._last_error = None
            return events
        except (_SourceError, OSError, TypeError, ValueError) as exc:
            self._last_status = "UNAVAILABLE"
            self._last_error = str(exc)
            return [UniversalVendorEvent(
                vendor=self.vendor, product=self.product, asset_id=self.asset_id,
                asset_type=self._asset_type, event_type=EventType.HEALTH_CHANGED,
                change_type=ChangeType.UPDATED, source=self._source,
                confidence=1.0,
                vendor_metadata={"availability": "UNAVAILABLE", "error": self._last_error},
                tenant_id=self._tenant_id,
            )]

    def snapshot(self) -> dict[str, Any]:
        return {"source": self._source, "packets": self._packets, "status": self._last_status}

    def heartbeat(self) -> dict[str, Any]:
        return {
            "vendor": self.vendor, "product": self.product,
            "mechanism": self.mechanism, "ok": self._last_status in {"OBSERVED", "UNCHANGED"},
            "status": self._last_status, "error": self._last_error,
        }

    def close(self) -> None:
        self._socket.close()


def build_connector(
    config: Mapping[str, Any],
    *,
    credential_resolver: CredentialResolver | None = None,
    tenant_id: str | None = None,
) -> LiveConnector:
    """Build one connector from persisted non-secret configuration."""
    vendor = str(config.get("vendor") or "").strip()
    product = str(config.get("product") or "").strip()
    asset_id = str(config.get("asset_id") or config.get("asset") or "").strip()
    source = str(config.get("source") or config.get("method") or "management_api")
    if config.get("listen_port") or config.get("syslog_port") or config.get("telemetry_port"):
        return UdpJsonEventConnector(
            listen_host=str(config.get("listen_host") or config.get("syslog_host")
                                or config.get("telemetry_host") or ""),
            listen_port=int(config.get("listen_port") or config.get("syslog_port")
                            or config.get("telemetry_port")),
            vendor=vendor, product=product, asset_id=asset_id,
            asset_type=str(config.get("asset_type") or "vendor"), source=source,
            tenant_id=tenant_id,
        )
    if config.get("event_file") or config.get("syslog_path") or config.get("telemetry_file"):
        return JsonLinesEventConnector(
            path=str(config.get("event_file") or config.get("syslog_path") or config.get("telemetry_file")),
            vendor=vendor, product=product, asset_id=asset_id,
            asset_type=str(config.get("asset_type") or "vendor"), source=source,
            tenant_id=tenant_id,
        )
    endpoint = str(config.get("endpoint") or config.get("api_endpoint") or "").strip()
    return HttpVendorConnector(
        endpoint=endpoint, vendor=vendor, product=product, asset_id=asset_id,
        asset_type=str(config.get("asset_type") or "vendor"),
        source=source, product_version=config.get("product_version"),
        headers=config.get("headers") if isinstance(config.get("headers"), Mapping) else None,
        auth_env=str(config.get("auth_env") or "") or None,
        credential_resolver=credential_resolver,
        timeout=float(config.get("timeout", 15.0)),
        max_bytes=int(config.get("max_bytes", 10 * 1024 * 1024)),
        tenant_id=tenant_id,
    )


__all__ = [
    "HttpVendorConnector", "JsonLinesEventConnector", "UdpJsonEventConnector",
    "build_connector",
]
