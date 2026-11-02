"""Session records out of the logs a bank already has.

:mod:`vendor_intel.runtime_usage` decodes a session; it does not produce one.
This module reads the three shapes that actually turn up in a payment
environment:

* **Zeek** ``ssl.log`` — tab-separated, a ``#fields`` header, ``-`` for absent
  values, an epoch timestamp, and the negotiated cipher in ``cipher``;
* **CSV** exported by a load balancer, a TLS terminator or a spreadsheet a
  network engineer keeps — with an alias table so ``cipher``/``cipher_suite``
  and ``ts``/``started_at`` both land in the same field;
* **nginx / Apache access logs** configured to append ``$ssl_protocol``,
  ``$ssl_cipher`` and ``$ssl_curve`` after the usual combined line.

Every reader obeys the same four rules, because a log is untrusted input:

1. It emits only the metadata fields :mod:`runtime_usage` accepts. A column
   named like key material (``payload``, ``premaster_secret``, ``ticket_key``)
   refuses the whole file rather than being skipped, because a pipeline that
   quietly ignores a payload column is a pipeline that will one day log it.
2. A row it cannot read is **counted and quoted**, never dropped. ``rows_read``,
   ``rows_used`` and ``rows_skipped`` are all in the result, and a file that
   yields nothing usable raises unless the caller asks for a soft read.
3. It reads no state and opens no socket: the caller supplies the text.
4. Absent values stay absent — Zeek's ``-`` becomes ``None``, not an empty
   string that later looks like a decoded value.
"""

from __future__ import annotations

import csv
import hashlib
import io
import re
from datetime import date, datetime, timezone
from typing import Any, Iterable, Mapping, Sequence

from vendor_intel.runtime_usage import (
    FORBIDDEN_FRAGMENTS,
    METADATA_FIELDS,
    decode_cipher_suite,
)

SCHEMA = "cryptoscan.runtime-sources/1"
FORMATS: tuple[str, ...] = ("zeek_ssl_log", "csv", "nginx_access")

#: Column names, lower-cased and stripped of punctuation, mapped onto the
#: metadata field they carry. Anything not in here is reported, not used.
COLUMN_ALIASES: dict[str, str] = {
    "sessionid": "session_id", "session": "session_id", "uid": "session_id",
    "connection": "session_id", "conn": "session_id", "id": "session_id",
    "ts": "started_at", "time": "started_at", "startedat": "started_at",
    "timestamp": "started_at", "date": "started_at", "firstseen": "started_at",
    "peer": "peer", "remoteaddr": "peer", "clientip": "peer", "client": "peer",
    "resp": "peer", "resph": "peer", "server": "peer", "dst": "peer",
    "cipher": "cipher_suite", "ciphersuite": "cipher_suite", "sslcipher": "cipher_suite",
    "tlscipher": "cipher_suite", "negotiatedcipher": "cipher_suite",
    "tlsversion": "tls_version", "version": "tls_version", "sslprotocol": "tls_version",
    "protocol": "tls_version",
    "group": "group", "curve": "group", "namedgroup": "group", "sslcurve": "group",
    "kexgroup": "group", "keyexchangegroup": "group",
    "assetid": "asset_id", "asset": "asset_id", "host": "asset_id",
    "sni": "sni", "servername": "sni",
    "signaturealgorithm": "signature_algorithm", "siga": "signature_algorithm",
}

_PROTOCOLS = {"TLSV13": "TLS1.3", "TLSV12": "TLS1.2", "TLSV11": "TLS1.1",
              "TLSV10": "TLS1.0", "TLS13": "TLS1.3", "TLS12": "TLS1.2",
              "TLS11": "TLS1.1", "TLS10": "TLS1.0"}
_NGINX_TIME = re.compile(r"\[(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})")
_MONTHS = {name: index for index, name in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"),
    start=1)}


class SourceError(ValueError):
    """The log could not be read for the stated reason."""


class EmptySource(SourceError):
    """The log was read and produced nothing usable."""


def _key(name: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(name or "").lower())


def _guard_columns(columns: Iterable[Any]) -> None:
    for column in columns:
        lowered = str(column).lower()
        for fragment in FORBIDDEN_FRAGMENTS:
            if fragment in lowered:
                raise SourceError(
                    f"column {column!r} looks like key material or payload; this reader takes "
                    "metadata only, and a file carrying a payload column is refused rather "
                    "than partially read")


def _field_for(column: Any) -> str | None:
    target = COLUMN_ALIASES.get(_key(column))
    return target if target in METADATA_FIELDS else None


def _protocol(value: Any, *, strict: bool = False) -> str | None:
    """Normalise a TLS version name; ``strict`` refuses anything unrecognised.

    Zeek writes ``TLSv13`` and a CSV may write ``TLS 1.3``; both are known. An
    access log's tail can contain anything at all, so there the reader asks the
    strict question and treats anything else as not-a-protocol rather than
    echoing a user agent back as a TLS version.
    """
    if not value:
        return None
    compact = re.sub(r"[^A-Z0-9]", "", str(value).upper())
    if compact in _PROTOCOLS:
        return _PROTOCOLS[compact]
    return None if strict else str(value)


def _epoch(value: Any) -> str | None:
    """Zeek's ``1780000000.123456`` -> an ISO date, in UTC."""
    try:
        stamp = float(str(value))
    except (TypeError, ValueError):
        return None
    if stamp <= 0:
        return None
    try:
        return datetime.fromtimestamp(stamp, tz=timezone.utc).date().isoformat()
    except (OverflowError, OSError, ValueError):  # pragma: no cover - absurd epoch
        return None


def _session_id(prefix: str, payload: str) -> str:
    return f"{prefix}-{hashlib.sha256(payload.encode()).hexdigest()[:12]}"


def detect_format(text: str) -> str | None:
    """Guess the source shape, or ``None`` when nothing is recognisable."""
    for line in str(text or "").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#separator") or stripped.startswith("#fields"):
            return "zeek_ssl_log"
        if stripped.startswith("#"):
            continue
        if re.match(r"^\S+ \S+ \S+ \[", stripped):
            return "nginx_access"
        if "," in stripped:
            # A header row that names a cipher column is a CSV; anything else with
            # commas is reported as unknown rather than guessed at.
            header = {_key(column) for column in stripped.split(",")}
            if any(COLUMN_ALIASES.get(name) == "cipher_suite" for name in header):
                return "csv"
            return None
        return None
    return None


# --------------------------------------------------------------------------- #
# Zeek
# --------------------------------------------------------------------------- #


_ZEEK_COLUMNS = {
    "ts": "started_at", "uid": "session_id", "idorig_h": "asset_id",
    "idresp_h": "peer_host", "idresp_p": "peer_port", "version": "tls_version",
    "cipher": "cipher_suite", "curve": "group", "server_name": "sni",
    "validation_status": None,
}


def read_zeek_ssl_log(text: str) -> dict[str, Any]:
    """Zeek's ``ssl.log``: ``#fields`` header, tabs, ``-`` for absent."""
    lines = [line for line in str(text or "").splitlines() if line.strip()]
    header: list[str] | None = None
    separator = "\t"
    rows: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for number, line in enumerate(lines, start=1):
        if line.startswith("#separator"):
            raw = line.split("\\x", 1)[-1] if "\\x" in line else "\t"
            separator = chr(int(raw, 16)) if raw not in {"\t", ""} else "\t"
            continue
        if line.startswith("#fields"):
            header = line.split(separator)[1:]
            _guard_columns(header)
            continue
        if line.startswith("#"):
            continue
        if header is None:
            raise SourceError("a Zeek log must declare #fields before its rows")
        values = line.split(separator)
        if len(values) != len(header):
            skipped.append({"line": number, "reason": f"{len(values)} column(s) for "
                                                      f"{len(header)} declared field(s)"})
            continue
        record = dict(zip(header, values))
        started = _epoch(record.get("ts"))
        if started is None:
            skipped.append({"line": number, "reason": "no usable ts"})
            continue
        cipher = record.get("cipher")
        if not cipher or cipher == "-":
            skipped.append({"line": number, "reason": "no cipher: the handshake did not finish"})
            continue
        peer_host = record.get("id.resp_h") or record.get("id_orig_h")
        peer_port = record.get("id.resp_p") or record.get("id_orig_p")
        rows.append({
            "session_id": record.get("uid") or _session_id("zeek", line),
            "started_at": started,
            "peer": f"{peer_host}:{peer_port}" if peer_host and peer_port else peer_host,
            "cipher_suite": cipher,
            "group": None if record.get("curve") in (None, "-") else record["curve"],
            "tls_version": _protocol(record.get("version")),
            "sni": None if record.get("server_name") in (None, "-") else record["server_name"],
        })
    return {"format": "zeek_ssl_log", "records": rows, "skipped": skipped,
            "rows_read": len([line for line in lines if not line.startswith("#")])}


# --------------------------------------------------------------------------- #
# CSV
# --------------------------------------------------------------------------- #


def read_csv_sessions(text: str) -> dict[str, Any]:
    """A CSV export, mapped through :data:`COLUMN_ALIASES`."""
    reader = csv.reader(io.StringIO(str(text or "")))
    try:
        header = next(reader)
    except StopIteration:
        raise SourceError("the CSV is empty") from None
    _guard_columns(header)
    mapping = {index: _field_for(column) for index, column in enumerate(header)}
    unknown = [column for column, target in zip(header, mapping.values()) if target is None]
    if "cipher_suite" not in mapping.values():
        raise SourceError(
            "the CSV has no cipher column this reader recognises; the headers were "
            f"{', '.join(header)}")
    if not ({"started_at"} <= set(mapping.values())):
        raise SourceError("the CSV has no timestamp column this reader recognises")
    rows: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    read = 0
    for number, values in enumerate(reader, start=2):
        if not any(value.strip() for value in values):
            continue
        read += 1
        if len(values) != len(header):
            skipped.append({"line": number, "reason": f"{len(values)} field(s) for "
                                                      f"{len(header)} column(s)"})
            continue
        record = {target: value.strip() for target, value in zip(mapping.values(), values)
                  if target}
        for key in ("cipher_suite", "started_at", "peer", "group", "tls_version", "asset_id"):
            if record.get(key) in {"", "-"}:
                record.pop(key, None)
        if not record.get("cipher_suite"):
            skipped.append({"line": number, "reason": "no cipher in the row"})
            continue
        if not record.get("started_at"):
            skipped.append({"line": number, "reason": "no timestamp in the row"})
            continue
        record["session_id"] = record.get("session_id") or _session_id(
            "csv", ",".join(values))
        record["tls_version"] = _protocol(record.get("tls_version"))
        rows.append(record)
    return {"format": "csv", "records": rows, "skipped": skipped, "rows_read": read,
            "unknown_columns": unknown}


# --------------------------------------------------------------------------- #
# nginx / Apache
# --------------------------------------------------------------------------- #


def _looks_like_cipher(value: str) -> bool:
    if not value or value == "-":
        return False
    return bool(decode_cipher_suite(value)["known"]) or bool(
        re.search(r"(?i)(TLS_|AES|CHACHA|3DES|RC4)", value))


def read_nginx_access(text: str) -> dict[str, Any]:
    """Combined log lines with protocol, cipher and (optionally) curve appended.

    The three values are the *last* quoted fields on the line, so the reader
    walks backwards and stops at the first quoted value that is not a protocol
    or a cipher. A line whose tail does not carry a cipher is counted as skipped
    with its reason — it is a line from a virtual host nobody configured for
    this, not a session without cryptography.
    """
    rows: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    read = 0
    for number, line in enumerate(str(text or "").splitlines(), start=1):
        if not line.strip():
            continue
        read += 1
        quoted = re.findall(r'"((?:[^"\\]|\\.)*)"', line)
        head = line.split('"', 1)[0]
        match = _NGINX_TIME.search(head)
        # The documented order is protocol, cipher, curve — appended, so they are
        # the last fields. Walk backwards from the newest and stop at the first
        # value that is not one of them.
        tail = [value for value in quoted if value]
        reversed_tail = list(reversed(tail))
        cipher = protocol = group = None
        cipher_index = next((index for index, value in enumerate(reversed_tail[:3])
                             if _looks_like_cipher(value)), None)
        if cipher_index is not None:
            cipher = reversed_tail[cipher_index]
            to_the_left = reversed_tail[cipher_index + 1:]
            to_the_right = reversed_tail[:cipher_index]
            if to_the_left:
                protocol = _protocol(to_the_left[0], strict=True)
            if to_the_right:
                candidate = to_the_right[0]
                if (re.fullmatch(r"[A-Za-z0-9_-]{3,40}", candidate)
                        and _protocol(candidate, strict=True) is None):
                    group = candidate
        if cipher is None or match is None:
            skipped.append({"line": number,
                            "reason": "no timestamp or no cipher at the end of the line: this "
                                      "virtual host is not logging $ssl_cipher"})
            continue
        day, month, year, hour, minute, second = match.groups()
        started = date(int(year), _MONTHS.get(month.title(), 1), int(day)).isoformat()
        remote = head.split()[0] if head.split() else None
        rows.append({
            "session_id": _session_id("ngx", line),
            "started_at": started,
            "peer": remote,
            "cipher_suite": cipher,
            "tls_version": protocol,
            "group": group,
        })
    return {"format": "nginx_access", "records": rows, "skipped": skipped, "rows_read": read}


_READERS = {"zeek_ssl_log": read_zeek_ssl_log, "csv": read_csv_sessions,
            "nginx_access": read_nginx_access}


def load_sessions(source: str, *, format: str | None = None,
                  strict: bool = True) -> dict[str, Any]:
    """Read one log into session records, saying what it could and could not use."""
    text = str(source or "")
    if not text.strip():
        raise SourceError("the log is empty; an empty file is not an absence of traffic")
    resolved = format or detect_format(text)
    if resolved not in _READERS:
        raise SourceError(
            f"the log is not in a shape this reader knows ({', '.join(FORMATS)}); detected "
            f"{resolved!r}")
    result = _READERS[resolved](text)
    records: Sequence[dict[str, Any]] = result["records"]
    unusable = bool(result["rows_read"]) and not records
    if strict and unusable:
        first = result["skipped"][0] if result["skipped"] else {"reason": "no rows"}
        raise EmptySource(
            f"{result['rows_read']} row(s) were read and none carried a session: "
            f"{first['reason']}")
    return {
        "schema": SCHEMA,
        "format": resolved,
        "rows_read": result["rows_read"],
        "rows_used": len(records),
        "rows_skipped": len(result["skipped"]),
        "skipped": result["skipped"][:20],
        "unknown_columns": result.get("unknown_columns", []),
        "records": list(records),
        "statement": (
            f"{resolved}: {len(records)} of {result['rows_read']} row(s) became session "
            f"records, {len(result['skipped'])} skipped with a reason"
            + (f"; {len(result['unknown_columns'])} column(s) were not recognised and were "
               "not used" if result.get("unknown_columns") else "")),
    }


def records_for_ingest(loaded: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The records in the shape :func:`runtime_usage.ingest_sessions` wants."""
    return [dict(record) for record in loaded.get("records") or ()]
