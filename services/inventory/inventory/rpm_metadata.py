"""Explicit bounded SQLite rpmdb Packages headers, never executes rpm/macros.

Supported: SQLite Packages(blob) with RPM header index/data, string NAME,
VERSION, RELEASE and optional INT32 EPOCH. Not Berkeley DB, ndb, package signature
verification, rpm dependency execution or algorithm invocation.
"""

import sqlite3
import struct
from shared_models.host_collection import HostFact, MAX_FACTS


def rpm_header(raw):
    # rpmdb stores the bare index-count/data-length form. Also accept the
    # standard 8-byte header magic/version/reserved prefix when present.
    offset = 8 if raw.startswith(b"\x8e\xad\xe8\x01\x00\x00\x00\x00") else 0
    if len(raw) < offset + 8:
        raise ValueError("Short RPM header")
    count, size = struct.unpack_from(">II", raw, offset)
    if count > 4096 or size > 1048576 or offset + 8 + 16 * count + size != len(raw):
        raise ValueError("RPM header bounds")
    data = raw[offset + 8 + 16 * count :]
    values = {}
    for i in range(count):
        tag, typ, start, length = struct.unpack_from(">IIII", raw, offset + 8 + 16 * i)
        if start > len(data):
            raise ValueError("RPM index bounds")
        if tag not in {1000, 1001, 1002, 1003}:
            continue
        if tag in values:
            raise ValueError("Duplicate RPM identity tag")
        if tag == 1003:
            if typ != 4 or length != 1 or start + 4 > len(data):
                raise ValueError("Invalid RPM epoch")
            values[tag] = str(struct.unpack_from(">I", data, start)[0])
        else:
            if typ != 6 or length != 1:
                raise ValueError("Invalid RPM identity string")
            end = data.find(b"\0", start)
            if end < 0 or not 0 < end - start <= 120:
                raise ValueError("Invalid RPM string bounds")
            values[tag] = data[start:end].decode("utf-8")
    if not {1000, 1001, 1002} <= values.keys():
        raise ValueError("Incomplete RPM identity")
    version = values[1001] + "-" + values[1002]
    if values.get(1003, "0") != "0":
        version = values[1003] + ":" + version
    return HostFact(
        kind="SOFTWARE",
        local_basis="OBSERVED",
        purpose="PACKAGE_DATABASE_RECORD",
        software_name=values[1000],
        software_version=version,
    )


def rpm_sqlite(data):
    if not data.startswith(b"SQLite format 3\0") or len(data) > 1048576:
        raise ValueError("Unsupported bounded RPM database")
    if data[18:20] != b"\x01\x01":
        raise ValueError("Only rollback-format checkpointed exports supported; no WAL sidecars")
    db = sqlite3.connect(":memory:")
    try:
        db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 1048576)
        db.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 2048)
        db.deserialize(data)
        db.execute("PRAGMA query_only=ON")
        db.execute("PRAGMA trusted_schema=OFF")
        # Views/virtual tables are not this profile. No schema-provided SQL is run.
        schema = db.execute("SELECT type,sql FROM sqlite_schema WHERE name='Packages'").fetchall()
        if len(schema) != 1 or schema[0][0] != "table" or not schema[0][1].upper().startswith("CREATE TABLE "):
            raise ValueError("Unsupported RPM schema")

        def authorize(action, arg1, arg2, *rest):
            if action == sqlite3.SQLITE_SELECT:
                return sqlite3.SQLITE_OK
            if action == sqlite3.SQLITE_READ and arg1 == "Packages" and arg2 in {"blob", "hnum"}:
                return sqlite3.SQLITE_OK
            return sqlite3.SQLITE_DENY

        db.set_authorizer(authorize)
        ticks = 0

        def progress():
            nonlocal ticks
            ticks += 1
            return ticks > 100  # at most ~100k VM instructions

        db.set_progress_handler(progress, 1000)
        rows = db.execute("SELECT blob FROM Packages ORDER BY hnum LIMIT 1001").fetchall()
        if not rows or len(rows) > MAX_FACTS:
            raise ValueError("Empty/oversize RPM database")
        facts = [rpm_header(blob) for (blob,) in rows if isinstance(blob, bytes)]
        if len(facts) != len(rows):
            raise ValueError("Nonbinary RPM header")
        identities = [(f.software_name, f.software_version) for f in facts]
        if len(set(identities)) != len(identities):
            raise ValueError("Ambiguous RPM package identity")
        return facts
    except sqlite3.Error:
        raise ValueError("Invalid/unsupported RPM database") from None
    finally:
        db.close()
