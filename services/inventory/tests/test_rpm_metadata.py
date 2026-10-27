"""Expected-truth RPM fixture bytes; not native Red Hat/SUSE qualification."""

import sqlite3
import struct
import pytest
from inventory.rpm_metadata import rpm_header, rpm_sqlite
from inventory.host import collect
from services.inventory.tests.test_linux_runtime import manifest


def header(name="openssl", version="3.2.2", release="5.el9", epoch=1):
    data = b""
    entries = []
    for tag, value in [(1000, name), (1001, version), (1002, release)]:
        entries.append((tag, 6, len(data), 1))
        data += value.encode() + b"\0"
    entries.append((1003, 4, len(data), 1))
    data += struct.pack(">I", epoch)
    return struct.pack(">II", len(entries), len(data)) + b"".join(struct.pack(">IIII", *e) for e in entries) + data


def database(blobs):
    db = sqlite3.connect(":memory:")
    try:
        db.execute("CREATE TABLE Packages(hnum INTEGER PRIMARY KEY,blob BLOB NOT NULL)")
        db.executemany("INSERT INTO Packages(blob) VALUES (?)", [(b,) for b in blobs])
        db.commit()
        return db.serialize()
    finally:
        db.close()


def test_rpm_header_and_sqlite_expected_truth_no_macros_or_execution(tmp_path):
    raw = database([header(), header("libcrypto", "3.0", "1", 0)])
    path = tmp_path / "rpmdb.sqlite"
    path.write_bytes(raw)
    snapshot = collect(manifest("RPM_SQLITE", str(path)))
    assert snapshot.receipts[0].status == "PARSED"
    assert [(f.software_name, f.software_version) for f in snapshot.receipts[0].facts] == [
        ("openssl", "1:3.2.2-5.el9"),
        ("libcrypto", "3.0-1"),
    ]
    assert all(f.algorithm == f.runtime_use == "UNKNOWN" for f in snapshot.receipts[0].facts)
    assert rpm_header(b"\x8e\xad\xe8\x01\0\0\0\0" + header()).software_name == "openssl"


@pytest.mark.parametrize("raw", [b"", b"not SQLite", database([]), database([b"bad"]), database([header(), header()])])
def test_invalid_empty_duplicate_rpm_inventory_is_not_positive(raw):
    with pytest.raises(ValueError):
        rpm_sqlite(raw)


@pytest.mark.parametrize(
    "raw", [b"", struct.pack(">II", 4097, 0), header()[:-1], header() + b"trailing", header("$(touch /tmp/never-run)")]
)
def test_rpm_header_bounds_strings_and_identity(raw):
    with pytest.raises(ValueError):
        rpm_header(raw)


def test_rpm_view_is_not_executed_as_package_database():
    db = sqlite3.connect(":memory:")
    db.execute("CREATE VIEW Packages AS SELECT 1 AS hnum,zeroblob(1000000000) AS blob")
    raw = db.serialize()
    db.close()
    with pytest.raises(ValueError):
        rpm_sqlite(raw)


def test_wal_mode_database_is_not_mistaken_for_current_committed_inventory():
    raw = bytearray(database([header()]))
    raw[18:20] = b"\x02\x02"
    with pytest.raises(ValueError, match="WAL"):
        rpm_sqlite(bytes(raw))
