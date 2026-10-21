"""Actual parser/file hashes on owned fixtures, not container or bank acceptance."""
import hashlib
from scanner.core.file_receipts import capture, finish, MAX_FIXTURE_BYTES
from scanner.core.scanner import Scanner


def test_real_scanner_records_actual_positive_and_negative_source_bytes(tmp_path):
    positive = b"import hashlib\nhashlib.md5(b'fixture')\n"
    negative = b"def add(a,b):\n    return a+b\n"
    (tmp_path / "crypto.py").write_bytes(positive)
    (tmp_path / "negative.py").write_bytes(negative)
    result = Scanner().scan(root_path=tmp_path)
    records = {r["file"]: r for r in result.statistics.file_observation_receipts}
    assert records["crypto.py"]["sha256"] == hashlib.sha256(positive).hexdigest()
    assert records["negative.py"]["sha256"] == hashlib.sha256(negative).hexdigest()
    assert records["negative.py"]["parser_completed"] is True
    assert result.statistics.file_receipts_complete is True
    assert any(f.crypto.algorithm == "MD5" for f in result.findings)


def test_changed_or_failed_unparsed_file_never_establishes_negative_identity(tmp_path):
    path = tmp_path / "source.py"
    path.write_text("before")
    first = capture(tmp_path, [path])
    path.write_text("after")
    assert finish(tmp_path, [path], first, {path}) == []
    assert finish(tmp_path, [path], capture(tmp_path, [path]), set()) == []


def test_large_files_and_symlinks_have_no_fixture_identity_receipt(tmp_path):
    path = tmp_path / "large.py"
    path.write_bytes(b"x" * (MAX_FIXTURE_BYTES + 1))
    link = tmp_path / "linked.py"
    link.symlink_to(path)
    assert capture(tmp_path, [path, link]) == {}
