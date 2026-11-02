"""Archive intake: what may be read out of an archive at all.

The scanner already bounded decompression (member count, member size, ratio).
This layer is about the *shape* of the member list — traversal, links out of the
root, device nodes — because those are refusals, not budgets: no amount of
headroom makes `../../etc/passwd` a safe member.
"""

from __future__ import annotations

import io
import tarfile
import zipfile

import pytest

from devsecops import archive_guard as guard


def _zip(members: list[tuple[str, bytes]], *, symlink: str | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, blob in members:
            archive.writestr(name, blob)
        if symlink:
            info = zipfile.ZipInfo(symlink)
            info.external_attr = (0o120777 << 16)
            archive.writestr(info, "/etc/shadow")
    return buf.getvalue()


def _tar(entries: list[tuple[str, bytes | None, bytes]]) -> bytes:
    """entries: (name, payload or None, type flag)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as archive:
        for name, payload, kind in entries:
            info = tarfile.TarInfo(name)
            info.type = kind
            if kind == tarfile.SYMTYPE:
                info.linkname = str(payload, "utf-8") if payload else ""
                archive.addfile(info)
            elif payload is None:
                archive.addfile(info)
            else:
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


def test_a_normal_zip_is_allowed():
    verdict = guard.from_zip(_zip([("app/lib/libssl.so", b"elf"), ("app/README", b"hi")]))
    assert verdict["verdict"] == "ALLOW"
    assert verdict["members"] == 2
    assert verdict["refused_members"] == []


@pytest.mark.parametrize("name", ["../etc/passwd", "app/../../etc/passwd", "/etc/passwd",
                                  "C:\\\\windows\\\\system32", "app\\\\..\\\\..\\\\win.ini"])
def test_traversal_and_absolute_names_are_refused(name):
    verdict = guard.from_zip(_zip([(name, b"x"), ("app/ok", b"y")]))
    assert verdict["verdict"] == "REFUSE", name
    assert verdict["refused_members"][0]["name"] == name


def test_a_nul_in_a_member_name_is_refused():
    verdict = guard.assess_members([{"name": "app/ok\x00.sh", "size": 1}])
    assert verdict["verdict"] == "REFUSE"
    assert "NUL byte" in verdict["statement"]


def test_a_control_character_in_a_member_name_is_refused():
    verdict = guard.assess_members([{"name": "app/\x1b[2J.sh", "size": 1}])
    assert verdict["verdict"] == "REFUSE"


def test_an_overlong_member_name_is_refused():
    verdict = guard.assess_members([{"name": "a/" + "b" * 2000, "size": 1}])
    assert verdict["verdict"] == "REFUSE"


def test_duplicate_member_names_are_refused():
    verdict = guard.assess_members([{"name": "app/index", "size": 1},
                                    {"name": "app/index", "size": 2}])
    assert verdict["verdict"] == "REFUSE"
    assert "appear more than once" in verdict["statement"]


def test_a_device_node_is_refused_not_materialised():
    verdict = guard.from_tar(_tar([("dev/mem", None, tarfile.CHRTYPE)]))
    assert verdict["verdict"] == "REFUSE"
    assert "device" in verdict["statement"]


def test_a_fifo_is_refused():
    verdict = guard.from_tar(_tar([("run/pipe", None, tarfile.FIFOTYPE)]))
    assert verdict["verdict"] == "REFUSE"


def test_a_symlink_out_of_the_root_is_refused():
    verdict = guard.from_tar(_tar([("app/link", b"../../etc/shadow", tarfile.SYMTYPE)]))
    assert verdict["verdict"] == "REFUSE"
    assert "links outside" in verdict["statement"]


def test_a_symlink_inside_the_root_is_allowed():
    verdict = guard.from_tar(_tar([("app/lib/libssl.so.3", b"libssl.so.3.0.13", tarfile.SYMTYPE),
                                   ("app/lib/libssl.so.3.0.13", b"elf", tarfile.REGTYPE)]))
    assert verdict["verdict"] == "ALLOW"


def test_a_member_larger_than_the_limit_is_refused():
    limits = guard.ArchiveLimits(max_member_bytes=1024)
    verdict = guard.assess_members([{"name": "big", "size": 2048}], limits=limits)
    assert verdict["verdict"] == "REFUSE"
    assert "over the 1024-byte member limit" in verdict["statement"]


def test_a_total_larger_than_the_limit_is_refused():
    limits = guard.ArchiveLimits(max_total_bytes=1024)
    verdict = guard.assess_members([{"name": "a", "size": 800}, {"name": "b", "size": 800}],
                                   limits=limits)
    assert verdict["verdict"] == "REFUSE"


def test_too_many_members_is_refused():
    limits = guard.ArchiveLimits(max_members=3)
    verdict = guard.assess_members([{"name": f"m{index}", "size": 1} for index in range(4)],
                                   limits=limits)
    assert verdict["verdict"] == "REFUSE"


def test_a_compression_bomb_ratio_is_refused():
    verdict = guard.assess_members([{"name": "bomb", "size": 10_000_000,
                                     "compressed_size": 100}])
    assert verdict["verdict"] == "REFUSE"
    assert "ratio" in verdict["statement"]


def test_a_high_ratio_inside_the_limit_is_allowed():
    verdict = guard.assess_members([{"name": "zeros", "size": 100_000,
                                     "compressed_size": 1_000}])
    assert verdict["verdict"] == "ALLOW"


def test_refused_members_are_listed_individually_with_reasons():
    verdict = guard.assess_members([{"name": "../a", "size": 1}, {"name": "ok", "size": 1}])
    assert len(verdict["refused_members"]) == 1
    assert verdict["refused_members"][0]["name"] == "../a"
    assert verdict["refused_members"][0]["reason"]


def test_a_directory_is_not_a_refusal():
    verdict = guard.assess_members([{"name": "app/", "size": 0, "is_dir": True},
                                    {"name": "app/ok", "size": 1}])
    assert verdict["verdict"] == "ALLOW"


def test_inspect_detects_zip_and_tar_from_magic():
    assert guard.inspect(_zip([("a", b"b")]))["format"] == "zip"
    assert guard.inspect(_tar([("a", b"b", tarfile.REGTYPE)]))["format"] == "tar"


def test_inspect_refuses_an_unrecognised_format_rather_than_assuming_it_is_fine():
    verdict = guard.inspect(b"\x7fELF" + b"\x00" * 512)
    assert verdict["verdict"] == "REFUSE"
    assert "not recognised" in verdict["statement"]


def test_a_corrupt_archive_is_refused_with_the_reader_error():
    verdict = guard.from_zip(b"PK\x03\x04" + b"\x00" * 64)
    assert verdict["verdict"] == "REFUSE"
    assert "cannot be read" in verdict["statement"]


def test_nothing_is_extracted_to_disk(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    guard.from_zip(_zip([("app/ok", b"payload")]))
    guard.from_tar(_tar([("app/ok", b"payload", tarfile.REGTYPE)]))
    assert list(tmp_path.iterdir()) == []


def test_the_limits_travel_with_the_verdict():
    verdict = guard.from_zip(_zip([("app/ok", b"payload")]))
    assert verdict["limits"]["max_members"] == guard.ArchiveLimits().max_members
    assert verdict["declared_bytes"] == len(b"payload")
