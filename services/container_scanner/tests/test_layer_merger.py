from pathlib import Path

from container_scanner.image.layer_merger import merge_layers


def test_merge_layers_overrides_and_whiteouts(tmp_path: Path):
    bottom = tmp_path / "l0"
    top = tmp_path / "l1"
    (bottom / "usr" / "lib").mkdir(parents=True)
    (bottom / "usr" / "lib" / "libssl.so").write_text("old")
    (bottom / "etc").mkdir()
    (bottom / "etc" / "passwd").write_text("root")
    (top / "usr" / "lib").mkdir(parents=True)
    (top / "usr" / "lib" / "libssl.so").write_text("new")
    (top / "etc").mkdir()
    (top / "etc" / ".wh.passwd").write_text("")
    dest = tmp_path / "merged"
    merge_layers([bottom, top], dest)
    assert (dest / "usr" / "lib" / "libssl.so").read_text() == "new"
    assert not (dest / "etc" / "passwd").exists()
