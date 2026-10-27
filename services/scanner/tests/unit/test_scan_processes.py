"""Per-file process parallelism (CRYPTOSCAN_SCAN_PROCESSES) is deterministic and opt-in."""
from pathlib import Path

from scanner.core.scanner import _scan_files, scan_processes


def _mk(tmp_path: Path, n: int) -> list[Path]:
    files = []
    for i in range(n):
        p = tmp_path / f"C{i}.java"
        p.write_text(f'import javax.crypto.Cipher;\nclass C{i} {{ Cipher c = Cipher.getInstance("{"AES" if i % 2 else "DES"}/CBC/PKCS5Padding"); }}\n')
        files.append(p)
    return files


def test_default_is_single_process(monkeypatch):
    monkeypatch.delenv("CRYPTOSCAN_SCAN_PROCESSES", raising=False)
    assert scan_processes() == 1
    monkeypatch.setenv("CRYPTOSCAN_SCAN_PROCESSES", "auto")
    assert scan_processes() >= 1
    monkeypatch.setenv("CRYPTOSCAN_SCAN_PROCESSES", "garbage")
    assert scan_processes() == 1


def test_pool_and_serial_agree(tmp_path, monkeypatch):
    files = _mk(tmp_path, 80)  # ≥64 so the pool path is taken
    monkeypatch.setenv("CRYPTOSCAN_SCAN_PROCESSES", "1")
    serial = sorted((str(f), x.crypto.algorithm) for f, fs, _ in _scan_files(files, tmp_path) for x in fs)
    monkeypatch.setenv("CRYPTOSCAN_SCAN_PROCESSES", "2")
    pooled = sorted((str(f), x.crypto.algorithm) for f, fs, _ in _scan_files(files, tmp_path) for x in fs)
    assert serial == pooled and len(serial) == 80
