"""Binary CFA adapters: angr/Ghidra guarded, honest degradation (52, R38)."""

from __future__ import annotations

import json
import os
import stat
import sys
import types

from universal_crypto import binary_cfa
from universal_crypto.binary_tables import scan_tables


def test_scan_tables_is_the_shared_attribution_core():
    # the CFA layer builds on the existing byte-level registry
    # (scan_tables matches full table heads — 32 bytes for AES)
    from universal_crypto.binary_tables import _SBOX
    hits = scan_tables(bytes(_SBOX))
    assert any(h.get("algorithm") == "AES" for h in hits)


# ── honest degradation ───────────────────────────────────────────────


def test_angr_absent_reports_reason_and_infers_nothing(monkeypatch):
    monkeypatch.setitem(sys.modules, "angr", None)  # import angr → ImportError
    report = binary_cfa.angr_analysis("/nonexistent.elf")
    assert report["available"] is False
    assert "angr not installed" in report["reason"]
    assert report["functions"] == []


def test_ghidra_absent_reports_reason(monkeypatch):
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    monkeypatch.setattr(binary_cfa.shutil, "which", lambda name: None)
    report = binary_cfa.ghidra_analysis("/nonexistent.elf")
    assert report["available"] is False
    assert "GHIDRA_INSTALL_DIR" in report["reason"]


def test_analyze_reports_every_attempt_when_nothing_available(monkeypatch):
    monkeypatch.setitem(sys.modules, "angr", None)
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    monkeypatch.setattr(binary_cfa.shutil, "which", lambda name: None)
    report = binary_cfa.analyze("/nonexistent.elf")
    assert report["model"] == "binary-cfa/v1"
    assert report["available"] is False
    assert [a["tool"] for a in report["attempted"]] == ["angr", "ghidra"]
    assert report["functions"] == []


# ── angr plumbing with a stub module ─────────────────────────────────


class _StubBlock:
    def __init__(self, data):
        self.bytes = data


def test_angr_analysis_attributes_constants_to_functions(monkeypatch, tmp_path):
    from universal_crypto.binary_tables import _SBOX

    # scan_tables matches full table heads (32 bytes for AES)
    crypto_body = bytes(_SBOX[:32]) + b"\x00" * 32
    plain_body = b"\x90" * 64

    function_blocks: dict[int, bytes] = {}
    functions: dict[str, object] = {}

    class _StubFunction:
        def __init__(self, name, addr, size, blocks):
            self.name, self.addr, self.size = name, addr, size
            self.block_addrs = [b[0] for b in blocks]
            function_blocks.update(dict(blocks))

    class _StubCfg:
        def __init__(self):
            self.kb = types.SimpleNamespace(functions=functions)

    class _StubProject:
        def __init__(self, path, **kwargs):
            _StubProject.last_path = path
            _StubProject.last_kwargs = kwargs
            self._cfg = _StubCfg()

        @property
        def analyses(self):
            return types.SimpleNamespace(CFGFast=lambda: self._cfg)

        @property
        def factory(self):
            return types.SimpleNamespace(
                block=lambda addr: _StubBlock(function_blocks[addr]))

    functions["aes_expand"] = _StubFunction(
        "aes_expand", 0x401000, 64, [(0x401000, crypto_body)])
    functions["main"] = _StubFunction(
        "main", 0x401100, 64, [(0x401100, plain_body)])

    fake_angr = types.ModuleType("angr")
    fake_angr.Project = _StubProject
    monkeypatch.setitem(sys.modules, "angr", fake_angr)

    binary = tmp_path / "libcrypto.so"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 60)
    report = binary_cfa.angr_analysis(str(binary))

    assert _StubProject.last_path == str(binary)
    assert _StubProject.last_kwargs == {"auto_load_libs": False}
    assert report["available"] is True
    names = {f["name"]: f for f in report["functions"]}
    assert names["aes_expand"]["algorithms"] == ["AES"]
    assert names["aes_expand"]["hits"] > 0
    assert names["main"]["algorithms"] == []
    # sorted: most hits first
    assert report["functions"][0]["name"] == "aes_expand"


# ── Ghidra runner with a fake headless executable ────────────────────


def test_ghidra_runner_parses_post_script_json(monkeypatch, tmp_path):
    payload = {"functions": [
        {"name": "AES_set_encrypt_key", "address": "0x1040",
         "size": 187, "algorithms": ["AES"], "hits": 1}]}
    fake = tmp_path / "analyzeHeadless"
    fake.write_text("#!/bin/sh\n"
                    "echo 'INFO  ANALYZING'\n"
                    f"echo '{json.dumps(payload)}'\n")
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)

    ghidra_dir = tmp_path / "ghidra"
    script_dir = ghidra_dir / "scripts"
    script_dir.mkdir(parents=True)
    (script_dir / binary_cfa.GHIDRA_SCRIPT_NAME).write_text("# stub\n")

    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra_dir))
    # point the runner at the stub script directory
    monkeypatch.setattr(binary_cfa, "_ghidra_headless", lambda: str(fake))

    report = binary_cfa.ghidra_analysis(
        "/bin/true", script_dir=str(script_dir))
    assert report["available"] is True
    assert report["functions"] == payload["functions"]
    assert report["tool"] == "ghidra"


def test_ghidra_runner_reports_failure_not_silence(monkeypatch, tmp_path):
    fake = tmp_path / "analyzeHeadless"
    fake.write_text("#!/bin/sh\nexit 3\n")
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    script_dir = tmp_path
    (script_dir / binary_cfa.GHIDRA_SCRIPT_NAME).write_text("# stub\n")
    monkeypatch.setattr(binary_cfa, "_ghidra_headless", lambda: str(fake))

    report = binary_cfa.ghidra_analysis(
        "/bin/true", script_dir=str(script_dir))
    assert report["available"] is False
    assert "rc=3" in report["reason"]


def test_ghidra_script_contract_is_satisfied_by_shipped_script():
    # the shipped post-script must exist and end with the single JSON print
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))))
    script = os.path.join(repo_root, "deploy", "ghidra",
                          binary_cfa.GHIDRA_SCRIPT_NAME)
    assert os.path.isfile(script)
    body = open(script).read()
    assert 'print(json.dumps({"functions": functions}))' in body
    assert "SBOX_HEAD" in body  # carries real AES S-box leading bytes
    # and the S-box head in the script matches the Python-side registry
    import re as _re

    from universal_crypto.binary_tables import _SBOX
    block = body[body.index("SBOX_HEAD = bytes(["):body.index("])",
                   body.index("SBOX_HEAD = bytes([")) + 2]
    literals = [int(m, 16) for m in _re.findall(r"0x[0-9a-f]{2}", block)]
    assert literals == list(_SBOX[:16])
