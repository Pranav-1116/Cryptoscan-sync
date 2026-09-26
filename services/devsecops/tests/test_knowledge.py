"""Installed detection knowledge: signed packs, the install gate, and loading.

Two properties are the whole point:

* a pack that does not verify — bad signature, edited file, unlisted file, rule
  text the engine refuses — is *refused*, never half-applied, and the reasons say
  which file or which rule;
* once installed, the next scan loads it without any call site changing, which is
  what makes a disconnected install updatable.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tarfile
from pathlib import Path

import pytest

from devsecops import binary_scan as bs
from devsecops import crypto_constants as cc
from devsecops import knowledge as kb

_spec = importlib.util.spec_from_file_location(
    "binary_scan_fixtures", Path(__file__).with_name("test_binary_scan.py"))
binary_scan_fixtures = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("binary_scan_fixtures", binary_scan_fixtures)
_spec.loader.exec_module(binary_scan_fixtures)
_elf64 = binary_scan_fixtures._elf64

SECRET = "offline-transport-key"
MARKER = b"ACME-BANNED-CIPHER-MARKER"

PACK_RULE = """
rule acme_banned_cipher
{
    meta:
        namespace = "acme-fips"
        description = "Acme policy: this cipher is not approved for the payment estate"
        severity = "HIGH"
    strings:
        $marker = "ACME-BANNED-CIPHER-MARKER" ascii
    condition:
        $marker
}
"""


@pytest.fixture(autouse=True)
def _knowledge_root(tmp_path, monkeypatch):
    """Every test installs into its own knowledge root — never the host's."""
    root = tmp_path / "knowledge"
    monkeypatch.setenv("CRYPTOSCAN_KNOWLEDGE_DIR", str(root))
    return root


def _pack(tmp_path: Path, *, text: str = PACK_RULE, name: str = "acme-fips",
          filename: str = "acme.yar", version: str = "1.0.0") -> Path:
    built = kb.build_pack(name, rules={filename: text}, version=version, out_dir=tmp_path / "built")
    return Path(built["pack_dir"])


def _signed(tmp_path: Path, **kwargs) -> Path:
    pack = _pack(tmp_path, **kwargs)
    kb.sign_pack(pack, secret=SECRET, key_id="offline-2026")
    return pack


# -------------------------------------------------------------- build ------ #

def test_build_records_every_rule_file_with_its_digest(tmp_path):
    pack = _pack(tmp_path, filename="acme.yar")
    manifest = json.loads((pack / kb.MANIFEST_NAME).read_text())
    assert manifest["format"] == kb.PACK_FORMAT
    assert manifest["name"] == "acme-fips" and manifest["version"] == "1.0.0"
    assert [row["name"] for row in manifest["files"]] == ["acme.yar"]
    assert manifest["files"][0]["sha256"] == kb._sha256_bytes(PACK_RULE.encode())
    assert manifest["digest"] == kb.manifest_digest(manifest)
    assert (pack / "rules" / "acme.yar").read_text() == PACK_RULE
    assert not (pack / kb.SIGNATURE_NAME).exists()  # building never signs


def test_build_takes_several_rule_files_in_order(tmp_path):
    built = kb.build_pack("multi", rules={"b.yar": PACK_RULE, "a.yar": PACK_RULE},
                          out_dir=tmp_path)
    assert [row["name"] for row in built["manifest"]["files"]] == ["a.yar", "b.yar"]


@pytest.mark.parametrize("rules", [{"../escape.yar": PACK_RULE}, {"notes.txt": "not a rule"}])
def test_build_refuses_what_is_not_a_rule_file(tmp_path, rules):
    with pytest.raises(kb.KnowledgeError, match="packs carry .yar|simple names"):
        kb.build_pack("bad", rules=rules, out_dir=tmp_path)


def test_build_refuses_an_empty_pack(tmp_path):
    with pytest.raises(kb.KnowledgeError, match="at least one rule file"):
        kb.build_pack("bad", rules={}, out_dir=tmp_path)


@pytest.mark.parametrize("name", ["", "  ", "../etc", ".hidden"])
def test_build_refuses_a_pack_name_that_is_a_path(tmp_path, name):
    with pytest.raises(kb.KnowledgeError):
        kb.build_pack(name, rules={"a.yar": PACK_RULE}, out_dir=tmp_path)


def test_build_copies_rule_files_from_disk(tmp_path):
    source = tmp_path / "acme.yar"
    source.write_text(PACK_RULE)
    built = kb.build_pack("from-disk", rules=[source], out_dir=tmp_path)
    assert (Path(built["pack_dir"]) / "rules" / "acme.yar").is_file()


def test_build_refuses_a_rule_file_that_is_not_there(tmp_path):
    with pytest.raises(kb.KnowledgeError, match="rule file not found"):
        kb.build_pack("missing", rules=[tmp_path / "nope.yar"], out_dir=tmp_path)


# ------------------------------------------------------------- verify ------ #

def test_an_unsigned_pack_is_refused_by_name(tmp_path):
    report = kb.verify_pack(_pack(tmp_path), secret=SECRET)
    assert report["ok"] is False
    assert any(kb.SIGNATURE_NAME in reason for reason in report["reasons"])
    assert any("unsigned pack is refused" in reason for reason in report["reasons"])


def test_a_signed_pack_verifies_and_names_the_key(tmp_path):
    report = kb.verify_pack(_signed(tmp_path), secret=SECRET)
    assert report["ok"] is True and report["reasons"] == []
    assert report["signature"]["key_id"] == "offline-2026"
    assert [row["name"] for row in report["files"]] == ["acme.yar"]
    assert len(report["ruleset"].rules) == 1


def test_signing_needs_a_secret(tmp_path):
    with pytest.raises(kb.KnowledgeError, match="signing secret is required"):
        kb.sign_pack(_pack(tmp_path), secret="")


def test_the_wrong_secret_does_not_verify(tmp_path):
    report = kb.verify_pack(_signed(tmp_path), secret="not-the-key")
    assert report["ok"] is False
    assert any("signature does not match" in reason for reason in report["reasons"])


def test_a_signed_pack_with_no_secret_to_check_it_against_is_refused(tmp_path):
    report = kb.verify_pack(_signed(tmp_path), secret=None)
    assert report["ok"] is False
    assert any("signing secret is required" in reason for reason in report["reasons"])


def test_an_edited_rule_file_is_caught_by_the_manifest_digest(tmp_path):
    pack = _signed(tmp_path)
    (pack / "rules" / "acme.yar").write_text(PACK_RULE.replace("ACME-BANNED", "ACME-ALLOWED"))
    report = kb.verify_pack(pack, secret=SECRET)
    assert report["ok"] is False
    assert any("acme.yar: content does not match the manifest" in reason for reason in report["reasons"])


def test_an_edited_manifest_is_caught_by_its_own_digest(tmp_path):
    pack = _signed(tmp_path)
    manifest_file = pack / kb.MANIFEST_NAME
    manifest = json.loads(manifest_file.read_text())
    manifest["description"] = "edited after signing"
    manifest_file.write_text(json.dumps(manifest, indent=1, sort_keys=True))
    report = kb.verify_pack(pack, secret=SECRET)
    assert report["ok"] is False
    assert any("digest does not match its own content" in reason for reason in report["reasons"])
    assert any("signature does not match the manifest" in reason for reason in report["reasons"])


def test_a_rule_file_the_manifest_never_listed_is_refused(tmp_path):
    pack = _signed(tmp_path)
    (pack / "rules" / "smuggled.yar").write_text("rule smuggled { condition: true }")
    report = kb.verify_pack(pack, secret=SECRET)
    assert report["ok"] is False
    assert any("the manifest does not list: smuggled.yar" in reason for reason in report["reasons"])


def test_a_listed_file_that_is_missing_is_refused(tmp_path):
    pack = _signed(tmp_path)
    (pack / "rules" / "acme.yar").unlink()
    report = kb.verify_pack(pack, secret=SECRET)
    assert report["ok"] is False
    assert any("missing from the pack" in reason for reason in report["reasons"])


def test_rule_text_this_engine_cannot_load_is_refused(tmp_path):
    pack = _signed(tmp_path, text="rule broken { strings: $a = \"x\" condition: $a and }")
    report = kb.verify_pack(pack, secret=SECRET)
    assert report["ok"] is False
    assert any("unsupported condition token" in reason and "acme.yar" in reason
               for reason in report["reasons"])
    assert any("no rules could be loaded" in reason for reason in report["reasons"])


def test_a_rule_group_that_refers_to_a_missing_rule_is_refused(tmp_path):
    text = "rule extra { condition: a }\nrule a { condition: b }"
    report = kb.verify_pack(_signed(tmp_path, text=text), secret=SECRET)
    assert report["ok"] is False
    assert any("unknown rule" in reason for reason in report["reasons"])


def test_a_rule_that_shadows_a_builtin_is_refused(tmp_path):
    from devsecops.yara_rules import BUILTIN_RULES, parse_rules

    builtin_name = parse_rules(BUILTIN_RULES, "builtin")[0].name
    text = f"rule {builtin_name} {{ condition: true }}"
    report = kb.verify_pack(_signed(tmp_path, text=text), secret=SECRET)
    assert report["ok"] is False
    assert any("already exist in the built-in set" in reason for reason in report["reasons"])


def test_a_directory_without_a_manifest_is_not_a_pack(tmp_path):
    empty = tmp_path / "random"
    empty.mkdir()
    report = kb.verify_pack(empty, secret=SECRET)
    assert report["ok"] is False and "not a knowledge pack" in report["reasons"][0]


def test_an_unreadable_manifest_is_reported_not_raised(tmp_path):
    pack = _signed(tmp_path)
    (pack / kb.MANIFEST_NAME).write_text("{ not json")
    report = kb.verify_pack(pack, secret=SECRET)
    assert report["ok"] is False and "not valid JSON" in report["reasons"][0]


def test_an_unsigned_pack_can_be_accepted_explicitly(tmp_path):
    report = kb.verify_pack(_pack(tmp_path), require_signature=False, secret=None)
    assert report["ok"] is True


# ------------------------------------------------------------ install ------ #

def test_install_puts_the_rules_where_a_scan_will_load_them(tmp_path, _knowledge_root):
    report = kb.install_pack(_signed(tmp_path), secret=SECRET)
    assert report["action"] == "installed" and report["installed"] is True
    installed = kb.installed_rule_files()
    assert [path.name for path in installed] == ["acme.yar"]
    assert installed[0].read_text() == PACK_RULE
    registry = kb.load_registry()
    assert registry["packs"]["acme-fips"]["version"] == "1.0.0"
    assert registry["packs"]["acme-fips"]["signed_by"] == "offline-2026"
    assert registry["packs"]["acme-fips"]["rule_names"] == ["acme_banned_cipher"]


def test_installing_the_same_pack_twice_changes_nothing(tmp_path):
    pack = _signed(tmp_path)
    first = kb.install_pack(pack, secret=SECRET)
    second = kb.install_pack(pack, secret=SECRET)
    assert first["action"] == "installed"
    assert second["action"] == "already-installed" and second["installed"] is True
    assert kb.load_registry()["packs"]["acme-fips"]["installed_at"] == first["registry_entry"]["installed_at"]


def test_a_new_version_of_a_pack_replaces_the_old_one(tmp_path):
    kb.install_pack(_signed(tmp_path), secret=SECRET)
    upgraded = _signed(tmp_path, version="2.0.0", text=PACK_RULE.replace("HIGH", "CRITICAL"))
    report = kb.install_pack(upgraded, secret=SECRET)
    assert report["action"] == "installed" and report["replaced"]["version"] == "1.0.0"
    registry = kb.load_registry()["packs"]["acme-fips"]
    assert registry["version"] == "2.0.0"
    assert len(kb.installed_rule_files()) == 1  # one pack, one version loaded


def test_a_refused_pack_installs_nothing(tmp_path):
    pack = _signed(tmp_path)
    (pack / "rules" / "acme.yar").write_text("rule tampered { condition: true }")
    report = kb.install_pack(pack, secret=SECRET)
    assert report["action"] == "refused" and report["installed"] is False
    assert kb.installed_rule_files() == []
    assert kb.load_registry()["packs"] == {}
    assert not kb.packs_dir().exists() or list(kb.packs_dir().iterdir()) == []


def test_a_dry_run_verifies_without_installing(tmp_path):
    report = kb.install_pack(_signed(tmp_path), secret=SECRET, dry_run=True)
    assert report["action"] == "would-install" and report["installed"] is False
    assert kb.load_registry()["packs"] == {}
    assert kb.installed_rule_files() == []


def test_a_pack_can_be_installed_without_a_signature_if_asked(tmp_path):
    report = kb.install_pack(_pack(tmp_path), secret=None, require_signature=False)
    assert report["action"] == "installed"
    assert kb.load_registry()["packs"]["acme-fips"]["signed_by"] is None
    assert len(kb.installed_rule_files()) == 1


def test_an_uninstall_stops_the_rules_loading(tmp_path):
    kb.install_pack(_signed(tmp_path), secret=SECRET)
    report = kb.uninstall_pack("acme-fips")
    assert report["action"] == "uninstalled" and report["removed"] is True
    assert kb.installed_rule_files() == []
    assert kb.load_registry()["packs"] == {}


def test_uninstalling_something_that_is_not_installed_says_so():
    report = kb.uninstall_pack("never-installed")
    assert report["action"] == "not-installed" and report["removed"] is False


def test_a_pack_whose_files_were_removed_by_hand_is_not_loaded(tmp_path):
    kb.install_pack(_signed(tmp_path), secret=SECRET)
    import shutil

    shutil.rmtree(kb.packs_dir() / "acme-fips")
    assert kb.installed_rule_files() == []


def test_a_corrupt_registry_does_not_stop_a_scan(tmp_path):
    kb.install_pack(_signed(tmp_path), secret=SECRET)
    kb.registry_path().write_text("{ truncated")
    assert kb.installed_rule_files() == []
    state = kb.knowledge_state()
    assert state["installed"] == {} and "unreadable" in (state["registry_note"] or "")


# ----------------------------------------------------------- knowledge ------ #

def test_knowledge_state_reports_the_set_a_scan_will_use(tmp_path):
    before = kb.knowledge_state()
    kb.install_pack(_signed(tmp_path), secret=SECRET)
    after = kb.knowledge_state()
    assert after["ruleset"]["rules"] == before["ruleset"]["rules"] + 1
    assert after["ruleset"]["digest"] != before["ruleset"]["digest"]
    assert list(after["installed"]) == ["acme-fips"]
    assert after["builtin"]["rules"] == before["builtin"]["rules"]


def test_an_installed_pack_survives_a_restart_of_the_process(tmp_path):
    kb.install_pack(_signed(tmp_path), secret=SECRET)
    # a fresh read of the registry is what a new process does
    assert [path.name for path in kb.installed_rule_files()] == ["acme.yar"]


def test_the_knowledge_root_prefers_the_explicit_directory(monkeypatch, tmp_path):
    monkeypatch.setenv("CRYPTOSCAN_KNOWLEDGE_DIR", str(tmp_path / "explicit"))
    monkeypatch.setenv("SBOM_STORAGE_DIR", str(tmp_path / "storage"))
    assert kb.knowledge_root() == tmp_path / "explicit"
    monkeypatch.delenv("CRYPTOSCAN_KNOWLEDGE_DIR")
    assert kb.knowledge_root() == tmp_path / "storage" / "knowledge"


def test_the_signing_key_comes_from_the_environment_and_is_never_invented(monkeypatch):
    monkeypatch.delenv("CRYPTOSCAN_BUNDLE_SECRET", raising=False)
    monkeypatch.delenv("SECRET_KEY", raising=False)
    assert kb.resolve_secret() == (None, "unsigned")
    monkeypatch.setenv("CRYPTOSCAN_BUNDLE_SECRET", SECRET)
    assert kb.resolve_secret() == (SECRET, "env:CRYPTOSCAN_BUNDLE_SECRET")
    assert kb.resolve_secret("given") == ("given", "default")


# ---------------------------------------------------------------- scan ------ #

def test_an_installed_pack_is_loaded_by_the_next_scan_without_being_asked(tmp_path, _knowledge_root):
    kb.install_pack(_signed(tmp_path), secret=SECRET)
    sample = tmp_path / "appliance.bin"
    sample.write_bytes(_elf64(constants=MARKER))
    result = bs.scan_path(sample)
    assert result["yara"]["by_rule"].get("acme_banned_cipher") == 1
    assert any(source.endswith("acme.yar") for source in result["yara"]["sources"])
    match = result["binaries"][0]["yara"]["matches"][0]
    assert match["rule"] == "acme_banned_cipher" and match["severity"] == "HIGH"
    assert match["meta"]["namespace"] == "acme-fips"


def test_the_same_scan_without_installed_rules_does_not_match(tmp_path, _knowledge_root):
    kb.install_pack(_signed(tmp_path), secret=SECRET)
    sample = tmp_path / "appliance.bin"
    sample.write_bytes(_elf64(constants=MARKER))
    result = bs.scan_path(sample, include_installed_rules=False)
    assert "acme_banned_cipher" not in json.dumps(result)


def test_a_scan_says_so_when_the_installed_packs_cannot_be_read(tmp_path, monkeypatch):
    """Unreadable pack state is recorded in the ruleset errors, not swallowed."""
    from devsecops import knowledge

    def _broken():
        raise OSError("permission denied reading the pack registry")

    monkeypatch.setattr(knowledge, "installed_rule_files", _broken)
    sample = tmp_path / "appliance.bin"
    sample.write_bytes(_elf64(constants=MARKER))
    result = bs.scan_path(sample)
    errors = result["yara"]["errors"]
    assert any(err["source"] == "installed-knowledge"
               and "built-in rules only" in err["error"] for err in errors)
    assert result["binaries_scanned"] == 1  # the scan itself still happened


def test_scanning_never_fails_because_a_pack_files_were_removed_by_hand(tmp_path, _knowledge_root):
    kb.install_pack(_signed(tmp_path), secret=SECRET)
    import shutil

    shutil.rmtree(kb.packs_dir() / "acme-fips")
    sample = tmp_path / "appliance.bin"
    sample.write_bytes(_elf64(constants=MARKER))
    assert bs.scan_path(sample)["binaries_scanned"] == 1


# --------------------------------------------------------- moving it on ---- #

def test_a_pack_can_be_carried_on_media_and_unpacked_safely(tmp_path):
    pack = _signed(tmp_path)
    bundle = kb.export_bundle(pack, tmp_path / "acme-fips.tar.gz")
    assert Path(bundle["bundle"]).is_file() and bundle["bytes"] > 0
    unpacked = kb.extract_bundle(bundle["bundle"], tmp_path / "carried")
    assert "acme-fips/pack.json" in unpacked["members"]
    report = kb.verify_pack(tmp_path / "carried" / "acme-fips", secret=SECRET)
    assert report["ok"] is True


def _make_tar(path: Path, member: tarfile.TarInfo, payload: bytes = b"") -> Path:
    with tarfile.open(path, "w:gz") as archive:
        if payload:
            import io

            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
        else:
            archive.addfile(member)
    return path


@pytest.mark.parametrize("name", ["../escape.yar", "/etc/escape.yar"])
def test_unpacking_refuses_to_write_outside_the_destination(tmp_path, name):
    member = tarfile.TarInfo(name)
    bundle = _make_tar(tmp_path / "evil.tar.gz", member, b"rule x { condition: true }")
    with pytest.raises(kb.KnowledgeError, match="outside the destination"):
        kb.extract_bundle(bundle, tmp_path / "dest")
    assert not (tmp_path / "escape.yar").exists()


def test_unpacking_refuses_a_symlink(tmp_path):
    member = tarfile.TarInfo("pack/rules/link.yar")
    member.type = tarfile.SYMTYPE
    member.linkname = "/etc/passwd"
    bundle = _make_tar(tmp_path / "link.tar.gz", member)
    with pytest.raises(kb.KnowledgeError, match="do not carry links"):
        kb.extract_bundle(bundle, tmp_path / "dest")


def test_unpacking_refuses_a_bundle_that_is_not_there(tmp_path):
    with pytest.raises(kb.KnowledgeError, match="bundle not found"):
        kb.extract_bundle(tmp_path / "nope.tar.gz", tmp_path / "dest")


def test_export_refuses_a_directory_that_is_not_a_pack(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(kb.KnowledgeError, match="pack.json"):
        kb.export_bundle(empty)


# ----------------------------------------------------------------- CLI ----- #

def test_cli_builds_signs_installs_and_lists(tmp_path, capsys):
    rule = tmp_path / "acme.yar"
    rule.write_text(PACK_RULE)
    out = tmp_path / "built"
    assert kb.main(["build", "acme-fips", "--rules", str(rule), "--out", str(out),
                    "--version", "2026.09", "--json", "-"]) == 0
    pack = out / "acme-fips"
    assert kb.main(["sign", str(pack), "--secret", SECRET, "--key-id", "offline-2026"]) == 0
    assert kb.main(["verify", str(pack), "--secret", SECRET]) == 0
    assert kb.main(["install", str(pack), "--secret", SECRET]) == 0
    assert len(kb.installed_rule_files()) == 1
    capsys.readouterr()
    assert kb.main(["list"]) == 0
    listing = capsys.readouterr().out
    assert "acme-fips v2026.09" in listing and "what a scan will load" in listing


def test_cli_refuses_an_unsigned_pack_with_reasons_and_exit_2(tmp_path, capsys):
    rule = tmp_path / "acme.yar"
    rule.write_text(PACK_RULE)
    assert kb.main(["build", "acme-fips", "--rules", str(rule), "--out", str(tmp_path)]) == 0
    assert kb.main(["install", str(tmp_path / "acme-fips"), "--secret", SECRET]) == 2
    err = capsys.readouterr().err
    assert "refused" in err and "pack.sig" in err
    assert kb.installed_rule_files() == []


def test_cli_verifies_an_exported_bundle(tmp_path, capsys):
    pack = _signed(tmp_path)
    bundle = kb.export_bundle(pack, tmp_path / "acme.tar.gz")
    assert kb.main(["verify", bundle["bundle"], "--secret", SECRET, "--out", str(tmp_path / "u")]) == 0
    assert "verify" in capsys.readouterr().out


def test_cli_uninstall_reports_what_is_not_there(capsys):
    assert kb.main(["uninstall", "ghost"]) == 0
    assert "not-installed" in capsys.readouterr().out


@pytest.mark.parametrize("argv", [["build"], ["verify"], ["install"], ["uninstall"], ["extract"]])
def test_cli_asks_for_what_it_needs(argv):
    assert kb.main(argv) == 4


# ------------------------------------------------ constant tables in a pack --- #
# The second thing an update bundle can carry. Rules say what a file *is*; tables
# say what bytes mean, and a table is only evidence if the scan can name where it
# came from. So: not buildable unless it loads, not installable unless it verifies,
# and every match cites its source.

TABLE_BYTES = bytes(range(1, 65))
TABLE_DOCUMENT = {
    "algorithm": "ACME-Cipher", "table": "rounds", "encoding": "hex",
    "bytes": TABLE_BYTES.hex(), "minimum": 32,
    "note": "Acme's proprietary round constants",
}


def _table_pack(tmp_path: Path, *, name: str = "acme-tables", rules: dict | None = None,
                tables: dict | None = None, version: str = "2026.09") -> Path:
    built = kb.build_pack(name, rules=rules or {}, tables=tables or {"acme.json": TABLE_DOCUMENT},
                          version=version, out_dir=tmp_path / "built")
    kb.sign_pack(built["pack_dir"], secret=SECRET, key_id="offline-2026")
    return Path(built["pack_dir"])


def test_build_writes_a_table_canonically_and_lists_it_in_the_manifest(tmp_path):
    pack = _table_pack(tmp_path)
    manifest = json.loads((pack / kb.MANIFEST_NAME).read_text())
    row = manifest["tables"][0]
    assert row["name"] == "acme.json" and row["algorithm"] == "ACME-Cipher"
    assert row["table"] == "rounds" and row["bytes"] == 64
    written = pack / kb.TABLES_DIRNAME / "acme.json"
    assert hashlib.sha256(written.read_bytes()).hexdigest() == row["sha256"]
    # canonical form: the same table built twice must hash the same, or two
    # operators comparing digests cannot tell whether they agree
    assert written.read_text() == json.dumps(TABLE_DOCUMENT, indent=1, sort_keys=True)
    again = kb.build_pack("acme-again", rules={}, tables={"acme.json": TABLE_DOCUMENT},
                          out_dir=tmp_path / "built2")
    assert again["manifest"]["tables"][0]["sha256"] == row["sha256"]


def test_a_pack_of_tables_only_builds_signs_verifies_and_installs(tmp_path):
    pack = _table_pack(tmp_path)
    report = kb.verify_pack(pack, secret=SECRET)
    assert report["ok"], report["reasons"]
    assert report["ruleset"] is None  # no rules to load, and that is not a failure
    assert [row["algorithm"] for row in report["tables"]] == ["ACME-Cipher"]
    installed = kb.install_pack(pack, secret=SECRET)
    assert installed["action"] == "installed"
    assert [row["table"] for row in installed["registry_entry"]["tables"]] == ["rounds"]


def test_a_pack_with_rules_and_tables_carries_both(tmp_path):
    pack = _table_pack(tmp_path, rules={"acme.yar": PACK_RULE}, tables={"acme.json": TABLE_DOCUMENT})
    report = kb.verify_pack(pack, secret=SECRET)
    assert report["ok"], report["reasons"]
    assert [row["name"] for row in report["files"]] == ["acme.yar"]
    assert [row["name"] for row in report["table_files"]] == ["acme.json"]
    assert [table.name for table in report["ruleset"].rules] == ["acme_banned_cipher"]


@pytest.mark.parametrize("tables,expected", [
    ({"acme.json": "{not json"}, "not valid JSON"),
    ({"acme.txt": TABLE_DOCUMENT}, "constant tables are JSON"),
    ({"acme.json": {k: v for k, v in TABLE_DOCUMENT.items() if k != "algorithm"}}, "has no 'algorithm'"),
    ({"acme.json": {**TABLE_DOCUMENT, "encoding": "base64"}}, "unsupported encoding"),
    ({"acme.json": {**TABLE_DOCUMENT, "mimimum": 8}}, "unknown field"),
    ({"acme.json": {**TABLE_DOCUMENT, "algorithm": "AES", "table": "S-box"}},
     "already exists in the database"),
    ({"acme.json": {**TABLE_DOCUMENT, "bytes": cc.aes_sbox().hex(), "minimum": 32}},
     "already the AES/S-box table"),
])
def test_a_table_a_scan_would_refuse_cannot_be_built(tmp_path, tables, expected):
    """The refusal happens on the workstation, not at the air-gapped install."""
    with pytest.raises(kb.KnowledgeError) as refused:
        kb.build_pack("acme-tables", rules={}, tables=tables, out_dir=tmp_path / "built")
    assert expected in str(refused.value)


def test_verification_refuses_a_table_edited_after_signing(tmp_path):
    pack = _table_pack(tmp_path)
    target = pack / kb.TABLES_DIRNAME / "acme.json"
    target.write_text(json.dumps({**TABLE_DOCUMENT, "minimum": 8}, indent=1, sort_keys=True))
    report = kb.verify_pack(pack, secret=SECRET)
    assert report["ok"] is False
    assert any("acme.json: content does not match the manifest" in reason for reason in report["reasons"])
    assert kb.install_pack(pack, secret=SECRET)["action"] == "refused"


def test_verification_refuses_a_table_the_manifest_never_listed(tmp_path):
    pack = _table_pack(tmp_path)
    extra = {**TABLE_DOCUMENT, "algorithm": "ACME-Cipher-II"}
    (pack / kb.TABLES_DIRNAME / "smuggled.json").write_text(json.dumps(extra))
    report = kb.verify_pack(pack, secret=SECRET)
    assert report["ok"] is False
    assert any("tables the manifest does not list: smuggled.json" in reason
               for reason in report["reasons"])


def test_verification_refuses_a_listed_table_that_is_missing(tmp_path):
    pack = _table_pack(tmp_path)
    (pack / kb.TABLES_DIRNAME / "acme.json").unlink()
    report = kb.verify_pack(pack, secret=SECRET)
    assert report["ok"] is False
    assert any("listed in the manifest but missing" in reason for reason in report["reasons"])


def test_an_installed_table_is_loaded_with_its_pack_as_its_source(tmp_path):
    pack = _table_pack(tmp_path)
    kb.install_pack(pack, secret=SECRET)
    loaded = kb.installed_constant_tables()
    assert loaded["errors"] == []
    assert [table.algorithm for table in loaded["tables"]] == ["ACME-Cipher"]
    assert loaded["tables"][0].source == "pack:acme-tables@2026.09"
    assert loaded["sources"] == ["pack:acme-tables@2026.09"]

    state = kb.knowledge_state()
    assert state["tables"]["builtin"] == len(cc.constant_tables())
    assert state["tables"]["installed"] == 1 and state["tables"]["total"] == state["tables"]["builtin"] + 1
    assert state["tables"]["digest"] == cc.tableset_digest(
        (*cc.constant_tables(), *loaded["tables"]))
    assert "ACME-Cipher" in state["tables"]["algorithms"]


def test_a_table_edited_in_the_install_is_reported_and_not_searched(tmp_path):
    """The registry records what was verified; a host edit makes that a lie."""
    pack = _table_pack(tmp_path)
    kb.install_pack(pack, secret=SECRET)
    installed = Path(kb.installed_table_files()[0])
    installed.write_text(json.dumps({**TABLE_DOCUMENT, "minimum": 8}, indent=1, sort_keys=True))

    loaded = kb.installed_constant_tables()
    assert loaded["tables"] == ()
    assert "changed after it was verified" in loaded["errors"][0]["error"]
    assert loaded["errors"][0]["source"] == "pack:acme-tables@2026.09"
    assert kb.knowledge_state()["tables"]["errors"]  # visible where an operator looks


def test_uninstalling_a_pack_takes_its_tables_with_it(tmp_path):
    pack = _table_pack(tmp_path)
    kb.install_pack(pack, secret=SECRET)
    assert len(kb.installed_constant_tables()["tables"]) == 1
    kb.uninstall_pack("acme-tables")
    assert kb.installed_constant_tables()["tables"] == ()
    assert kb.knowledge_state()["tables"]["installed"] == 0


def test_replacing_a_pack_replaces_its_tables(tmp_path):
    first = _table_pack(tmp_path, name="acme-tables", version="2026.09")
    kb.install_pack(first, secret=SECRET)
    second_document = {**TABLE_DOCUMENT, "table": "rounds-v2", "bytes": bytes(range(65, 129)).hex()}
    second = _table_pack(tmp_path, name="acme-tables", tables={"acme.json": second_document},
                         version="2026.10")
    replaced = kb.install_pack(second, secret=SECRET)
    assert replaced["action"] == "installed" and replaced["replaced"]["version"] == "2026.09"
    loaded = kb.installed_constant_tables()
    assert [table.table for table in loaded["tables"]] == ["rounds-v2"]
    assert loaded["tables"][0].source == "pack:acme-tables@2026.10"


def test_a_rule_only_pack_is_unchanged_by_the_table_support(tmp_path):
    """Packs built before tables existed must still verify byte for byte."""
    pack = _signed(tmp_path)
    manifest = json.loads((pack / kb.MANIFEST_NAME).read_text())
    assert "tables" not in manifest
    report = kb.verify_pack(pack, secret=SECRET)
    assert report["ok"] and report["tables"] == [] and report["table_files"] == []
    assert kb.install_pack(pack, secret=SECRET)["action"] == "installed"
    assert kb.installed_constant_tables()["tables"] == ()


def test_the_cli_builds_a_table_pack_and_lists_it(tmp_path, capsys):
    document = tmp_path / "acme.json"
    document.write_text(json.dumps(TABLE_DOCUMENT))
    assert kb.main(["build", "acme-tables", "--table", str(document), "--out", str(tmp_path)]) == 0
    assert "1 table(s)" in capsys.readouterr().out
    assert kb.main(["sign", str(tmp_path / "acme-tables"), "--secret", SECRET]) == 0
    assert kb.main(["install", str(tmp_path / "acme-tables"), "--secret", SECRET]) == 0
    assert kb.main(["list"]) == 0
    listing = capsys.readouterr().out
    assert "constant tables: 21 (20 built-in, 1 from packs)" in listing


def test_the_cli_refuses_a_table_it_cannot_load(tmp_path, capsys):
    """Exit 2: the command was well-formed, the pack was not. The reason is printed."""
    document = tmp_path / "acme.json"
    document.write_text(json.dumps({**TABLE_DOCUMENT, "kind": "magic"}))
    assert kb.main(["build", "acme-tables", "--table", str(document), "--out", str(tmp_path)]) == 2
    assert "unknown kind 'magic'" in capsys.readouterr().err


def test_an_installed_table_changes_what_the_next_scan_names(tmp_path):
    """The air-gap acceptance test: an update on media changes a scan's evidence.

    A table that only ever appears in a listing would be a claim, not a capability.
    This walks the whole path: build a table for an algorithm the scanner has never
    heard of, sign it, install it, scan a binary that contains those bytes, and
    check that the algorithm is *named* — with the pack as its stated source — then
    that the answer goes back to the built-in database when the pack is removed.
    """
    target = tmp_path / "images"
    target.mkdir()
    (target / "app.bin").write_bytes(_elf64(soname="app.so", constants=TABLE_BYTES * 2))

    before = bs.scan_path(target)
    assert before["constant_tables"]["total"] == len(cc.constant_tables())
    assert before["constant_tables"]["installed"] == 0
    assert "ACME-Cipher" not in before["binaries"][0]["crypto"]["algorithms"]

    pack = _table_pack(tmp_path)
    assert kb.install_pack(pack, secret=SECRET)["action"] == "installed"

    after = bs.scan_path(target)
    tables = after["constant_tables"]
    assert tables["installed"] == 1 and tables["total"] == tables["builtin"] + 1
    assert tables["sources"] == ["pack:acme-tables@2026.09"]
    assert tables["digest"] != tables["builtin_digest"]
    assert tables["errors"] == []

    record = after["binaries"][0]
    named = next(row for row in record["crypto"]["algorithm_evidence"]
                 if row["name"] == "ACME-Cipher")
    assert named["strongest_evidence"] == "CONSTANT_MATCH"
    assert named["constant_level"] == "CONSTANT_COMPLETE"
    assert "ACME-Cipher" in record["crypto"]["algorithms"]
    cited = next(row for row in record["crypto_constants"] if row["algorithm"] == "ACME-Cipher")
    assert cited["source"] == "pack:acme-tables@2026.09"
    assert cited["complete"] is True
    assert "table from pack acme-tables@2026.09" in cited["evidence"]

    # a caller can ask for the release-only answer, and the report says so
    release_only = bs.scan_path(target, include_installed_tables=False)
    assert release_only["constant_tables"]["installed"] == 0
    assert "ACME-Cipher" not in release_only["binaries"][0]["crypto"]["algorithms"]

    # and removing the pack removes the capability, not just the listing
    kb.uninstall_pack("acme-tables")
    removed = bs.scan_path(target)
    assert removed["constant_tables"]["installed"] == 0
    assert "ACME-Cipher" not in removed["binaries"][0]["crypto"]["algorithms"]


def test_a_broken_installed_table_is_reported_on_the_scan_it_could_have_helped(tmp_path):
    """A table that will not load must not read as "nothing to find"."""
    pack = _table_pack(tmp_path)
    kb.install_pack(pack, secret=SECRET)
    Path(kb.installed_table_files()[0]).write_text("{not json")

    target = tmp_path / "images"
    target.mkdir()
    (target / "app.bin").write_bytes(_elf64(soname="app.so", constants=TABLE_BYTES * 2))
    result = bs.scan_path(target)
    errors = result["constant_tables"]["errors"]
    assert errors and errors[0]["file"] == "acme.json"
    assert "pack:acme-tables@2026.09" == errors[0]["source"]
    assert "changed after it was verified" in errors[0]["error"]
    assert "built-in tables only" not in result["constant_tables"]["note"]
    assert "ACME-Cipher" not in result["binaries"][0]["crypto"]["algorithms"]


def test_the_cli_asks_for_a_rule_or_a_table(tmp_path, capsys):
    assert kb.main(["build", "acme-tables", "--out", str(tmp_path)]) == 4
    assert "at least one --rules FILE or --table FILE" in capsys.readouterr().err


def test_a_table_pack_survives_the_journey_as_one_bundle(tmp_path):
    """Export, unpack, verify, install — the path an air-gapped update really takes.

    The bundle is the only artefact that crosses the gap, so a content directory
    the exporter forgets is a table that never arrives. (It did exactly that
    before this test existed: the first live drill installed a bundle and the
    tables were missing.)
    """
    pack = _table_pack(tmp_path)
    bundle = kb.export_bundle(pack, tmp_path / "acme-tables-2026.09.tar.gz")
    unpacked = kb.extract_bundle(bundle["bundle"], tmp_path / "unpacked")
    assert f"acme-tables/{kb.TABLES_DIRNAME}/acme.json" in unpacked["members"]
    extracted = Path(unpacked["dest"]) / "acme-tables"
    report = kb.verify_pack(extracted, secret=SECRET)
    assert report["ok"], report["reasons"]
    assert [row["algorithm"] for row in report["tables"]] == ["ACME-Cipher"]
    assert kb.install_pack(extracted, secret=SECRET)["action"] == "installed"
    assert len(kb.installed_constant_tables()["tables"]) == 1


def test_a_bundle_missing_its_tables_is_refused_not_half_installed(tmp_path):
    pack = _table_pack(tmp_path)
    bundle = Path(kb.export_bundle(pack, tmp_path / "acme-tables.tar.gz")["bundle"])
    stripped = tmp_path / "stripped.tar.gz"
    with tarfile.open(bundle) as source, tarfile.open(stripped, "w:gz") as destination:
        for member in source.getmembers():
            # inside the pack, not in the pack's *name* (which is acme-tables)
            if member.name.startswith(f"acme-tables/{kb.TABLES_DIRNAME}"):
                continue
            destination.addfile(member, source.extractfile(member) if member.isreg() else None)
    unpacked = kb.extract_bundle(stripped, tmp_path / "stripped")
    report = kb.verify_pack(Path(unpacked["dest"]) / "acme-tables", secret=SECRET)
    assert report["ok"] is False
    assert any("acme.json: listed in the manifest but missing" in reason
               for reason in report["reasons"])


def test_reinstalling_a_pack_repairs_files_changed_on_the_host(tmp_path):
    """`already-installed` must not be said over a copy that no longer verifies."""
    pack = _table_pack(tmp_path, rules={"acme.yar": PACK_RULE})
    first = kb.install_pack(pack, secret=SECRET)
    assert first["action"] == "installed"

    second = kb.install_pack(pack, secret=SECRET)
    assert second["action"] == "already-installed"

    # a table edited on this host, and a rule truncated by a bad restore
    table_path = Path(kb.installed_table_files()[0])
    table_path.write_text(json.dumps({**TABLE_DOCUMENT, "minimum": 8}, indent=1, sort_keys=True))
    rule_path = Path(kb.installed_rule_files()[0])
    rule_path.write_text(PACK_RULE[:40])

    dry = kb.install_pack(pack, secret=SECRET, dry_run=True)
    assert dry["action"] == "would-repair"
    assert sorted(row["file"] for row in dry["drift"]) == ["acme.json", "acme.yar"]
    assert {row["reason"] for row in dry["drift"]} == {"changed"}
    assert json.loads(table_path.read_text())["minimum"] == 8  # a dry run writes nothing

    repaired = kb.install_pack(pack, secret=SECRET)
    assert repaired["action"] == "repaired"
    assert sorted(row["file"] for row in repaired["repaired"]) == ["acme.json", "acme.yar"]
    assert json.loads(table_path.read_text())["minimum"] == 32
    assert rule_path.read_text() == PACK_RULE

    # and the repaired install is once again exactly what was verified
    assert kb.install_pack(pack, secret=SECRET)["action"] == "already-installed"
    assert kb.installed_constant_tables()["errors"] == []
    assert len(kb.installed_constant_tables()["tables"]) == 1


def test_reinstalling_a_pack_restores_a_file_that_went_missing(tmp_path):
    pack = _table_pack(tmp_path)
    kb.install_pack(pack, secret=SECRET)
    Path(kb.installed_table_files()[0]).unlink()
    repaired = kb.install_pack(pack, secret=SECRET)
    assert repaired["action"] == "repaired"
    assert repaired["repaired"][0]["reason"] == "missing"
    assert len(kb.installed_constant_tables()["tables"]) == 1
