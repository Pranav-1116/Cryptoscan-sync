import json

from scanner.analysis.dependency_inventory import collect_package_dependencies


def test_package_lockfile_keeps_direct_and_transitive_nodes(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"crypto-js": "4.2.0"}}))
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "packages": {
            "": {"dependencies": {"crypto-js": "4.2.0"}},
            "node_modules/crypto-js": {"version": "4.2.0"},
            "node_modules/crypto-js/node_modules/helper": {"version": "1.0.0"},
        }
    }))
    rows, unresolved = collect_package_dependencies(list(tmp_path.iterdir()), tmp_path)
    crypto = next(row for row in rows if row["name"] == "crypto-js")
    helper = next(row for row in rows if row["name"] == "helper")
    assert crypto["direct"] is True and crypto["dependency_type"] == "direct"
    assert helper["direct"] is False and helper["dependency_type"] == "transitive"
    assert crypto["evidence_type"] == "manifest+lockfile"
    assert unresolved == []


def test_cargo_lock_records_unresolved_relationship_metadata(tmp_path):
    (tmp_path / "Cargo.toml").write_text('[dependencies]\nring = "0.17"\n')
    (tmp_path / "Cargo.lock").write_text('''[[package]]\nname = "app"\nversion = "1.0.0"\ndependencies = ["ring 0.17.0", "missing 1.0"]\n\n[[package]]\nname = "ring"\nversion = "0.17.0"\n''')
    rows, unresolved = collect_package_dependencies(list(tmp_path.iterdir()), tmp_path)
    ring = next(row for row in rows if row["name"] == "ring")
    assert ring["direct"] is True and ring["parent"] == "app"
    assert unresolved[0]["parent"] == "app"
    assert unresolved[0]["child"] == "missing"
    assert unresolved[0]["evidence_type"] == "lockfile"
