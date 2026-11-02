"""An executed parser qualification matrix — not a table in a document.

The review's item 3 makes the point precisely: *recognised filename ≠ complete
compatibility with every format revision*. A claim like that can only be made
honestly by running the real parser over a real file for each revision, so this
module does exactly that.

Every case is a tiny source tree written to disk, scanned by
``devsecops.sbom_scan.scan_source`` — the same entry point the API uses — and
checked for the package names the file declares. Nothing is mocked: if the
``package-lock`` v3 reader breaks, ``npm_lockfile_v3`` goes red.

Three verdicts, and no others:

``PASS``
    every expected component was found, with the expected version.
``FIX``
    the parser ran and produced something, but not what the file says — a defect.
``PARTIAL``
    the file was recognised and partially read (for example the lockfile was
    accepted but the manifest was not), which is a qualification gap rather than
    a wrong answer.

A case whose expected component is missing makes the artifact red. That is the
whole point: the matrix is a measurement, and the day a reader regresses the
guide fails.
"""

from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

SCHEMA = "cryptoscan.sbom-parser-qualification/1"

PASS, PARTIAL, FIX = "PASS", "PARTIAL", "FIX"

#: Ecosystems with both a manifest and a lockfile reader, as the review lists them.
ECOSYSTEMS: tuple[str, ...] = ("npm", "python", "maven", "go", "rust", "dotnet", "ruby", "php")


@dataclass(frozen=True)
class Case:
    """One file (or file pair) and the components it must yield."""

    id: str
    ecosystem: str
    manifest: str
    lockfile: str | None
    revision: str
    files: dict[str, str]
    expect: tuple[tuple[str, str], ...]
    note: str = ""
    #: At least one expected row must carry this ``scope`` (``resolved`` for a
    #: lockfile, ``declared`` for a manifest).
    expect_scope: str | None = None
    #: Names that must *not* appear — a manifest's range must not be reported as
    #: a resolved version.
    forbid: tuple[str, ...] = ()
    #: ``(name, raw spec)``: the specifier as the file wrote it. A range that is
    #: silently coerced to a version is a defect, not a normalisation.
    expect_spec: tuple[tuple[str, str], ...] = ()
    #: ``(name, constraint kind)`` — ``EXACT``, ``RANGE``, ``ANY``, ``NON_VERSION``.
    expect_constraint: tuple[tuple[str, str], ...] = ()

    def expected_names(self) -> list[str]:
        return [name for name, _ in self.expect]


def _case(**kwargs: Any) -> Case:
    return Case(**kwargs)


NPM_PACKAGE_JSON = """{
  "name": "payments-api",
  "version": "1.0.0",
  "dependencies": {"jose": "^5.0.0", "express": "4.19.2"},
  "devDependencies": {"jest": "^29.7.0"}
}
"""

CASES: tuple[Case, ...] = (
    _case(
        id="npm_lockfile_v1", ecosystem="npm", manifest="package.json",
        lockfile="package-lock.json", revision="lockfileVersion 1",
        files={
            "package.json": NPM_PACKAGE_JSON,
            "package-lock.json": """{
  "name": "payments-api", "version": "1.0.0", "lockfileVersion": 1,
  "dependencies": {
    "jose": {"version": "5.2.3", "resolved": "https://registry.npmjs.org/jose/-/jose-5.2.3.tgz"},
    "express": {"version": "4.19.2", "dependencies": {"body-parser": {"version": "1.20.2"}}}
  }
}
"""},
        expect=(("jose", "5.2.3"), ("express", "4.19.2")), expect_scope="resolved"),
    _case(
        id="npm_lockfile_v2", ecosystem="npm", manifest="package.json",
        lockfile="package-lock.json", revision="lockfileVersion 2",
        files={
            "package.json": NPM_PACKAGE_JSON,
            "package-lock.json": """{
  "name": "payments-api", "version": "1.0.0", "lockfileVersion": 2,
  "requires": true,
  "packages": {
    "": {"name": "payments-api", "version": "1.0.0", "dependencies": {"jose": "^5.0.0"}},
    "node_modules/jose": {"version": "5.2.3", "resolved": "https://registry.npmjs.org/jose/-/jose-5.2.3.tgz"},
    "node_modules/express": {"version": "4.19.2"}
  },
  "dependencies": {"jose": {"version": "5.2.3"}, "express": {"version": "4.19.2"}}
}
"""},
        expect=(("jose", "5.2.3"), ("express", "4.19.2")), expect_scope="resolved"),
    _case(
        id="npm_lockfile_v3", ecosystem="npm", manifest="package.json",
        lockfile="package-lock.json", revision="lockfileVersion 3",
        files={
            "package.json": NPM_PACKAGE_JSON,
            "package-lock.json": """{
  "name": "payments-api", "version": "1.0.0", "lockfileVersion": 3,
  "packages": {
    "node_modules/jose": {"version": "5.9.6", "integrity": "sha512-abc"},
    "node_modules/express": {"version": "4.19.2"},
    "node_modules/body-parser": {"version": "1.20.2"}
  }
}
"""},
        expect=(("jose", "5.9.6"), ("express", "4.19.2")), expect_scope="resolved"),
    _case(
        id="npm_declared_range_is_not_a_version", ecosystem="npm", manifest="package.json",
        lockfile=None, revision="manifest only",
        files={"package.json": NPM_PACKAGE_JSON},
        expect=(("jose", "5.0.0"),), expect_scope="declared",
        expect_spec=(("jose", "^5.0.0"),), expect_constraint=(("jose", "RANGE"),),
        note="the caret survives, so nothing downstream can mistake a range for a pin"),
    _case(
        id="python_requirements", ecosystem="python", manifest="requirements.txt",
        lockfile=None, revision="pip requirements",
        files={"requirements.txt": "cryptography==42.0.5\nrequests>=2.31\n# comment\n"},
        expect=(("cryptography", "42.0.5"),), expect_scope="declared"),
    _case(
        id="python_poetry_lock", ecosystem="python", manifest="pyproject.toml",
        lockfile="poetry.lock", revision="poetry lock",
        files={
            "pyproject.toml": '[tool.poetry.dependencies]\ncryptography = "^42.0.5"\n',
            "poetry.lock": """[[package]]
name = "cryptography"
version = "42.0.5"
description = "cryptography is a package designed to expose cryptographic primitives"
optional = false
python-versions = ">=3.7"

[[package]]
name = "cffi"
version = "1.16.0"
description = "Foreign Function Interface for Python"
optional = false
python-versions = ">=3.8"
"""},
        expect=(("cryptography", "42.0.5"),), expect_scope="resolved",
        expect_spec=(("cryptography", "^42.0.5"),), expect_constraint=(("cryptography", "RANGE"),),
        note="the manifest half must be read too: the resolved 42.0.5 is a consequence of "
             "the declared ^42.0.5, and a lockfile-only answer cannot tell a reviewer the "
             "project accepted a range"),
    _case(
        id="python_pipfile_lock", ecosystem="python", manifest="Pipfile",
        lockfile="Pipfile.lock", revision="pipenv lock v2",
        files={
            "Pipfile": '[packages]\ncryptography = "*"\n',
            "Pipfile.lock": """{
  "_meta": {"hash": {"sha256": "0"}, "pipfile-spec": 6, "requires": {"python_version": "3.11"}},
  "default": {
    "cryptography": {"hashes": [], "index": "pypi", "version": "==42.0.5"},
    "requests": {"hashes": [], "index": "pypi", "version": "==2.31.0"}
  },
  "develop": {}
}
"""},
        expect=(("cryptography", "42.0.5"),), expect_scope="resolved",
        expect_spec=(("cryptography", "*"),), expect_constraint=(("cryptography", "ANY"),),
        note="'*' is a declaration with no version in it at all; reporting the locked 42.0.5 "
             "without saying the project declared 'anything' would overstate the guarantee"),
    _case(
        id="maven_pom", ecosystem="maven", manifest="pom.xml",
        lockfile=None, revision="pom.xml",
        files={"pom.xml": """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.bank</groupId><artifactId>payments</artifactId><version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcprov-jdk18on</artifactId>
      <version>1.78.1</version>
    </dependency>
    <dependency>
      <groupId>com.nimbusds</groupId>
      <artifactId>nimbus-jose-jwt</artifactId>
      <version>9.37.3</version>
    </dependency>
  </dependencies>
</project>
"""},
        expect=(("bcprov-jdk18on", "1.78.1"),), expect_scope="declared"),
    _case(
        id="go_mod_and_sum", ecosystem="go", manifest="go.mod", lockfile="go.sum",
        revision="go modules",
        files={
            "go.mod": """module github.com/bank/payments

go 1.22

require (
\tgolang.org/x/crypto v0.23.0
\tgithub.com/nimbusds/jose v1.2.3
)
""",
            "go.sum": """golang.org/x/crypto v0.23.0 h1:abc=
golang.org/x/crypto v0.23.0/go.mod h1:def=
"""},
        expect=(("golang.org/x/crypto", "0.23.0"),), expect_scope="resolved",
        note="the module version is canonicalised without its v prefix, which keeps "
             "the value comparable across ecosystems"),
    _case(
        id="rust_cargo_lock_v1", ecosystem="rust", manifest="Cargo.toml",
        lockfile="Cargo.lock", revision="Cargo.lock v1 (no version field)",
        files={
            "Cargo.toml": '[package]\nname = "payments"\nversion = "0.1.0"\n\n'
                          '[dependencies]\nring = "0.17"\n',
            "Cargo.lock": """[[package]]
name = "ring"
version = "0.17.8"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "payments"
version = "0.1.0"
dependencies = ["ring"]
"""},
        expect=(("ring", "0.17.8"),), expect_scope="resolved"),
    _case(
        id="rust_cargo_lock_v2", ecosystem="rust", manifest="Cargo.toml",
        lockfile="Cargo.lock", revision="Cargo.lock v2 (version = 3 header)",
        files={
            "Cargo.toml": '[package]\nname = "payments"\nversion = "0.1.0"\n\n'
                          '[dependencies]\nring = "0.17"\n',
            "Cargo.lock": """version = 3

[[package]]
name = "ring"
version = "0.17.8"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc"
"""},
        expect=(("ring", "0.17.8"),), expect_scope="resolved"),
    _case(
        id="dotnet_csproj", ecosystem="dotnet", manifest="App.csproj",
        lockfile=None, revision="csproj PackageReference",
        files={"App.csproj": """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageReference Include="BouncyCastle.Cryptography" Version="2.3.1" />
  </ItemGroup>
</Project>
"""},
        expect=(("bouncycastle.cryptography", "2.3.1"),), expect_scope="declared",
        note="this is the case the review named: the parser existed and dispatch "
             "could never reach it"),
    _case(
        id="dotnet_packages_lock", ecosystem="dotnet", manifest="App.csproj",
        lockfile="packages.lock.json", revision="NuGet lock file v1",
        files={
            "App.csproj": """<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup>
</Project>
""",
            "packages.lock.json": """{
  "version": 1,
  "dependencies": {
    "net8.0": {
      "Newtonsoft.Json": {"type": "Direct", "requested": "[13.0.3, )", "resolved": "13.0.3"},
      "System.Memory": {"type": "Transitive", "resolved": "4.5.5"}
    }
  }
}
"""},
        expect=(("newtonsoft.json", "13.0.3"),), expect_scope="resolved"),
    _case(
        id="ruby_gemfile_lock", ecosystem="ruby", manifest="Gemfile",
        lockfile="Gemfile.lock", revision="bundler lock",
        files={
            "Gemfile": 'source "https://rubygems.org"\ngem "openssl"\n',
            "Gemfile.lock": """GEM
  remote: https://rubygems.org/
  specs:
    openssl (3.2.0)
    openssl-signature_algorithm (1.3.0)

PLATFORMS
  ruby

DEPENDENCIES
  openssl
"""},
        expect=(("openssl", "3.2.0"),), expect_scope="resolved"),
    _case(
        id="php_composer_lock", ecosystem="php", manifest="composer.json",
        lockfile="composer.lock", revision="composer lock",
        files={
            "composer.json": '{"require": {"phpseclib/phpseclib": "^3.0"}}',
            "composer.lock": """{
  "packages": [
    {"name": "phpseclib/phpseclib", "version": "3.0.37", "license": ["MIT"]}
  ],
  "packages-dev": []
}
"""},
        expect=(("phpseclib/phpseclib", "3.0.37"),), expect_scope="resolved"),
)


def write_case(case: Case, root: Path) -> Path:
    """Materialise one case under ``root``, refusing a path that escapes it."""
    target = (root / case.id).resolve()
    if root.resolve() not in target.parents and target != root.resolve():
        raise ValueError(f"case {case.id} would write outside the fixture root")
    target.mkdir(parents=True, exist_ok=True)
    for name, content in case.files.items():
        path = (target / name).resolve()
        if target not in path.parents:
            raise ValueError(f"case {case.id} declares a path outside itself: {name}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return target


def _scan(path: Path) -> dict[str, Any]:
    from devsecops import sbom_scan  # noqa: PLC0415 - the module under test

    return sbom_scan.scan_source(str(path), use_lockfiles=True)


def _versions(packages: Iterable[dict[str, Any]]) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for package in packages:
        name = str(package.get("name") or "").lower()
        if not name:
            continue
        found.setdefault(name, set()).add(str(package.get("version")))
    return found


def qualify_case(case: Case, root: Path) -> dict[str, Any]:
    """Run one case and say exactly what happened to it."""
    path = write_case(case, root)
    result = _scan(path)
    packages = result.get("packages") or []
    found = _versions(packages)
    missing = [(name, version) for name, version in case.expect if name not in found]
    wrong = [(name, version, sorted(found.get(name, ()))) for name, version in case.expect
             if name in found and version not in found[name]]
    forbidden = [name for name in case.forbid if name in found]
    from container_scanner.parsers.package_parsers import classify_spec  # noqa: PLC0415

    specs: dict[str, str] = {}
    constraints: dict[str, str] = {}
    for package in packages:
        name = str(package.get("name") or "").lower()
        # A row merged with a lockfile keeps the declaration as ``declared_spec``
        # (the resolved version wins the ``version`` field), so the specifier is
        # still checkable after the merge.
        spec = package.get("raw_spec") or package.get("declared_spec")
        if spec:
            specs[name] = str(spec)
        if package.get("version_constraint"):
            constraints[name] = str(package["version_constraint"])
        elif spec:
            _, kind = classify_spec(spec)
            if kind:
                constraints[name] = kind
    bad_specs = [(name, want, specs.get(name)) for name, want in case.expect_spec
                 if specs.get(name) != want]
    bad_constraints = [(name, want, constraints.get(name))
                       for name, want in case.expect_constraint
                       if constraints.get(name) != want]
    scopes = {str(package.get("scope") or "declared") for package in packages}
    scope_ok = case.expect_scope is None or case.expect_scope in scopes
    manifests = result.get("manifests") or []
    lockfiles = result.get("lockfiles") or []

    if not packages:
        verdict = FIX
        reason = ("the scan produced no package at all from this file: the reader either "
                  "cannot see it or cannot parse it")
    elif missing or wrong or forbidden or bad_specs or bad_constraints:
        verdict = FIX
        parts = []
        if missing:
            parts.append("missing " + ", ".join(f"{name}" for name, _ in missing))
        if wrong:
            parts.append("wrong version " + ", ".join(
                f"{name} read as {', '.join(got)} not {want}" for name, want, got in wrong))
        if forbidden:
            parts.append("unexpected " + ", ".join(forbidden))
        if bad_specs:
            parts.append("specifier lost " + ", ".join(
                f"{name} read as {got!r} not {want!r}" for name, want, got in bad_specs))
        if bad_constraints:
            parts.append("constraint misread " + ", ".join(
                f"{name} as {got!r} not {want!r}" for name, want, got in bad_constraints))
        reason = "; ".join(parts)
    elif case.lockfile and case.lockfile not in lockfiles:
        verdict = PARTIAL
        reason = (f"the components were found but {case.lockfile} was not recorded as the "
                  "source, so provenance is weaker than the content")
    elif not scope_ok:
        verdict = PARTIAL
        reason = (f"components were found but none carried scope {case.expect_scope!r}; the "
                  "declared/resolved distinction did not survive")
    else:
        verdict = PASS
        reason = (f"{len(case.expect)} expected component(s) found"
                  + (f" from {case.lockfile}" if case.lockfile else " from the manifest")
                  + (f" with scope {case.expect_scope}" if case.expect_scope else ""))
    return {
        "id": case.id,
        "ecosystem": case.ecosystem,
        "manifest": case.manifest,
        "lockfile": case.lockfile,
        "revision": case.revision,
        "verdict": verdict,
        "reason": reason,
        "components_found": sorted(found),
        "manifests_seen": manifests,
        "lockfiles_seen": lockfiles,
        "scopes": sorted(scopes),
        "declared_specs": dict(sorted(specs.items())),
        "version_constraints": dict(sorted(constraints.items())),
        "note": case.note,
    }


def qualify(cases: Iterable[Case] = CASES, *, root: Path | None = None) -> dict[str, Any]:
    """Run the whole matrix and summarise it per ecosystem."""
    cases = list(cases)
    with tempfile.TemporaryDirectory(prefix="sbom-qualification-") as workspace:
        base = Path(root) if root else Path(workspace)
        base.mkdir(parents=True, exist_ok=True)
        rows = [qualify_case(case, base) for case in cases]
    by_ecosystem: dict[str, dict[str, Any]] = {}
    for row in rows:
        entry = by_ecosystem.setdefault(row["ecosystem"], {
            "ecosystem": row["ecosystem"], "cases": 0, "pass": 0, "partial": 0, "fix": 0,
            "verdict": PASS, "manifests": set(), "lockfiles": set(), "revisions": []})
        entry["cases"] += 1
        entry["pass" if row["verdict"] == PASS else
              "partial" if row["verdict"] == PARTIAL else "fix"] += 1
        entry["manifests"].add(row["manifest"])
        if row["lockfile"]:
            entry["lockfiles"].add(row["lockfile"])
        entry["revisions"].append(row["revision"])
    ecosystems = []
    for entry in by_ecosystem.values():
        if entry["fix"] or entry["partial"]:
            entry["verdict"] = FIX if entry["fix"] else PARTIAL
        entry["manifests"] = sorted(entry["manifests"])
        entry["lockfiles"] = sorted(entry["lockfiles"])
        ecosystems.append(entry)
    ecosystems.sort(key=lambda row: row["ecosystem"])
    counts = {verdict: sum(1 for row in rows if row["verdict"] == verdict)
              for verdict in (PASS, PARTIAL, FIX)}
    return {
        "schema": SCHEMA,
        "cases": len(rows),
        "counts": counts,
        "ecosystems": ecosystems,
        "rows": rows,
        "qualified": all(row["verdict"] == PASS for row in rows),
        "statement": (
            f"{counts[PASS]} of {len(rows)} parser case(s) pass; {counts[PARTIAL]} are partial "
            f"and {counts[FIX]} need a fix. "
            + ("Every ecosystem the review listed is production-qualified against the "
               "revisions exercised here."
               if counts[PASS] == len(rows) else
               "An ecosystem with any non-PASS case is not production-qualified, whatever "
               "the filename list says.")),
    }
