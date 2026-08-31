"""Container package-manifest parsers tests (parsers.package_parsers)."""

from __future__ import annotations

from pathlib import Path

from container_scanner.parsers.package_parsers import (
    parse_cargo,
    parse_composer,
    parse_csproj,
    parse_gemfile,
    parse_gomod,
    parse_package_json,
    parse_pom,
    parse_requirements,
)


def _write(tmp_path: Path, name: str, content: str) -> Path:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


class TestRequirements:
    def test_pip_pins_and_ranges(self, tmp_path):
        path = _write(tmp_path, "requirements.txt", """
# comment
requests==2.31.0
cryptography>=41.0
flask
-r other.txt
""")
        packages = parse_requirements(path)
        names = [p["name"] for p in packages]
        assert names == ["requests", "cryptography", "flask"]
        assert packages[0]["version"] == "2.31.0"
        assert packages[0]["manager"] == "pip"
        assert packages[2]["version"] is None

    def test_blank_and_option_lines_skipped(self, tmp_path):
        path = _write(tmp_path, "requirements.txt", "\n  \n--no-binary :all:\n")
        assert parse_requirements(path) == []


class TestPackageJson:
    def test_sections_and_semver(self, tmp_path):
        path = _write(tmp_path, "package.json", """
        {
          "dependencies": {"axios": "^1.6.0", "lodash": "~4.17.21"},
          "devDependencies": {"jest": "29.7.0"},
          "optionalDependencies": {"fsevents": "*"}
        }
        """)
        packages = parse_package_json(path)
        by_name = {p["name"]: p for p in packages}
        assert set(by_name) == {"axios", "lodash", "jest", "fsevents"}
        assert by_name["axios"]["version"] == "1.6.0"  # ^ stripped
        assert by_name["lodash"]["version"] == "4.17.21"  # ~ stripped
        assert all(p["manager"] == "npm" for p in packages)

    def test_invalid_json_returns_empty(self, tmp_path):
        path = _write(tmp_path, "package.json", "{not json")
        assert parse_package_json(path) == []


class TestPom:
    def test_maven_dependencies(self, tmp_path):
        path = _write(tmp_path, "pom.xml", """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <dependencies>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcprov-jdk18on</artifactId>
      <version>1.77</version>
    </dependency>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>no-version-lib</artifactId>
    </dependency>
  </dependencies>
</project>
""")
        packages = parse_pom(path)
        assert packages[0]["name"] == "bcprov-jdk18on"
        assert packages[0]["group"] == "org.bouncycastle"
        assert packages[0]["version"] == "1.77"
        assert packages[0]["manager"] == "maven"
        assert packages[1]["version"] is None

    def test_broken_xml_returns_empty(self, tmp_path):
        path = _write(tmp_path, "pom.xml", "<project><dependencies>")
        assert parse_pom(path) == []


class TestCsproj:
    def test_package_references(self, tmp_path):
        path = _write(tmp_path, "app.csproj", """<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="BouncyCastle.Cryptography" Version="2.4.0" />
    <PackageReference Update="System.Security.Cryptography" />
  </ItemGroup>
</Project>
""")
        packages = parse_csproj(path)
        assert packages[0]["name"] == "bouncycastle.cryptography"
        assert packages[0]["version"] == "2.4.0"
        assert packages[0]["manager"] == "nuget"
        assert packages[1]["name"] == "system.security.cryptography"
        assert packages[1]["version"] is None


class TestGomod:
    def test_direct_dependencies(self, tmp_path):
        path = _write(tmp_path, "go.mod", """
module example.com/app

go 1.21

require (
    github.com/golang-jwt/jwt/v5 v5.2.0
    golang.org/x/crypto v0.18.0
)
""")
        packages = parse_gomod(path)
        names = [p["name"] for p in packages]
        assert "github.com/golang-jwt/jwt/v5" in names
        assert "golang.org/x/crypto" in names
        assert packages[0]["manager"] == "go"
        assert packages[0]["version"] == "5.2.0"  # leading v stripped


class TestComposer:
    def test_require_sections(self, tmp_path):
        path = _write(tmp_path, "composer.json", """
        {"require": {"php": "^8.2", "paragonie/sodium_compat": "^1.20"},
         "require-dev": {"phpunit/phpunit": "^10.5"}}
        """)
        packages = parse_composer(path)
        names = [p["name"] for p in packages]
        assert "php" not in names  # PHP runtime excluded
        assert "paragonie/sodium_compat" in names
        assert packages[0]["section"] == "require"
        assert packages[1]["section"] == "require-dev"


class TestGemfile:
    def test_gem_entries(self, tmp_path):
        path = _write(tmp_path, "Gemfile", """
source 'https://rubygems.org'
gem 'openssl', '~> 3.0'
gem 'jwt'
""")
        packages = parse_gemfile(path)
        names = [p["name"] for p in packages]
        assert names == ["openssl", "jwt"]
        assert packages[0]["version"] == "~> 3.0"
        assert packages[0]["manager"] == "bundler"


class TestCargo:
    def test_cargo_toml(self, tmp_path):
        path = _write(tmp_path, "Cargo.toml", """
[package]
name = "app"
version = "0.1.0"

[dependencies]
ring = "0.17.5"
rustls = { version = "0.22.0", features = ["tls12"] }

[dev-dependencies]
criterion = "0.5.1"
""")
        packages = parse_cargo(path)
        by_name = {p["name"]: p for p in packages}
        assert by_name["ring"]["version"] == "0.17.5"
        assert by_name["rustls"]["version"] == "0.22.0"  # inline table
        assert by_name["criterion"]["version"] == "0.5.1"
        assert all(p["manager"] == "cargo" for p in packages)
