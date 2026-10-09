"""GitClient repository-URL validation (audit 10 — clone URL is unvalidated input).

GitPython never uses a shell, so classic command injection is out; the real
vectors are git's own transport machinery: ``ext::<command>`` executes an
arbitrary helper command (CVE-2022-24439), any ``<helper>::<address>``
invokes a remote helper by name, and a leading ``-`` can be parsed by git as
an option. The allowlist keeps https/http/git/ssh/file URLs, scp-style
targets and local paths working — the scanner clones local checkouts with
the same client.
"""

from __future__ import annotations

import pytest

from scanner.git.git_client import GitClient, validate_repo_url


class TestValidateRepoUrl:
    @pytest.mark.parametrize("url", [
        "https://github.com/acme/payments.git",
        "http://git.internal/acme/repo.git",
        "git@github.com:acme/payments.git",
        "ssh://git@host:29418/acme/repo.git",
        "git://host/acme/repo.git",
        "file:///srv/checkouts/payments",
        "/srv/checkouts/payments",           # local path (same client)
        "src/relative/checkout",
    ])
    def test_accepts_the_transports_the_scanner_uses(self, url):
        assert validate_repo_url(url) == url

    @pytest.mark.parametrize("url", [
        "ext::sh -c id",                      # CVE-2022-24439 remote-helper RCE
        "ext::ssh -i /tmp/id_rsa host",
        "myhelper::address",                  # any helper-by-name transport
        "fd::17",
        "-uconfig",                           # leading dash: git option injection
        "--upload-pack=touch /tmp/pwn",
    ])
    def test_rejects_git_transport_abuse(self, url):
        with pytest.raises(ValueError):
            validate_repo_url(url)

    @pytest.mark.parametrize("url", [
        "ftp://host/repo.git",
        "gopher://host/x",
        "weird+scheme://host/repo.git",
    ])
    def test_rejects_disallowed_schemes(self, url):
        with pytest.raises(ValueError):
            validate_repo_url(url)

    def test_empty_is_rejected(self):
        with pytest.raises(ValueError):
            validate_repo_url("   ")

    def test_helper_syntax_with_slash_in_name_is_caught(self):
        # ``some/thing::addr`` — the helper slot contains a path separator,
        # which no real scheme has; the guard keys on '::' with a bare head.
        with pytest.raises(ValueError):
            validate_repo_url("a/b::c")

    def test_clone_refuses_before_git_is_touched(self, tmp_path):
        """The guard is clone()'s first statement — a hostile URL never
        reaches git (the ValueError fires before ``import git`` runs)."""
        client = GitClient()
        with pytest.raises(ValueError):
            client.clone("ext::sh -c id", tmp_path / "target")
