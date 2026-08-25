from container_scanner.config.settings import load_settings
from container_scanner.core.scan_context import ScanContext
from container_scanner.cve.cve_cache import CveCache
from container_scanner.cve.github_advisory_client import GitHubAdvisoryClient
from container_scanner.cve.resolver import VulnerabilityResolver
from container_scanner.workspace.cleanup_handler import ensure_cleanup
from container_scanner.workspace.workspace_manager import WorkspaceManager


LOCAL = {
    "advisories": [
        {
            "cve": "CVE-2013-1445",
            "package": "pycrypto",
            "affected": "*",
            "severity": "MEDIUM",
            "summary": "fork-unsafe PRNG",
        }
    ]
}


def test_github_advisory_client_parses_and_fails_open():
    def transport(url, params):
        assert "pycrypto" in params["affects"]
        return [
            {
                "cve_id": "CVE-2099-4242",
                "ghsa_id": "GHSA-demo",
                "severity": "high",
                "summary": "github hit",
            }
        ]

    client = GitHubAdvisoryClient(transport=transport)
    rows = client.lookup({"name": "pycrypto", "version": "2.6.1", "manager": "pip"})
    assert rows[0]["cve"] == "CVE-2099-4242"
    assert rows[0]["source"] == "github"

    def boom(url, params):
        raise RuntimeError("network down")

    assert GitHubAdvisoryClient(transport=boom).lookup({"name": "pycrypto"}) == []


def test_resolver_merges_github_when_provided():
    class FakeGithub:
        def lookup(self, package):
            return [
                {
                    "cve": "CVE-2099-4242",
                    "package": "pycrypto",
                    "version": "2.6.1",
                    "severity": "HIGH",
                    "summary": "gh",
                    "source": "github",
                }
            ]

    resolver = VulnerabilityResolver(LOCAL, live=True, osv=_EmptyOsv(), github=FakeGithub())
    cves = {item["cve"] for item in resolver.lookup([{"name": "pycrypto", "version": "2.6.1"}])}
    assert "CVE-2013-1445" in cves
    assert "CVE-2099-4242" in cves


def test_cve_cache_round_trip_and_ttl():
    cache = CveCache(ttl_seconds=60)
    key = cache.key_for([{"name": "pycrypto", "version": "2.6.1"}], live=True)
    assert cache.get(key) is None
    cache.set(key, [{"cve": "CVE-1"}])
    assert cache.get(key) == [{"cve": "CVE-1"}]
    cache._store[key] = (0, [{"cve": "stale"}])
    assert cache.get(key) is None


def test_workspace_cleanup_removes_job_dir():
    workspace = WorkspaceManager()
    path = workspace.create("demo")
    (path / "layer.txt").write_text("x")
    assert path.is_dir()
    with ensure_cleanup(workspace, path):
        assert path.exists()
    assert not path.exists()


def test_main_scans_filesystem(tmp_path):
    (tmp_path / "requirements.txt").write_text("pycrypto==2.6.1\n")
    from container_scanner.main import main

    out = tmp_path / "out.json"
    assert main([str(tmp_path), "-o", str(out)]) == 0
    payload = out.read_text(encoding="utf-8")
    assert "pycrypto" in payload
    assert "scan_context" in payload


def test_scan_context_and_settings(monkeypatch):
    ctx = ScanContext.for_image("alpine:latest", live_cve=True)
    assert ctx.target_kind == "image"
    assert ctx.to_dict()["target"] == "alpine:latest"
    monkeypatch.setenv("CRYPTOSCAN_CVE_LIVE", "1")
    monkeypatch.setenv("NVD_API_KEY", "k")
    settings = load_settings()
    assert settings.live_cve is True
    assert settings.nvd_api_key == "k"


class _EmptyOsv:
    def query_batch(self, packages):
        return []
