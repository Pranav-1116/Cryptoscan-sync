from container_scanner.cve.resolver import VulnerabilityResolver


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


class FakeOsv:
    def query_batch(self, packages):
        return [
            {
                "cve": "CVE-2099-0001",
                "package": "pycrypto",
                "version": "2.6.1",
                "severity": "HIGH",
                "summary": "live osv hit",
                "source": "osv",
            }
        ]


def test_resolver_merges_local_and_live():
    resolver = VulnerabilityResolver(LOCAL, live=True, osv=FakeOsv())
    rows = resolver.lookup([{"name": "pycrypto", "version": "2.6.1", "manager": "pip"}])
    cves = {item["cve"] for item in rows}
    assert "CVE-2013-1445" in cves
    assert "CVE-2099-0001" in cves


def test_resolver_offline_skips_live():
    resolver = VulnerabilityResolver(LOCAL, live=False, osv=FakeOsv())
    rows = resolver.lookup([{"name": "pycrypto", "version": "2.6.1", "manager": "pip"}])
    assert {item["cve"] for item in rows} == {"CVE-2013-1445"}


def test_resolver_dedupes_same_cve():
    class DupOsv:
        def query_batch(self, packages):
            return [
                {
                    "cve": "CVE-2013-1445",
                    "package": "pycrypto",
                    "version": "2.6.1",
                    "severity": "MEDIUM",
                    "summary": "dup",
                    "source": "osv",
                }
            ]

    resolver = VulnerabilityResolver(LOCAL, live=True, osv=DupOsv())
    rows = resolver.lookup([{"name": "pycrypto", "version": "2.6.1"}])
    assert len(rows) == 1
