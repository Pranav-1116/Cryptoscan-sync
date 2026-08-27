"""Scan-to-scan drift: regressions, expiries, downgrades, improvements."""

from __future__ import annotations

from network_scanner.reports.scan_drift import diff_scans


def _finding(endpoint, *, status="OK", version="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384", issues=None, alpn="h2"):
    return {
        "endpoint": endpoint,
        "status": status,
        "policy_issues": list(issues or []),
        "crypto": {"tls_version": version, "cipher_suite": cipher, "alpn": alpn},
    }


def _scan(findings, certs=None, scan_id="s"):
    return {"scan_id": scan_id, "findings": findings, "certificates": certs or []}


def _cert(fp, days, subject="cn.example"):
    return {"fingerprint_sha256": fp, "days_until_expiry": days, "subject": subject}


def _types(report):
    return [change["type"] for change in report["changes"]]


# --------------------------------------------------------------------------- #
# no drift / empty inputs
# --------------------------------------------------------------------------- #

def test_identical_scans_are_unchanged():
    scan = _scan([_finding("a:443")], [_cert("fp1", 90)])
    report = diff_scans(scan, _scan([_finding("a:443")], [_cert("fp1", 89)]))
    # one day of natural expiry burn-down is not drift
    assert report["verdict"] == "UNCHANGED"
    assert report["change_count"] == 0
    assert report["headline"] is None


def test_empty_inputs_are_safe():
    report = diff_scans(None, None)
    assert report["verdict"] == "UNCHANGED"
    assert report["changes"] == []


# --------------------------------------------------------------------------- #
# endpoints
# --------------------------------------------------------------------------- #

def test_endpoint_added_clean_is_info():
    report = diff_scans(_scan([]), _scan([_finding("new:443")]))
    assert report["verdict"] == "UNCHANGED"  # clean addition is not a regression
    change = report["changes"][0]
    assert change["type"] == "ENDPOINT_ADDED" and change["severity"] == "INFO"


def test_endpoint_added_with_weak_issues_carries_severity():
    report = diff_scans(
        _scan([]),
        _scan([_finding("new:443", issues=["CBC_ACCEPTED"])]),
    )
    change = report["changes"][0]
    assert change["type"] == "ENDPOINT_ADDED" and change["severity"] == "HIGH"
    assert report["verdict"] == "REGRESSED"


def test_endpoint_removed_is_medium():
    report = diff_scans(_scan([_finding("gone:443")]), _scan([]))
    change = report["changes"][0]
    assert change["type"] == "ENDPOINT_REMOVED" and change["severity"] == "MEDIUM"


def test_status_degraded_and_recovered():
    degraded = diff_scans(
        _scan([_finding("a:443")]), _scan([_finding("a:443", status="TIMEOUT")])
    )
    assert degraded["changes"][0]["type"] == "STATUS_DEGRADED"
    assert degraded["changes"][0]["severity"] == "HIGH"
    recovered = diff_scans(
        _scan([_finding("a:443", status="TIMEOUT")]), _scan([_finding("a:443")])
    )
    assert recovered["changes"][0]["type"] == "STATUS_RECOVERED"
    assert recovered["verdict"] == "IMPROVED"


# --------------------------------------------------------------------------- #
# TLS posture
# --------------------------------------------------------------------------- #

def test_tls_downgrade_is_high():
    report = diff_scans(
        _scan([_finding("a:443", version="TLSv1.3")]),
        _scan([_finding("a:443", version="TLSv1.2")]),
    )
    change = report["changes"][0]
    assert change["type"] == "TLS_VERSION_DOWNGRADED" and change["severity"] == "HIGH"
    assert change["was"] == "TLSv1.3" and change["now"] == "TLSv1.2"
    assert report["verdict"] == "REGRESSED"


def test_tls_upgrade_is_info_improvement():
    report = diff_scans(
        _scan([_finding("a:443", version="TLSv1.2")]),
        _scan([_finding("a:443", version="TLSv1.3")]),
    )
    assert report["changes"][0]["type"] == "TLS_VERSION_UPGRADED"
    assert report["verdict"] == "IMPROVED"


def test_cipher_change_same_version_is_info():
    report = diff_scans(
        _scan([_finding("a:443", cipher="TLS_AES_256_GCM_SHA384")]),
        _scan([_finding("a:443", cipher="TLS_CHACHA20_POLY1305_SHA256")]),
    )
    assert report["changes"][0]["type"] == "CIPHER_SUITE_CHANGED"


# --------------------------------------------------------------------------- #
# policy issues
# --------------------------------------------------------------------------- #

def test_issue_appeared_severity_tiers():
    tiers = [
        (["CERT_REVOKED"], "CRITICAL"),
        (["WEAK_TLS_VERSION_ACCEPTED"], "HIGH"),
        (["SOME_OTHER_ISSUE"], "MEDIUM"),
    ]
    for issues, severity in tiers:
        report = diff_scans(
            _scan([_finding("a:443")]),
            _scan([_finding("a:443", issues=issues)]),
        )
        change = report["changes"][0]
        assert change["type"] == "POLICY_ISSUE_APPEARED"
        assert change["severity"] == severity, (issues, change)


def test_issues_resolved_is_improvement():
    report = diff_scans(
        _scan([_finding("a:443", issues=["CBC_ACCEPTED"])]),
        _scan([_finding("a:443")]),
    )
    assert report["changes"][0]["type"] == "ISSUES_RESOLVED"
    assert report["verdict"] == "IMPROVED"


def test_mixed_verdict():
    report = diff_scans(
        _scan([_finding("a:443", issues=["CBC_ACCEPTED"]), _finding("b:443")]),
        _scan([_finding("a:443"), _finding("b:443", version="TLSv1.2")]),  # resolved + downgrade
    )
    assert report["verdict"] == "MIXED"
    assert report["severity_counts"]["HIGH"] == 1
    assert report["summary"]["issues_resolved"] == 1


# --------------------------------------------------------------------------- #
# certificates
# --------------------------------------------------------------------------- #

def test_cert_expired_since_last_scan_is_critical():
    report = diff_scans(
        _scan([], [_cert("fp1", 2)]),
        _scan([], [_cert("fp1", -1)]),
    )
    change = report["changes"][0]
    assert change["type"] == "CERT_EXPIRED_SINCE_LAST_SCAN"
    assert change["severity"] == "CRITICAL"
    assert report["summary"]["certs_expired"] == 1
    assert report["verdict"] == "REGRESSED"


def test_cert_entering_warning_window_is_high():
    report = diff_scans(
        _scan([], [_cert("fp1", 12)]),
        _scan([], [_cert("fp1", 5)]),
    )
    assert report["changes"][0]["type"] == "CERT_ENTERING_WARNING_WINDOW"
    assert report["changes"][0]["severity"] == "HIGH"


def test_cert_renewed_matched_by_subject():
    report = diff_scans(
        _scan([], [_cert("fpold", 5, subject="CN=app")]),
        _scan([], [_cert("fpnew", 90, subject="CN=app")]),
    )
    assert _types(report) == ["CERT_RENEWED"]
    assert report["verdict"] == "IMPROVED"


def test_cert_no_longer_seen_and_added():
    report = diff_scans(
        _scan([], [_cert("fpgone", 30, subject="CN=old")]),
        _scan([], [_cert("fpfresh", 90, subject="CN=new")]),
    )
    assert set(_types(report)) == {"CERT_NO_LONGER_SEEN", "CERT_ADDED"}


# --------------------------------------------------------------------------- #
# ordering + headline
# --------------------------------------------------------------------------- #

def test_changes_sorted_most_severe_first():
    report = diff_scans(
        _scan(
            [_finding("a:443"), _finding("b:443", issues=["CBC_ACCEPTED"])],
            [_cert("fp1", 2)],
        ),
        _scan(
            [_finding("a:443", issues=["CERT_REVOKED"]), _finding("b:443")],
            [_cert("fp1", -1)],
        ),
    )
    severities = [change["severity"] for change in report["changes"]]
    assert severities == sorted(severities, key=lambda sev: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}[sev])
    assert report["headline"] == report["changes"][0]["detail"]


# --------------------------------------------------------------------------- #
# end-to-end over scan_hosts output
# --------------------------------------------------------------------------- #

def test_diff_over_scanner_output(monkeypatch):
    import network_scanner.core.scanner as scanner_mod
    from network_scanner.core.scanner import NetworkTlsScanner

    state = {"weak": False}

    def fake_probe(endpoint, **_kwargs):
        if endpoint.startswith("good"):
            return {
                "endpoint": endpoint,
                "status": "OK",
                "policy_issues": [],
                "crypto": {"tls_version": "TLSv1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384"},
                "certificates": [],
            }
        weak = state["weak"]  # posture is fixed per scan, not per call
        return {
            "endpoint": endpoint,
            "status": "OK",
            "policy_issues": ["CBC_ACCEPTED"] if weak else [],
            "crypto": {
                "tls_version": "TLSv1.2" if weak else "TLSv1.3",
                "cipher_suite": "AES128-SHA" if weak else "TLS_AES_256_GCM_SHA384",
            },
            "certificates": [],
        }

    monkeypatch.setattr(scanner_mod, "probe_endpoint", fake_probe)
    scanner = NetworkTlsScanner(live=True)
    previous = scanner.scan_hosts(["good:443", "flaky:443"], scan_id="prev")
    state["weak"] = True  # the host downgrades before the next scan
    current = scanner.scan_hosts(["good:443", "flaky:443"], scan_id="cur")
    report = diff_scans(previous, current)
    assert report["previous_scan_id"] == "prev" and report["current_scan_id"] == "cur"
    types = _types(report)
    assert "TLS_VERSION_DOWNGRADED" in types
    assert "POLICY_ISSUE_APPEARED" in types
    assert report["verdict"] == "REGRESSED"
