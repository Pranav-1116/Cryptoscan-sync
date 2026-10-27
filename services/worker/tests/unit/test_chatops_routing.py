"""ChatOps alert routing (deep/31 ChatOps remainder, round 37)."""

from __future__ import annotations

from worker.monitor.alerting import AlertRouter, format_chatops


class _Settings:
    def __init__(self, **kwargs):
        self.ALERT_CEF_HOST = ""
        self.ALERT_CEF_PORT = 514
        self.ALERT_WEBHOOK_URL = ""
        self.ALERT_WEBHOOK_SECRET = ""
        self.ALERT_CHATOPS_URL = ""
        self.ALERT_CHATOPS_SECRET = ""
        self.ALERT_CHATOPS_CHANNEL = ""
        self.SMTP_HOST = ""
        for key, value in kwargs.items():
            setattr(self, key, value)


class _Recorder:
    def __init__(self, fail=False):
        self.calls = []
        self.fail = fail

    def __call__(self, url, body, headers):
        if self.fail:
            raise ConnectionError("chatops down")
        self.calls.append((url, body, headers))


def test_format_chatops_body_is_slack_and_mattermost_compatible():
    body = format_chatops(target="bank-gateway", issue="WEAK_TLS_VERSION:h:443",
                          payload={"severity": "CRITICAL"})
    assert body["text"] == "[CryptoScan ALERT] bank-gateway: WEAK_TLS_VERSION:h:443"
    attachment = body["attachments"][0]
    assert attachment["color"] == "#cc0000"  # CRITICAL red
    fields = {f["title"]: f["value"] for f in attachment["fields"]}
    assert fields["Severity"] == "CRITICAL"
    assert fields["Target"] == "bank-gateway"
    # no channel key unless explicitly configured
    assert "channel" not in body


def test_format_chatops_severity_colors_and_channel():
    assert format_chatops(target="t", issue="i",
                          payload={"severity": "HIGH"})["attachments"][0]["color"] == "#e33e1c"
    assert format_chatops(target="t", issue="i",
                          payload={"severity": "weird"})["attachments"][0]["color"] == "#cccccc"
    body = format_chatops(target="t", issue="i", channel="#soc-crypto")
    assert body["channel"] == "#soc-crypto"


def test_host_values_are_data_not_markup():
    # a hostile target string cannot inject ChatOps markdown structure
    body = format_chatops(target="host *bold* <b>x</b> `code`",
                          issue="issue with & <chars>")
    assert "host *bold* <b>x</b> `code`" in body["text"]
    # fields carry the raw values; nothing is interpreted as markup keys
    fields = body["attachments"][0]["fields"]
    assert fields[0]["value"] == "host *bold* <b>x</b> `code`"


def test_dispatch_sends_to_configured_chatops_with_signature():
    recorder = _Recorder()
    router = AlertRouter(
        settings=_Settings(ALERT_CHATOPS_URL="https://chat.example/hooks/xyz",
                           ALERT_CHATOPS_SECRET="chatops-secret-0123456789"),
        post=recorder)
    outcome = router.dispatch("bank-gateway", "WEAK_TLS_VERSION:h:443",
                              {"severity": "HIGH"})
    assert outcome == {"chatops": "sent"}
    url, body, headers = recorder.calls[0]
    assert url == "https://chat.example/hooks/xyz"
    assert body["text"].startswith("[CryptoScan ALERT] bank-gateway")
    assert "generated_at" in body
    assert headers["X-CryptoScan-Signature"].startswith("sha256=")


def test_dispatch_skips_chatops_honestly_when_unconfigured():
    recorder = _Recorder()
    router = AlertRouter(settings=_Settings(), post=recorder)
    assert router.dispatch("t", "i") == {}
    assert recorder.calls == []


def test_chatops_failure_never_kills_other_sinks():
    calls = []

    def _webhook(url, body, headers):
        calls.append(("webhook", url))

    def _chatops(url, body, headers):
        calls.append(("chatops", url))
        raise ConnectionError("chatops down")

    def _post(url, body, headers):
        if "chat.example" in url:
            _chatops(url, body, headers)
        else:
            _webhook(url, body, headers)

    router = AlertRouter(
        settings=_Settings(ALERT_WEBHOOK_URL="https://hooks.example/wh",
                           ALERT_WEBHOOK_SECRET="whsecret-whsecret-whsecret",
                           ALERT_CHATOPS_URL="https://chat.example/hooks/xyz"),
        post=_post)
    outcome = router.dispatch("t", "i")
    assert outcome["webhook"] == "sent"
    assert outcome["chatops"].startswith("failed:")
    assert ("webhook", "https://hooks.example/wh") in calls
    assert ("chatops", "https://chat.example/hooks/xyz") in calls


def test_no_secret_still_sends_unsigned():
    recorder = _Recorder()
    router = AlertRouter(
        settings=_Settings(ALERT_CHATOPS_URL="https://chat.example/hooks/xyz"),
        post=recorder)
    outcome = router.dispatch("t", "i")
    assert outcome == {"chatops": "sent"}
    _, _, headers = recorder.calls[0]
    assert headers == {}


# ── severity -> channel routing (round 38) ───────────────────────────


def test_route_chatops_channel_first_match_wins():
    from worker.monitor.alerting import route_chatops_channel

    routes = "CRITICAL=#soc-critical,HIGH=#soc-high,ANY=#soc-crypto"
    assert route_chatops_channel(severity="CRITICAL", routes=routes) == "#soc-critical"
    assert route_chatops_channel(severity="HIGH", routes=routes) == "#soc-high"
    assert route_chatops_channel(severity="LOW", routes=routes) == "#soc-crypto"
    assert route_chatops_channel(severity="critical", routes=routes) == "#soc-critical"
    # no rules -> default channel; no default -> no channel key
    assert route_chatops_channel(severity="HIGH", routes="",
                                 default_channel="#ops") == "#ops"
    assert route_chatops_channel(severity="HIGH", routes="") == ""


def test_route_chatops_channel_tolerates_malformed_rules():
    from worker.monitor.alerting import route_chatops_channel

    assert route_chatops_channel(severity="HIGH", routes=",,HIGH=#x,=") == "#x"
    assert route_chatops_channel(severity="HIGH", routes="no-separator") == ""


def test_dispatch_routes_by_severity():
    recorder = _Recorder()
    router = AlertRouter(
        settings=_Settings(ALERT_CHATOPS_URL="https://chat.example/hooks/x",
                           ALERT_CHATOPS_SECRET="chatops-secret-0123456789",
                           ALERT_CHATOPS_ROUTES="CRITICAL=#soc-critical"),
        post=recorder)
    router.dispatch("bank-gateway", "KEY_ROTATION_OVERDUE",
                    {"severity": "CRITICAL"})
    _, body, _ = recorder.calls[0]
    assert body["channel"] == "#soc-critical"
    router.dispatch("bank-gateway", "WEAK_TLS_VERSION",
                    {"severity": "MEDIUM"})
    _, body, _ = recorder.calls[1]
    assert "channel" not in body  # no matching rule, no default
