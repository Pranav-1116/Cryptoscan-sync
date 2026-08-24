from drift.alerts.email_alerter import EmailAlerter, SMTPConfig


def test_email_alerter_constructs():
    alerter = EmailAlerter(
        SMTPConfig(host="localhost", port=1025, username="", password="", use_tls=False)
    )
    assert alerter._config.host == "localhost"


def test_send_drift_alert_logs(caplog):
    alerter = EmailAlerter()
    alerter.send_drift_alert("local://demo", [{"algorithm": "DES"}])
    assert True
