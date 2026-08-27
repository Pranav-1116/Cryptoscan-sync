"""Drift alerting: notifications when drift between scans is detected.

Modules:
- alert_dispatcher: Alert dispatcher - routes drift alerts to correct channels
- daily_digest: Daily drift digest — MEDIUM/INFO plus still-open HIGH/CRITICAL
- email_alerter: Production email alerter for drift notifications
"""
