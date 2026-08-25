# Certificate inventory

Network scans store certificates by SHA-256 fingerprint. Each cert tracks subject, SAN, expiry status (`VALID`, `EXPIRING_SOON`, `EXPIRING_CRITICAL`, `EXPIRED`), OCSP/CRL revocation, and the endpoints that presented it. Open **TLS / Certificates** on the dashboard to see days remaining and usage.
