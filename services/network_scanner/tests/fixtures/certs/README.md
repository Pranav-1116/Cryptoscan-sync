# X.509 scanner fixtures

Offline PEMs used by the network TLS scanner. They are generated with
OpenSSL and carry the extensions CryptoScan extracts without the
`cryptography` extra: SAN, key usage, EKU, basic constraints, OCSP AIA,
and a CRL distribution point.

| File | Role |
| --- | --- |
| `valid_root.pem` | Self-signed RSA-2048 CA |
| `valid_intermediate.pem` | Intermediate CA signed by the root |
| `valid_leaf.pem` | `api.payment.example.com` leaf (SAN + OCSP + CRL) |
| `expired_cert.pem` | Expired leaf (notAfter in the past) |
| `self_signed.pem` | Self-signed server cert |

Private keys are not checked in. These fixtures are test-only and are not included in runtime source trees.
