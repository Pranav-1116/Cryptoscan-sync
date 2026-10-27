# Runtime evidence — what actually ran

Static discovery answers *what could run*. A bank auditor also asks *what did run*, and the
answer is already sitting in logs the bank keeps for other reasons. `scanner/parsers/runtime_log_parser.py`
reads those logs and emits the same `RawFinding` records as the source parsers, tagged
`source.type = "RUNTIME_LOG"`, aggregated per (source, algorithm, raw token) with an
`occurrences` count.

| Log | What is read | Example line → finding |
|---|---|---|
| ICSF SMF type-82 reports / `CSF` messages | `SERVICE=CSNBxxx`, `ALGORITHM=`, `KEY TYPE=`, key labels | `SERVICE=CSNBSYE ALGORITHM=AES` → AES · `CSNBENC` → 3DES (DATA key) · `CSNDDSG` → RSA signature · `CSNBPVR` → 3DES PIN verify |
| RACF `RACDCERT LIST` | `Key Type`, `Key Size`, `Private Key Type`, `Signing Algorithm` | `Key Type: RSA / Key Size: 1024 / Signing Algorithm: sha1RSA` → RSA-1024 keypair + SHA-1 signature |
| Thales payShield host audit | `Command: A0` … with HSM/Response context | `A0 … LMK ID=00` → 3DES key generation; `… key block LMK ID=01` → AES; `EI` → RSA |
| JSSE `-Djavax.net.debug=ssl` | `Negotiated protocol version`, `Negotiated cipher suite`, `"cipher suite" :` | `TLS_RSA_WITH_3DES_EDE_CBC_SHA` → TLS + 3DES + SHA-1 + RSA |
| `openssl s_client` / `x509 -text` | `New, TLSv1.3, Cipher is …`, `Protocol :`, `Cipher :`, `Server Temp Key`, `Peer signature type`, `Signature Algorithm`, `Public Key Algorithm` | `Server Temp Key: X25519` → X25519; `sha256WithRSAEncryption` → RSA + SHA-256 |
| nginx / Apache / HAProxy access logs with `$ssl_protocol $ssl_cipher` | protocol token followed by an OpenSSL or IANA suite name | `TLSv1 DES-CBC3-SHA` → TLS + 3DES + SHA-1 |
| OpenSSH `sshd -d` / `ssh -vv` / auth log | `kex: algorithm`, `host key algorithm`, `cipher:`, `Accepted publickey … ssh2: RSA` | `curve25519-sha256` → X25519; `aes256-gcm@openssh.com` → AES-256 |
| z/OS AT-TLS `EZD12xxI` | `CIPHER 0A` / `CIPHER C030` hex codes, `TLSV1.2` | `CIPHER 0A` → TLS_RSA_WITH_3DES_EDE_CBC_SHA → 3DES + SHA-1 + RSA |

Cipher-suite strings are decomposed by the same `_expand_cipher_suites` step as source
findings, so a runtime `ECDHE-RSA-AES128-GCM-SHA256` yields AES, SHA-256, ECDH and RSA
children that keep `source.type = RUNTIME_LOG`.

## Using it

```
# 1. logs are opt-in in discovery (log trees are big and repetitive)
CRYPTOSCAN_RUNTIME_LOGS=1 python -m scanner ... /path/with/logs

# 2. or ingest a log drop and reconcile with the source inventory
python scripts/ingest_runtime_logs.py /drop/2026-09-logs --source /repos/payments-switch -o runtime.json
```

The reconciliation prints three sets: algorithms observed at runtime **and** in source,
observed at runtime **but in no scanned repo** (a vendor binary, an appliance, or a repo the
bank has not handed over — the discovery gap made visible), and in source but never observed
(dead code, or a system not yet in the log capture window).

## Precision rules

* Every pattern needs its *product* context on the line (ICSF verb **and** `SERVICE=`/`RC=`; a payShield
  command **and** `Response`/`HSM`/`LMK`; `EZD12xxI` prefix). A plain application log with
  `command: ls` or `key=value` produces nothing (`tests/fixtures/runtime_logs/app.log`).
* Findings are aggregated, never one per line: a 10 GB access log yields one finding per
  distinct protocol/suite with an occurrence count.
* ICSF `CSNBENC/CSNBDEC` (DATA keys) are reported 3DES: no current CKDS holds single-length DATA keys.
  `CSNBSYE/CSNBSYD` take the algorithm from the `ALGORITHM=` field of the same record.
* payShield commands are 3DES unless the record shows a key-block LMK (`key block`, `LMK ID≥1`,
  scheme `S`); `E*`/`G*`/`I*` families are RSA.
* Files above 200 MB are skipped by the parser (stream the log through `split` first).

## What this does not do

* It does not sniff the network. A packet-capture / JA3 / passive TLS sensor is a different
  product; the log route was chosen because banks already retain these logs for audit and
  will hand them over, while a tap on a payments segment needs a change board.
* It cannot see algorithms a log does not print (e.g. an application that logs only
  "encrypted OK"). Enable the vendor's crypto audit level (ICSF `SMF 82`, payShield audit
  trail, `javax.net.debug=ssl:handshake`) for the capture window.

## First-call C-shim metadata — 2026-10-22

The separate `services/runtime/cshim/cryptoscan_trace.c` interceptor resolves
OpenSSL metadata symbols **before logging the first intercepted EVP operation**.
A fresh process making only one cipher/digest initialization can therefore retain
its available algorithm name/type metadata, instead of needing a later call to
initialize lookup functions. The regression uses a one-call fresh process; it is
not an endurance, full-library/version or whole-estate observation claim.

Do not confuse opt-in instrumentation with approved bank runtime collection.
Mapped libraries, runtime logs and intercepted operations are distinct evidence
classes; no key bytes should be collected. The controlled production collector
remains local-source/v1. See [current status](../CURRENT-IMPLEMENTATION-STATUS.md).
