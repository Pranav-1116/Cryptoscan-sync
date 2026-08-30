"""Payment cryptography visibility: HSM key inventory, audit-log telemetry, policy.

Banks move 10M+ transactions a day on keys this module makes visible: LMK/ZMK/
ZPK hierarchies, PIN verification keys, CVKs, MAC keys, BDKs and EMV issuer
keys — the cryptography the estate scanners cannot see.

Three layers:

- ``keyblocks`` — parse TR-31 / ANSI X9.143 key blocks (structure + binding
  version + optional blocks) so key metadata lands in the inventory instead
  of a spreadsheet;
- ``auditlog`` — ingest HSM audit trails (native JSONL, mapped CSV, syslog
  key=value lines) into one event taxonomy, whatever the vendor;
- ``policy`` — PAY-xxx rules drawn from PCI DSS, ANS X9.24/TR-39 and the
  NQO migration guidance (3DES deprecation, rotation windows, dual control,
  clear-key exports, firmware changes, auth-failure storms).

Honesty rules: unknown TR-31 codes stay ``UNKNOWN(code)`` instead of being
guessed, and nothing is invented — ingest adapters consume documented
formats, not vendor formats we have never seen.
"""

from payment_crypto.auditlog import HsmAuditParser  # noqa: F401
from payment_crypto.keyblocks import parse_tr31_header  # noqa: F401
from payment_crypto.policy import PaymentPolicyEngine  # noqa: F401
