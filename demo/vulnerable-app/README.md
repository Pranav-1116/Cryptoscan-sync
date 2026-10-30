# Demo Java application (intentionally vulnerable)

CryptoScan's bundled sample. It is **not** a real payment service — it exists so
you can run a complete scan without cloning an external repository.

Detected patterns:

| File | Finding | Policy |
|---|---|---|
| `PaymentService.java` | `DES`, `AES/ECB`, `AES/GCM` | BASELINE-001, BASELINE-003 |
| `LegacyCipher.java` | `DESede`, `RC4` | BASELINE-001 |
| `HashUtil.java` | `MD5`, `SHA-1`, `SHA-256` | BASELINE-001 |
| `RsaKeys.java` | `RSA` 1024-bit keygen | BASELINE-002 |
| `SecretStore.java` | hardcoded `SecretKeySpec` | BASELINE-004 |

Scan it with:

```
local://demo/vulnerable-app
```
