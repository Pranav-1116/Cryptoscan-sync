# External validation — real third-party code

The corpus in `REPORT.md` is hand-labelled by us. To check the scanner against code nobody here
wrote, we point it at the Python packages installed in the project's own virtualenv and review
every finding by hand (`python scripts/scan_third_party.py <pkg> v`).

Date: 2026-09-24 · scanner at the commit that adds this file.

## Packages with no cryptography (precision check)

| Package | Files scanned | Findings | Verdict |
|---|---|---|---|
| click | 17 | 0 | correct (only `random.randrange` for a temp-file suffix, not key material) |
| structlog | 21 | 0 | correct |
| pyyaml | 17 | 0 | correct |
| pytest + _pytest + pluggy + iniconfig | 92 | 0 | correct |
| packaging | 22 | 0 | correct |
| pygments | 343 | 0 | correct |
| pydantic | 105 | 0 | correct (`SecretStr` types are not crypto) |
| gitpython (git) | 37 | 0 | correct |
| smmap | 10 | 0 | correct |
| pkg_resources | 51 | 0 | correct |

**715 files, 0 false positives.**

## Packages with cryptography (recall check, every `hashlib`/`hmac`/`ssl` call site grepped and compared)

| Package | Files | Findings | Missed before this round | Status |
|---|---|---|---|---|
| gitdb | 25 | 1 (`hashlib.sha1`) | — | complete |
| setuptools | 179 | 5 | `getattr(hashlib, "md5", None)` table in `_distutils/command/upload.py`; dynamic `hashlib.new(hash_name)` | fixed: 3 digests + UNKNOWN now reported |
| pip (+ vendored urllib3/requests/distlib/cachecontrol) | 491 | 41 | `operations/build/build_tracker.py` skipped because the directory is named `build` | fixed: output-dir exclusion no longer applies to Python packages |
| cryptography | 78 | 60 → 96 | algorithm *implementations* (`class MD5(HashAlgorithm)`, `class TripleDES(BlockCipherAlgorithm)`, curve classes) were invisible | fixed: reported with purpose `ALGORITHM_IMPLEMENTATION` when the base class is a crypto ABC |

Every remaining finding in these packages was reviewed and is a genuine cryptographic call, constant or
implementation (digest auth MD5/SHA in `requests/auth.py`, `PROTOCOL_SSLv3`/`CERT_NONE` in urllib3
contrib backends, `os.urandom`, `ssl.create_default_context`, etc.).

## Two discovery bugs this exercise exposed (both fixed, both regression-tested)

1. **Config files were never scanned in a repository scan** — `FileDiscovery` only yielded source
   extensions, so nginx/sshd/Docker/Kubernetes/Terraform/`.env` files were skipped entirely.
2. **Any source directory named `build`, `out`, `target`, `dist` or `bin` was skipped**, even when it
   was a Python package.

## Round 2 — npm tarballs and GitHub checkouts (JavaScript, Java, Go)

Fetched with `npm pack` / `git clone --depth 1`, scanned unmodified, every finding reviewed.

| Project | Lang | Files | Findings | Review |
|---|---|---|---|---|
| lodash | JS | 1,048 | 0 | correct — 0 FP on the largest pure-utility package on npm |
| express | JS | 7 | 1 | `require('cookie-signature')` → HMAC-SHA256 ✔; a `cookieParser("secret")` *inside an error string* was a false positive → fixed |
| cookie-signature | JS | 1 | 3 | `crypto\n .createHmac('sha256')` chained across lines was reported as bare SHA-256, not HMAC → fixed |
| express-session | JS | 5 | 2 | SHA-1 session-id hash, HMAC-SHA256 signing ✔ |
| jsonwebtoken | JS | 12 | 4 → 11 | the `jws` dependency that does the actual signing was invisible → `jws.sign/verify/decode`, `require('jws')` now → JWT |
| bcryptjs | JS | 6 | 7 → 11 | a *vendored bcrypt implementation* only surfaced as CSPRNG → `hashSync/compareSync` definitions now → BCRYPT (ALGORITHM_IMPLEMENTATION) |
| spring-petclinic | Java | 69 | 0 | correct — no cryptography in the project (`grep`-verified) |
| golang-jwt/jwt | Go | 47 | 406 | ECDSA/RSA/Ed25519/HMAC/SHA-2/X.509/JWT/`UnsafeAllowNoneSignatureType` all reported; no FPs found in a 100-finding sample |
| gin-gonic/gin | Go | 102 | 19 → 17 | TLS/`InsecureSkipVerify`/`subtle.ConstantTimeCompare`/QUIC ✔; `math/rand` used to build *test data* was reported as weak RNG → math/rand is now only reported in a security context (statement or enclosing `func` mentions key/token/secret/session/…) |

Regression tests for every fix: `tests/unit/test_external_validation_regressions.py`.
Labelled corpus after these changes: still 348/348 (`scripts/accuracy_benchmark.py`).

## Round 3 — JWT libraries in five languages (the same problem domain, five parsers)

| Project | Lang | Files | Findings | Review |
|---|---|---|---|---|
| firebase/php-jwt | PHP | 13 | 317 | JWT algs, RSA/ECDSA/EdDSA, `hash_equals`, `openssl_pkey_*` ✔; no FPs |
| jwt/ruby-jwt | Ruby | 87 | 887 | **bug:** `Digest::SHA256.hexdigest` was reported as UNKNOWN (an over-broad "dynamic digest" rule shadowed the concrete one) → fixed; `JWT.decode(..., algorithms: ['RS512'])` only surfaced as UNKNOWN → now RS512 |
| golang-jwt/jwt | Go | 47 | 406 | see round 2 |
| Keats/jsonwebtoken | Rust | 36 | 430 | `Algorithm::HS256…EdDSA`, ring `RSA_PSS_2048_8192_SHA512`, `sha2::Sha256`, `rand` ✔; no FPs in sample |
| jwtk/jjwt | Java | 407 | 1,821 | **bug:** `Cipher.getInstance(jcaName)` / `new SecretKeySpec(bytes, alg.getJcaName())` with a *non-literal* name produced findings with `algorithm = None` (22 occurrences) → now `UNKNOWN`; `HmacSHA256` transformations were normalised to the non-vocabulary string `HmacSHA-256` → now `HMAC-SHA-256` |
| jwt-dotnet/jwt | C# | 106 | 104 | JWT, RSA/ECDSA, SHA-2, HMAC, X509 ✔ |

Cumulative external sample: **~2,900 files across 20 projects in 6 languages**; 9 scanner defects found and fixed,
each with a regression test; hand-labelled corpus unchanged at 348/348.

## Round 4 — a large application framework (Django, 928 files, 2.9 s)

| Area | Result |
|---|---|
| False positives | 0 in 913 files without crypto (ORM, templates, admin, forms, migrations…) |
| `conf/global_settings.py` `PASSWORD_HASHERS` | PBKDF2+SHA-256, PBKDF2+SHA-1, Argon2, bcrypt, scrypt ✔ |
| `contrib/auth/hashers.py` | **miss:** `digest = hashlib.sha256` / `hashlib.sha1` class attributes (constructor stored, called later) → now reported |
| `utils/crypto.py` `salted_hmac` | `hmac.new(key, msg, digestmod=hasher)` produced the non-vocabulary algorithm `HMAC-HASHER` → runtime-selected digest now yields plain `HMAC` |
| MD5 cache keys / ETags, SHA-1 template-cache keys, sqlite3 hash functions, SMTP `PROTOCOL_TLS_CLIENT`, `secrets.*` | all reported ✔ |
| Vocabulary clean-up | `CONSTANT-TIME` (Go `subtle.ConstantTimeCompare`, PHP `hash_equals`, `sodium_memcmp`) removed — a comparison routine is not a cryptographic asset and the label was outside the algorithm vocabulary |
