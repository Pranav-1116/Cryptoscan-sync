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

## Round 5 — apache/commons-codec (Java) and caddyserver/caddy (Go)

| Project | Files | Findings | Review |
|---|---|---|---|
| commons-codec | 187 | 320 → 302 | `DigestUtils`/`HmacUtils`/`Md5Crypt`/`Sha2Crypt`/`MessageDigestAlgorithms` fully covered (MD2…SHA3-512, 85 HMAC sites). **noise:** `new Random()` / `ThreadLocalRandom.nextBytes` used to build Base64/Hex *test vectors* (18 findings in tests) → Java now uses the same security-context gate as Go for `java.util.Random`; the old `[^;]*` in the "key = … new Random()" rule could also span lines → fixed. Not reported by design: `Crypt`/`UnixCrypt`/`Blake3` pure-Java implementations and pass-through `MessageDigest` parameters. |
| caddy | 362 | 724 | 351 TLS + 182 X.509 + ML-KEM/X25519 hybrids, `tls.VersionSSL30`/`VersionTLS10` constants in the version table, fastcgi-client MD5 test vectors, `weakrand.Uint32()` in `newMaskKey` (a true weak-RNG-for-key finding) ✔; 5.8 s |

## Round 6 — curl (C, 1,105 files) and microsoft/reverse-proxy (C#, 722 files)

| Project | Findings | Review |
|---|---|---|
| curl | 288 → 412, 25 → 40 files | All six TLS backends (OpenSSL, GnuTLS, mbedTLS, wolfSSL, Schannel, **rustls-ffi — previously invisible**), QUIC, NTLM DES/MD4/MD5, Ed25519 ✔. **miss:** curl's own digest/MAC abstraction (`Curl_MD5_init/update/final`, `Curl_HMAC_init`, `Curl_HMAC_MD5`, `Curl_DIGEST_MD5`) hid HTTP Digest, CRAM-MD5, APOP, AWS SigV4 and NTLMv2 → generic *project-wrapper* rules added (function name embeds a digest name plus an init/update/final verb; `<prefix>_HMAC_<digest>` descriptors). Also added Apple Secure Transport / Network.framework protocol constants. Not reported by design: pure implementations `md5.c`, `md4.c`, `sha256.c` beyond their OpenSSL/mbedTLS branches. 21 s (largest tree so far). |
| YARP | 202 | `SslProtocols.Ssl2/Ssl3/Tls/Tls11` in the TLS-frame parser tests, `X509Certificate2`, AES data-protection ✔. **FP:** `new Random()` next to a `CancellationToken cancellationToken` parameter was read as "token context" → the C# rule now uses the shared security-context gate, which ignores `CancellationToken` and also looks at the enclosing class name. |

## Round 7 — laravel/framework (PHP, 3,098 files) and kubernetes/ingress-nginx (Go + nginx templates + manifests)

| Project | Findings | Review |
|---|---|---|
| laravel/framework | 1,256 → 1,050 | Encrypter AES-CBC/GCM + HMAC-SHA256, Hash bcrypt/argon2, `random_bytes`/`Str::random`, `hash_hmac('sha256')`, HKDF ✔. **FPs found and fixed:** (1) `hash("foo", …)` inside an SQL DDL string in a test produced algorithm `FOO` — PHP `hash()` now only reports names PHP actually supports and *drops* non-cryptographic hashes (xxh128/xxh3/crc32/fnv/murmur/adler — 66 findings gone); (2) `new Builder(` was claimed by both the lcobucci-JWT and paragonie-PASETO rules (134 phantom JWT/PASETO findings on Laravel's query builder) — both now require the vendor namespace; (3) `uniqid(…, true)` / `mt_srand` in cache and memoisation tests reported as weak RNG — PHP now uses the shared security-context gate. |
| ingress-nginx | 195 | TLS/X.509 handling in the controller, `InsecureSkipVerify` in e2e tests, DH params, OCSP, bcrypt in auth tests, nginx `ssl_*` directives in the template ✔ |

### Performance
The Laravel scan exposed the cost of ~300 regex rules per file (71 s). The rule engine now
pre-computes, per rule, the literal words that *must* appear in any match and skips the rule
when the file lacks them. Verified on 4,447 findings across ten repos: byte-identical output,
53 s → 20 s. Unit-tested in `tests/unit/test_rule_prefilter.py`.

Follow-up on ingress-nginx: the controller's real nginx configuration lives in `nginx.tmpl` (a Go
template) and was **not discovered at all** — `.tmpl`, `.tpl`, `.j2` and `.toml` are now scanned as
configuration; templated values (`ssl_protocols {{ $cfg.SSLProtocols }}`) are recorded as a
versionless TLS endpoint (LOW confidence) instead of being dropped; `ssl_ecdh_curve` → ECDH;
`proxy_ssl_protocols` covered. A line-number off-by-one for `^\s*directive` rules that begin on a
preceding blank line was fixed in both the config parser and the rule engine. gRPC
`insecure.NewCredentials` is now labelled `TLS-DISABLED` (same as `sslmode=disable`) instead of
the one-off `TLS-NONE`.

## Round 8 — square/okhttp (Kotlin, 698 files) and panva/jose (TypeScript, 139 files)

| Project | Findings | Review |
|---|---|---|
| okhttp | 1,033 → 1,250 | **4 files were dropped outright** (`CertificatePinner.kt`, `HttpUrl.kt`, `MultipartBody.kt`, `RequestTest.kt`): Kotlin char literals such as `'{'` unbalanced the shallow brace check and the Java/Kotlin parser raised instead of degrading. Both the AST path and the regex path now fall back gracefully — a file is never lost to a syntax heuristic. okio `ByteString.sha256()/sha1()/md5()/hmacSha256()`, `CertificatePinner` `"sha256/…"` pins, `ConnectionSpec`/`TlsVersion` constants added. `KeyStore.getInstance("PKCS12")` now inventoried under X.509 instead of leaking store-format strings as algorithm names. |
| jose | 1,338 (120 UNKNOWN → 78) | JWS/JWE/JWK/JWKS algorithms, X25519/ECDH-ES, PBES2, A128CBC-HS256 ✔. WebCrypto calls with a *multi-line* algorithm object (`{ iv, name: 'AES-CBC' }`) or a bare algorithm string (`importKey('raw', k, 'AES-CBC')`) were UNKNOWN → the argument list is now inspected; JWE `alg: 'dir'` → JWT family. |

## Round 9 — new file classes: shell / Dockerfile / Swift / plist

Two whole file classes were previously **not scanned at all**: shell scripts (where certificates, key pairs and encrypted backups are actually provisioned, and where `curl -k` / `NODE_TLS_REJECT_UNAUTHORIZED=0` live) and Swift (CryptoKit, CommonCrypto, Security.framework, Alamofire pinning, CryptoSwift, sodium, JWTKit) plus ATS `Info.plist`. `.gradle/.groovy` now go through the JVM rule set and `.vue/.svelte` through the JS parser. Corpus wave 5 (64 files) covers them; 450/450 after reconciliation.

| Project | Files | Findings | Review |
|---|---|---|---|
| acmesh-official/acme.sh | 288 | 78 | First pass reported 408 bogus `X509` hits — the repo's own script name matched a `\bacme\.sh\b` rule (now needs `--issue/--renew…`) — and **missed every real openssl call** because acme.sh invokes `${ACME_OPENSSL_BIN:-openssl}`. Tool-behind-variable normalisation added (`"$OPENSSL"`, `$(which openssl)`, `/usr/bin/openssl`). After: genrsa/ecparam/req/x509/pkcs12/pkcs8 -v2 aes256/ocsp/`dgst -mac HMAC`/`curl --insecure` all inventoried; package-install lines and `openssl version` silent. |
| docker-library/postgres, mysql | 92 | 34 | `gpg --batch --verify` (signature, algorithm unknown), `openssl rand` in entrypoints. `pg_hba.conf` auth methods (md5 / scram-sha-256 / password / hostnossl) and MySQL `default_authentication_plugin` / `require_secure_transport` rules added for the generated configs. |
| Alamofire | 121 | 72 | `PinnedCertificatesTrustEvaluator`/`PublicKeysTrustEvaluator` → X509 pinning, `DisabledTrustEvaluator` → TRUST-ALL, SecTrust/SecPolicy API ✔. `UInt32.random(in:)` for a multipart boundary was reported as CSPRNG → generic `.random(in:)` rule removed (not a crypto asset). |
| vapor/jwt-kit | 107 | ~310 | `Insecure.RSA.*`, `ES256PrivateKey`, `EdDSA.*`, `.add(hmac:digestAlgorithm:)` now emit the real family (RSA/ECDSA/Ed25519/HMAC+digest) alongside JWT, not just "JWT". |
| krzyzanowskim/CryptoSwift | 163 | 342 | AES block modes captured per call (`blockMode: GCM/CBC/CTR/CCM/CFB`), `PKCS5.PBKDF2`, `Scrypt`, `HKDF`, `ChaCha20`, `Rabbit`, `Blowfish`, `Poly1305`, `CMAC`, `Digest.*`, `SHA2(variant:)`, `SHA3`, `RSA(keySize:)` ✔. `.md5()`-style extensions are only reported when CryptoSwift is actually imported / used in the file. |
| KeychainAccess | 29 | 2 | Keychain access-control (`SecAccessControlCreateWithFlags`) produced 40 UNKNOWNs → removed; it is key *storage*, not an algorithm. Only `SecRandomCopyBytes` remains. |

## Round 10 — XML configuration

`.xml`, `.config`, `.csproj`, `.props` were not scanned before. New `xml_parser.py` covers web.config/WCF/ADO.NET connection strings, Spring Security XML, Android network-security-config / manifest, Tomcat and WildFly server configs, JDBC URLs, Maven/NuGet crypto dependencies and SAML/XML-DSig algorithm URIs. XML comments are blanked first. Corpus wave 6 (20 files, 5 negatives) → 470/470.

| Project | XML files | Findings | Review |
|---|---|---|---|
| spring-projects/spring-security | 485 | 91 | `<remember-me>` (MD5 default, LOW), `<jwt>`, `<x509>`, SAML metadata `KeyDescriptor`/`X509Certificate`, `requires-channel`, `NoOpPasswordEncoder` bean → PLAINTEXT. No hits in build/test-fixture XML. |
| apache/tomcat | 220 | 13 | Only `conf/server.xml` fires: `SSLHostConfig`, keystore/certificate files, `Connector SSLEnabled`. Everything else (build files, MBean descriptors, web.xml) silent. |
| dotnet/aspnetcore (391 .csproj/.props/.config) | 391 | 0 → 14 | `<Reference Include="…JwtBearer">` (not `PackageReference`) was missed → rule widened to `Reference`/`PackageVersion`. |

## Round 11 — bank / payments proxies (jPOS, Apache Fineract)

The bank-realism question: a real bank estate is dominated by payments crypto (PIN blocks, EMV cryptograms, DUKPT, TR-31 key blocks, retail MACs, HSM adapters) that no generic `Cipher.getInstance` rule sees. Two open-source proxies for that code were scanned end to end with the production parsers.

| Project | Files | Before | After | Review |
|---|---|---|---|---|
| jpos/jPOS (ISO 8583 / payments switch, `org.jpos.security`, `org.jpos.emv`) | 1207 | 46 findings in 14 files — **43 payment-crypto files had zero findings** (`SecureDESKey`, `EncryptedPIN`, `SMAdapter`/`BaseSMAdapter`/`JCESecurityModule`, `EMVSMAdapter`, `KeySerialNumber`/DUKPT, `SecureKeyBlock`, `KeyScheme`, CVN data builders, ISO 9797 padding), and `new SecretKeySpec(bytes, "testJCEHandlerParam2")` leaked the literal as an algorithm name | 1647 findings in 75 files: 3DES 1243 (PIN/CVV/ARQC/DUKPT/MAC/working keys), RSA 222 (EMV issuer/ICC/CA public keys, DDA/CDA), AES 44 (format-4 PIN, TR-31 key blocks, AES working keys), UNKNOWN 83 (SM adapter / key-store instantiations, providers). | Every finding outside `org/jpos/security`, `org/jpos/emv` and the SSM CLI was re-read by hand: JKS keystore + TRUST-ALL in `GenericSSLSocketFactory`, MD5 in `MD5Filter`/`MD5Template`, PGP/3DES/HMAC in `PGPHelper`, `new Random()` in `ISOServer`. Nothing spurious. First cut of the pack matched `throws SMException` on every method (664 junk UNKNOWNs) and Thales 2-letter host-command literals (`"OK",` in Fineract) — both removed; class markers now require `new`/`extends`/`implements`/typed-field forms. |
| apache/fineract (core banking, Spring) | 7533 | 105 findings / 43 files | 105 / 43 (unchanged — zero new noise from the payments pack) | TLS/JWT/BCrypt/PBKDF2/SecureRandom, `PlatformPasswordEncoder`, `EncryptionUtil` (AES), two `SSLv3` in test SSL contexts, BouncyCastle Gradle deps. 107 files that mention `key`/`token`/`password` without crypto correctly stay silent. |

New detector surface (all in `java_rules.py`, plus `known_algorithm_or_unknown()` gate in the algorithm extractor):
PIN blocks (ISO 9564 formats; `FORMAT04` → AES), CVV/CVC/dCVV, EMV ARQC/ARPC/SKD/MKD, ISO 9797 retail MAC, `SecureDESKey`/`TYPE_ZPK…`/`KeyScheme`, DUKPT/KSN/BDK, TR-31 / `SecureKeyBlock`, KCV, SM adapters (inventory-only UNKNOWN), Thales `ThalesAdapter`/payShield/LMK, PKCS#11 providers (SunPKCS11, IAIK, Luna, nCipher, Utimaco, CloudHSM, IBMJCECCA) with per-family `CKM_*`/`CKK_*` resolution, SWIFT LAU, 3-D Secure CAVV, FF1/FF3-1 format-preserving encryption. Corpus wave 8 (31 files, blind) first pass 25/31 → 544/544.

Still open for a bank engagement (not covered by any proxy on GitHub): PL/SQL `DBMS_CRYPTO` / T-SQL `ENCRYPTBYKEY`/`HASHBYTES`, COBOL ICSF callable services (`CSNBENC`, `CSNBSYE`, `CSNBOWH`, `CSNBPVR`), CICS/IMS middleware config, and throughput on a 10M-LOC monorepo. These are the next parsers.
