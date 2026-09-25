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

## Round 12 — database and mainframe code (new `sql_parser.py`, `cobol_parser.py`)

`.sql/.pks/.pkb/.pls/.prc/.tsql/.ddl…` and `.cbl/.cob/.cpy/.jcl/.pco/.sqb…` were not scanned before. Corpus wave 9 (50 files, 9 negatives) → 594/594.

| Project | Files | Findings | Review |
|---|---|---|---|
| microsoft/sql-server-samples | 2359 (≈1400 .sql) | 90 in 30 files | Always Encrypted `ALGORITHM = 'AEAD_AES_256_CBC_HMAC_SHA_256'` → AES + HMAC-SHA256 (17 scripts), `COLUMN_ENCRYPTION_KEY`, `HASHBYTES('SHA2_256'/'SHA2_512')` in WideWorldImporters password procedures (5 of 6 files — the 6th has it only in a comment), `CREATE CERTIFICATE` templates. **One FP class found and removed**: the DB2 `HASH(expr, n)` rule matched SQL Server memory-optimized `INDEX … HASH (col) WITH (BUCKET_COUNT = 3…)` across lines — now requires a single identifier and a bare 0–3 second argument. |
| utPLSQL/utPLSQL (PL/SQL framework) | 499 | 6 | `dbms_crypto.hash_sh256` ×5 (correct), `curl -Lk` in a dev script. Zero noise across 400+ PL/SQL bodies. |
| oracle-samples/db-sample-schemas | 223 | 0 | Product descriptions containing the word "encryption" correctly ignored. |
| aws-samples/aws-mainframe-modernization-carddemo (CICS/VSAM card app, 184 COBOL/JCL/copybooks) | 184 | 0 | No ICSF calls in the repo (`grep -i CSNB\|ICSF` empty) — a 184-file true-negative set for the COBOL parser: VSAM `RECORD KEY`, `PASSWORD` fields, `FUNCTION RANDOM`, JCL all silent. |
| openmainframeproject/cobol-programming-course | 73 | 0 | Same — no cryptography, no noise. |

Limitation stated plainly: no public COBOL repository exercises ICSF, so the positive side of the COBOL parser is validated only by the wave-9 corpus (written from the ICSF Application Programmer's Guide verb list and rule-array keywords). The first real-bank engagement should start by running `scan_third_party.py` over the ICSF-calling modules and triaging that output.

## Round 13 — code published by banks themselves, plus middleware / bytecode / PL/I (wave 10 → 628/628)

New in this round: IBM MQ (MQSC `SSLCIPH`, `mqclient.ini`, JMS XML, `MQEnvironment`/`WMQConstants`), WebSphere (`security.xml`, `ssl.client.props`, Liberty `server.xml`, `JSSEHelper`), WebLogic (`config.xml`, `-Dweblogic.security.SSL.*`), `java.security` provider order and `jdk.tls.*` policies, IBMJSSE2/IBMJCE, Mule TLS/crypto, Camel SSL/crypto/PGP, CXF/Rampart/WSO2, jasypt, QuickFIX/J session TLS, SWIFT LAU, Thales payShield host commands in a Java HSM client, a PL/I parser (ICSF verbs), and a constant-pool scanner for JAR/WAR/EAR/`.class` (no javap needed). Every finding now carries `metadata.code_origin` ∈ {source, test, generated, vendored, archive}.

Real repositories published under bank GitHub organisations (shallow clones, `scripts/scan_third_party.py`, every sampled finding traced back to its source line):

| Org / project | Files | Findings | Review |
|---|---|---|---|
| jpmorganchase/quorum (Go, Ethereum fork) | 1535 | 1742 in 297 files (797 source / 944 test / 1 generated) | secp256k1/ECDSA, Keccak, AES keystores, scrypt, TLS. **One mis-attribution fixed**: `crypto.Keccak256Hash(...)` from the go-ethereum `crypto` package was reported as ECDSA in addition to SHA3 — now SHA3 only. The `hash.Hash`/`crypto.Signer` interface markers stay LOW/UNKNOWN and are excluded from accuracy scoring. |
| OpenBankProject/OBP-API (Scala, open-banking API) | 1594 | 182 in 47 files (121 source / 57 test / 4 generated) | Nimbus JOSE (HS256/RS256 JWTs), `SHA256withRSA` Berlin-Group request signing, jBCrypt, KeyStore/PEM handling, `scala.util.Random` flagged as PRNG (correct — it is used to build passwords in a test helper). No false positives in the 14-line random sample. |
| ing-bank/baker (Scala) | 762 | 27 in 8 files | **One label bug fixed**: `Cipher.getInstance(s"$algorithmName/ECB/PKCS5Padding")` produced the algorithm `$algorithmName`. Interpolated/format-string transformations are now `UNKNOWN` with the mode kept — ECB is still the finding that matters. |
| goldmansachs/legend-engine (Java, 6744 files) | 6744 | 53 in 19 files | AES/GCM utility, PBE key spec for Snowflake key-pair auth, PEM parsers, `DigestUtils.sha256Hex`, BouncyCastle provider registration. Zero noise across 6.7k files. |
| capitalone/Hygieia (Java/Spring) | 386 | 0 | True-negative repo — `grep` confirms no JCA/JSSE usage in the top-level project. |

Origin split matters at bank scale: in quorum more than half of the crypto call sites are in `_test.go`; a remediation queue built on `code_origin == source` is 797 items, not 1742. Nothing is dropped — inventory and CBOM keep every finding.

Still not validated on public code (stated plainly): payShield host-command clients, ICSF-calling COBOL/PL/I, WebSphere/WebLogic production descriptors, MQSC with `SSLCIPH`. Those are corpus-validated only (wave 10 first pass 610/628; the 18 misses were 12 label-convention slips and 6 real rule gaps, all fixed).

## Round 14 — IBM i (AS/400) — new `rpg_parser.py`, wave 11 → 656/656

RPG IV (`.rpgle/.sqlrpgle/.rpg*`), CL (`.clle/.clp/.cl`) and ILE C were not scanned before. The IBM i crypto surface is small and very specific: `Qc3*` Cryptographic Services APIs whose algorithm lives in a numeric code inside the `ALGD02xx/04xx/05xx` structure (22 = AES, 21 = 3DES, 3 = SHA-256 …), GSKit TLS, and the `QSSLPCL`/`QSSLCSL` system values. The parser resolves the code from the field initialiser (free or fixed form), the `qc3cci.h` constants (`Qc3_SHA1`), or a unique keyword in the surrounding declarations — otherwise the call stays UNKNOWN rather than being guessed.

| Project (public IBM i code) | Files | Findings | Review |
|---|---|---|---|
| sitemule/ILEastic (ILE C web server) | 167 | 45 in 3 files | GSKit environment/keyring/`GSK_PROTOCOL_TLSV12/13` in `ileastic.c` + `sockets.c`; WebSocket handshake `Qc3CalculateHash` in `websockets.c` correctly resolved to **SHA-1** from `algDesc[3] = Qc3_SHA1`. |
| OSSILE/OSSILE (51 RPGLE + C utilities) | 155 | 3 in 2 files | `QC3CALHA` / `QC3CRTAX` in the `c_md5crc` utility (algorithm context token → UNKNOWN, correct: the algorithm is in a runtime token). 51 RPGLE business programs silent. |
| worksofliam/noxDB (RPG/C JSON lib) | 253 | 0 | true negative |
| richardschoen/QshOni | 98 | 1 | `curl -k` in a shell wrapper |

Finding: real IBM i shops call `Qc3`/GSKit from **ILE C** as often as from RPG — the C parser now runs the IBM i rule table whenever a `.c/.h` mentions `Qc3`/`QC3xxxxx`/`gsk_`/`GSK_`. The blind PCI-PIN half of wave 11 (10 files written from PCI PIN Security / X9.24 / ISO 9564 / TR-31 text rather than any library API) scored 8/10 on the first pass; both misses were real and are fixed (DUKPT class/`ipek` naming, C# `CipherMode` receiver resolution).

## Round 15 — .NET assemblies and native DLLs (new `detectors/dotnet/assembly_scanner.py`)

Vendored `.dll/.exe` are the .NET analogue of fat JARs. The scanner reads the PE directly (no SDK): the CLI metadata `#Strings`/`#US` heaps for managed assemblies (type references gated on the owning namespace being present — a bank's own `RSA` class is not `System.Security.Cryptography.RSA`), and the import table for native binaries (CNG/CAPI/DPAPI/Schannel, OpenSSL, libsodium, mbedTLS, wolfSSL, PKCS#11 `C_*`).

Real binaries (Windows wheels from PyPI — the only binary source reachable from this sandbox):

| Binary | Findings | Review |
|---|---|---|
| pythonnet 3.1.0 runtime — 99 .NET facade assemblies | 9 assemblies with findings, 90 silent | `System.Security.Cryptography.Algorithms.dll` → AES, RSA, 3DES, RC2, MD5, SHA-1/256/384 (the types it forwards); `System.Net.Security.dll` → TLS + X509; `netstandard.dll` → the union. `Python.Runtime.dll` and the 89 non-crypto facades: 0. |
| OpenSSL `libssl-3-x64.dll` (from psycopg2-binary) | 38 | imports from libcrypto: HMAC, RSA, MD5/SHA-1/256/384/512 (`EVP_sha*`), 26 UNKNOWN for algorithm-agnostic `EVP_*Init/Update/Final` (correct: the algorithm is a runtime parameter). |
| `libpq.dll` | 23 | `SSL_CTX_new`/`SSL_connect`/`TLS_client_method` → TLS, `PKCS5_PBKDF2_HMAC`/`HMAC` (SCRAM), `RAND_bytes`, `EVP_sha256/512` |
| `libcrypto-3-x64.dll` | 9 | Windows `CertOpenStore`/`CertFindCertificateInStore` → X509 (it can load the Windows root store), `BCryptGenRandom` UNKNOWN→CSPRNG path. |

Limits stated plainly: names only — no data flow inside IL or machine code, so `EVP_EncryptInit` is UNKNOWN, and a managed assembly that builds algorithm names at runtime shows only the namespace. Findings carry `code_origin="archive"` and `file_path = x.dll!Type` / `x.dll!import:Symbol`.

## Round 16 — full-pipeline parity check (found two discovery bugs)

Every previous round drove the parsers through `scan_third_party.py` (FileDiscovery + `scan_file`). Running the *production* pipeline (`Scanner().scan`, i.e. the CLI / worker path) over the same tree exposed two gaps that the corpus could never see:

1. **Test directories were silently dropped.** `ScannerConfig.exclude_dirs` defaulted to `{test, tests, build, …}` and *replaced* `DEFAULT_EXCLUDED_DIRS`, so goldmansachs/legend-engine scanned 4 927 files instead of 6 744 and reported 48 findings instead of 53 — and `node_modules`/`vendor`/`.idea` were no longer excluded whenever the config object loaded. Config directories are now *merged* with the defaults and test dirs are only excluded with `--exclude-tests` (findings from tests are tagged `code_origin=test` instead).
2. **Every JAR finding was emitted twice.** A legacy `rglob("*.jar")` pass ran in addition to the discovery path. Removed; a pipeline test asserts one finding per archive member.

After the fix `Scanner().scan` and `scan_third_party.py` agree exactly (6 744 files / 53 findings / 48 source + 5 test). Lesson recorded for the runbook: validate through the same entry point the bank will run, not only through the parser harness.

## Round 17 — indirection / evasion shapes (wave 12, blind) → 689/689

Before writing the wave, the resolver was probed on one constant-argument shape per language; only Ruby (`OpenSSL::Cipher.new(ALG)`) failed and was fixed first. The 33-file wave was then written blind and scored **679/689 (P 0.999 / R 0.986 / F1 0.993)** before any rule was touched. Every miss was a false negative; the single precision loss was a coined name (`SHABITS`) from an unresolved Kotlin `"SHA-$bits"` template — `parse_transformation` now maps any surviving `$var` / `%s` / `{0}` / `#{}` placeholder to `UNKNOWN` (which is never counted) instead of inventing an algorithm.

Decision recorded: a **declaration-only JCA transformation constant** (`static final String CIPHER = "DESede/CBC/PKCS5Padding"` with the `getInstance` in another file) *is* inventory — the literal form `Algorithm/Mode/Padding` is unambiguous. Re-scanning Fineract after the change added exactly three findings, all `DEFAULT_ENCRYPTION = "AES/CBC/PKCS5Padding"` passed to an internal wrapper (`EncryptionUtil.encryptToBase64`) — true positives the old rule could not see. jPOS output is byte-identical. Bare Node cipher names in an unused enum member are *not* counted (declared-but-unused is not usage); this asymmetry is deliberate and documented in the corpus.

Other resolver additions: Java `import static javax.crypto.Cipher.getInstance`, class-qualified constants (`Algorithms.CIPHER`), numeric constants folded into Kotlin/JS/Python templates, `hashlib` dispatch tables (`{"legacy": hashlib.md5}`), TS `const enum` members, Go dot imports (`import . "crypto/sha1"` → bare `Sum(`), C# `using Sym = System.Security.Cryptography.Aes;`.
