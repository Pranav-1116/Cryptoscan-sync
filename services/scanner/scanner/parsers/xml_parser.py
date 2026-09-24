"""XML configuration crypto detector.

Covers the XML files that decide real cryptographic posture:

* ASP.NET ``web.config`` / ``app.config`` — machineKey validation/decryption
  algorithms, membership hashAlgorithmType / passwordFormat, ``requireSSL``,
  ``SecurityProtocol`` app settings, IIS ``sslFlags``, WCF bindings,
  ADO.NET connection strings (``Encrypt=false``, ``TrustServerCertificate``)
* Spring / Spring Security XML — ``<password-encoder hash="md5">``,
  ``*PasswordEncoder`` beans, remember-me, requires-channel, jasypt PBE beans
* Android ``network_security_config.xml`` / ``AndroidManifest.xml`` —
  cleartext traffic, user trust anchors, certificate pins
* Tomcat ``server.xml`` — connector protocols / ciphers / keystores, realm digests
* WildFly / Elytron — ssl contexts, password mappers, clear-text credentials
* JDBC URLs (``useSSL=false``, ``sslmode=disable``, ``trustServerCertificate``)
* Maven ``pom.xml`` / NuGet ``packages.config`` / ``*.csproj`` crypto dependencies
* XML-DSig / XML-Enc / WS-Security / SAML algorithm URIs

Every rule needs an element/attribute context; prose in ``<description>`` or
XML comments never matches on its own.
"""

from __future__ import annotations

import re
from pathlib import Path

from scanner.models.raw_finding import RawFinding
from scanner.parsers.finding_factory import make_finding
from scanner.parsers.rule_engine import Rule, run_rules

SCANNER_ID = "static-xml-scanner-v1.0"

_D = {"api_type": "MESSAGE_DIGEST", "purpose": "HASHING"}
_C = {"api_type": "CIPHER_INSTANCE", "purpose": "ENCRYPTION"}
_S = {"api_type": "SIGNATURE", "purpose": "SIGNING"}
_M = {"api_type": "MAC", "purpose": "MAC_GENERATION"}
_KDF = {"api_type": "KEY_GENERATOR", "purpose": "PASSWORD_HASHING"}
_TLS = {"api_type": "KEY_AGREEMENT", "purpose": "NETWORK_ENCRYPTION"}
_DEP = {"api_type": "KEY_GENERATOR", "purpose": "KEY_MANAGEMENT"}


def _r(pattern: str, base: dict, library: str, **extra) -> Rule:
    return re.compile(pattern, re.I), {**base, "library": library, **extra}


_DIGEST = {"md5": "MD5", "md4": "MD4", "sha": "SHA-1", "sha1": "SHA-1", "sha-1": "SHA-1", "sha256": "SHA-256", "sha-256": "SHA-256", "sha384": "SHA-384", "sha-384": "SHA-384",
           "sha512": "SHA-512", "sha-512": "SHA-512", "hmacsha256": "HMAC-SHA256", "hmacsha384": "HMAC-SHA384", "hmacsha512": "HMAC-SHA512", "hmacmd5": "HMAC-MD5", "hmacsha1": "HMAC-SHA1"}
_CIPHER = {"aes": "AES", "3des": "3DES", "des": "DES", "auto": "AES", "tripledes": "3DES", "rc2": "RC2", "rc4": "RC4", "rijndael": "AES", "desede": "3DES", "blowfish": "Blowfish", "chacha20": "ChaCha20", "chacha20-poly1305": "ChaCha20-Poly1305"}
_PROTO = {"tls13": "TLS1.3", "tls12": "TLS1.2", "tls11": "TLS1.1", "tls": "TLS1.0", "ssl3": "SSLv3", "ssl2": "SSLv2", "systemdefault": "TLS",
          "tlsv1.3": "TLS1.3", "tlsv1.2": "TLS1.2", "tlsv1.1": "TLS1.1", "tlsv1": "TLS1.0", "tlsv1.0": "TLS1.0", "tls1.2": "TLS1.2", "tls1.3": "TLS1.3", "sslv3": "SSLv3", "sslv2": "SSLv2", "sslv2hello": "SSLv2"}
_JWT = {k: "JWT" for k in ("hs256", "hs384", "hs512", "rs256", "rs384", "rs512", "es256", "es384", "es512", "ps256", "ps384", "ps512", "eddsa")}
_JWT["none"] = "none"
_XMLDSIG: dict[str, tuple[str, str | None]] = {
    "rsa-sha1": ("RSA", "SHA-1"), "rsa-sha256": ("RSA", "SHA-256"), "rsa-sha384": ("RSA", "SHA-384"), "rsa-sha512": ("RSA", "SHA-512"), "rsa-md5": ("RSA", "MD5"),
    "rsa-sha256-mgf1": ("RSA", "SHA-256"), "dsa-sha1": ("DSA", "SHA-1"), "dsa-sha256": ("DSA", "SHA-256"),
    "ecdsa-sha1": ("ECDSA", "SHA-1"), "ecdsa-sha256": ("ECDSA", "SHA-256"), "ecdsa-sha384": ("ECDSA", "SHA-384"), "ecdsa-sha512": ("ECDSA", "SHA-512"),
    "hmac-sha1": ("HMAC", "SHA-1"), "hmac-sha256": ("HMAC", "SHA-256"), "hmac-sha384": ("HMAC", "SHA-384"), "hmac-sha512": ("HMAC", "SHA-512"), "hmac-md5": ("HMAC", "MD5"),
    "sha1": ("SHA-1", None), "sha224": ("SHA-224", None), "sha256": ("SHA-256", None), "sha384": ("SHA-384", None), "sha512": ("SHA-512", None), "md5": ("MD5", None),
    "aes128-cbc": ("AES", None), "aes192-cbc": ("AES", None), "aes256-cbc": ("AES", None), "aes128-gcm": ("AES", None), "aes192-gcm": ("AES", None), "aes256-gcm": ("AES", None),
    "tripledes-cbc": ("3DES", None), "rsa-1_5": ("RSA", None), "rsa-oaep-mgf1p": ("RSA", None), "rsa-oaep": ("RSA", None),
    "kw-aes128": ("AES", None), "kw-aes192": ("AES", None), "kw-aes256": ("AES", None), "kw-tripledes": ("3DES", None), "dh": ("DH", None), "dh-es": ("DH", None), "ecdh-es": ("ECDH", None),
}
_XMLDSIG_URI = r"http://www\.w3\.org/(?:2000/09/xmldsig|2001/04/xmldsig-more|2001/04/xmlenc|2009/xmlenc11|2007/05/xmldsig-more)#([a-z0-9_.-]+)"

_MAVEN_DEPS = {
    "bcprov-jdk15on": "UNKNOWN", "bcprov-jdk18on": "UNKNOWN", "bcprov-jdk15to18": "UNKNOWN", "bcpkix-jdk15on": "UNKNOWN", "bcpkix-jdk18on": "UNKNOWN",
    "bcprov-ext-jdk15on": "UNKNOWN", "bctls-jdk15on": "UNKNOWN", "bctls-jdk18on": "UNKNOWN", "bc-fips": "UNKNOWN",
    "jjwt": "JWT", "jjwt-api": "JWT", "jjwt-impl": "JWT", "jjwt-jackson": "JWT", "jjwt-gson": "JWT", "java-jwt": "JWT", "nimbus-jose-jwt": "JWT", "jose4j": "JWT", "jwks-rsa": "JWT", "fusionauth-jwt": "JWT",
    "tink": "UNKNOWN", "tink-android": "UNKNOWN", "lazysodium-java": "UNKNOWN", "libsodium-jni": "UNKNOWN", "argon2-jvm": "ARGON2", "bcrypt": "BCRYPT", "jbcrypt": "BCRYPT", "scrypt": "SCRYPT", "password4j": "ARGON2",
    "jasypt": "PBKDF2", "jasypt-spring-boot-starter": "PBKDF2", "spring-security-crypto": "BCRYPT", "conscrypt-android": "TLS", "conscrypt-openjdk-uber": "TLS", "okhttp-tls": "TLS",
    "liboqs-java": "ML-KEM", "xmlsec": "UNKNOWN", "wss4j-ws-security-common": "UNKNOWN", "opensaml-saml-api": "UNKNOWN", "opensaml-xmlsec-api": "UNKNOWN", "keycloak-core": "JWT",
}
_NUGET_DEPS = {
    "bouncycastle": "UNKNOWN", "bouncycastle.cryptography": "UNKNOWN", "bouncycastle.netcore": "UNKNOWN", "portable.bouncycastle": "UNKNOWN",
    "system.identitymodel.tokens.jwt": "JWT", "microsoft.identitymodel.tokens": "JWT", "microsoft.aspnetcore.authentication.jwtbearer": "JWT", "jose-jwt": "JWT", "jwt": "JWT",
    "bcrypt.net-next": "BCRYPT", "bcrypt.net": "BCRYPT", "konscious.security.cryptography.argon2": "ARGON2", "isopoh.cryptography.argon2": "ARGON2", "sodium.core": "UNKNOWN", "UNKNOWN": "UNKNOWN",
    "nsec.cryptography": "UNKNOWN", "scrypt.net": "SCRYPT", "cryptsharpofficial": "BCRYPT", "microsoft.aspnetcore.dataprotection": "AES", "system.security.cryptography.protecteddata": "DPAPI",
    "system.security.cryptography.pkcs": "X509", "system.security.cryptography.xml": "UNKNOWN", "azure.security.keyvault.keys": "RSA", "google.crypto.tink": "UNKNOWN", "pgpcore": "UNKNOWN",
    "paseto.core": "PASETO", "chaos.nacl": "Ed25519", "ssh.net": "SSH", "renci.sshnet": "SSH",
}

_RULES: list[Rule] = [
    # ------------------------------------------------------------ ASP.NET web.config / app.config
    _r(r"<machineKey\b[^>]*\bvalidation\s*=\s*[\"'](MD5|SHA1|3DES|AES|HMACSHA256|HMACSHA384|HMACSHA512)[\"']", _M, "asp.net", algo_from_group=1, algo_map={**_DIGEST, "3des": "3DES", "aes": "AES"}, confidence_reason="machineKey validation algorithm"),
    _r(r"<machineKey\b[^>]*\bdecryption\s*=\s*[\"'](Auto|AES|3DES|DES)[\"']", _C, "asp.net", algo_from_group=1, algo_map=_CIPHER, confidence_reason="machineKey decryption algorithm"),
    _r(r"<machineKey\b(?![^>]*\bvalidation\s*=)", _M, "asp.net", algorithm="HMAC-SHA256", confidence="MEDIUM", confidence_reason="machineKey default validation is HMACSHA256"),
    _r(r"<membership\b[^>]*\bhashAlgorithmType\s*=\s*[\"'](MD5|SHA1|SHA256|SHA512|HMACSHA256|HMACSHA512)[\"']|<add\b[^>]*\bhashAlgorithmType\s*=\s*[\"'](MD5|SHA1|SHA256|SHA512|HMACSHA256|HMACSHA512)[\"']", _KDF, "asp.net", algo_from_group=1, algo_map=_DIGEST),
    _r(r"\bpasswordFormat\s*=\s*[\"']Clear[\"']", _KDF, "asp.net", algorithm="PLAINTEXT", confidence="HIGH", confidence_reason="membership passwords stored in clear"),
    _r(r"\bpasswordFormat\s*=\s*[\"']Encrypted[\"']", _KDF, "asp.net", algorithm="AES", confidence="MEDIUM", confidence_reason="membership passwordFormat=Encrypted uses machineKey decryption (default AES)"),
    _r(r"\bpasswordFormat\s*=\s*[\"']Hashed[\"'](?![^>]*\bhashAlgorithmType\s*=)", _KDF, "asp.net", algorithm="SHA-1", confidence="MEDIUM", confidence_reason="membership passwordFormat=Hashed defaults to SHA1"),
    _r(r"<(?:httpCookies|forms|roleManager|anonymousIdentification)\b[^>]*\brequireSSL\s*=\s*[\"']false[\"']", _TLS, "asp.net", algorithm="TLS-CLEARTEXT", confidence="HIGH", confidence_reason="cookies allowed over plain HTTP"),
    _r(r"<(?:httpCookies|forms|roleManager)\b[^>]*\brequireSSL\s*=\s*[\"']true[\"']", _TLS, "asp.net", algorithm="TLS", confidence="MEDIUM"),
    _r(r"<add\b[^>]*\bkey\s*=\s*[\"'][^\"']*(?:SecurityProtocol|TlsVersion|Tls_Version|SslProtocols)[^\"']*[\"'][^>]*\bvalue\s*=\s*[\"'](Tls13|Tls12|Tls11|Tls|Ssl3|Ssl2|SystemDefault)\b", _TLS, "asp.net", algo_from_group=1, algo_map=_PROTO),
    _r(r"\bSwitch\.System\.Net\.DontEnableSchUseStrongCrypto\s*=\s*true|\bkey\s*=\s*[\"']Switch\.System\.Net\.DontEnableSchUseStrongCrypto[\"'][^>]*\bvalue\s*=\s*[\"']true[\"']", _TLS, ".net", algorithm="TLS1.0", confidence="HIGH", confidence_reason="strong-crypto switch disabled → SSL3/TLS1.0 re-enabled"),
    _r(r"\bSwitch\.System\.Net\.DontEnableSystemDefaultTlsVersions\s*=\s*true|\bkey\s*=\s*[\"']Switch\.System\.Net\.DontEnableSystemDefaultTlsVersions[\"'][^>]*\bvalue\s*=\s*[\"']true[\"']", _TLS, ".net", algorithm="TLS1.0", confidence="MEDIUM", confidence_reason="system default TLS versions disabled"),
    _r(r"<access\b[^>]*\bsslFlags\s*=\s*[\"']None[\"']", _TLS, "iis", algorithm="TLS-CLEARTEXT", confidence="MEDIUM", confidence_reason="IIS site does not require SSL"),
    _r(r"<access\b[^>]*\bsslFlags\s*=\s*[\"'][^\"']*Ssl\b", _TLS, "iis", algorithm="TLS", confidence="MEDIUM"),
    _r(r"<binding\b[^>]*\bsslProtocols\s*=\s*[\"']([^\"']+)[\"']", _TLS, "wcf", algorithm="TLS", confidence="MEDIUM", split_tls_group=1),
    _r(r"<security\b[^>]*\bmode\s*=\s*[\"']Transport(?:WithMessageCredential)?[\"']", _TLS, "wcf", algorithm="TLS", confidence="MEDIUM"),
    _r(r"<security\b[^>]*\bmode\s*=\s*[\"']None[\"']", _TLS, "wcf", algorithm="TLS-CLEARTEXT", confidence="HIGH", confidence_reason="WCF binding without transport or message security"),
    _r(r"\balgorithmSuite\s*=\s*[\"'](Basic128|Basic192|Basic256|TripleDes)(?:Rsa15|Sha256|Sha256Rsa15)?[\"']", _C, "wcf", algo_from_group=1, algo_map={"basic128": "AES", "basic192": "AES", "basic256": "AES", "tripledes": "3DES"}),
    _r(r"\balgorithmSuite\s*=\s*[\"'](?:Basic128|Basic192|Basic256|TripleDes)Sha256(?:Rsa15)?[\"']", _D, "wcf", algorithm="SHA-256"),
    _r(r"\balgorithmSuite\s*=\s*[\"'](?:Basic128|Basic192|Basic256|TripleDes)(?:Sha256)?Rsa15[\"']", _S, "wcf", algorithm="RSA", confidence_reason="RSA PKCS#1 v1.5 key wrap"),
    _r(r"<(?:clientCertificate|serviceCertificate|certificateReference|certificate)\b[^>]*\b(?:findValue|storeName|storeLocation|encodedValue)\s*=", _TLS, "wcf", algorithm="X509", confidence="MEDIUM"),
    _r(r"\bcertificateValidationMode\s*=\s*[\"']None[\"']", _TLS, "wcf", algorithm="TLS-CERT-NONE", confidence="HIGH", confidence_reason="certificate validation disabled"),
    _r(r"\bconnectionString\s*=\s*[\"'][^\"']*\b(?:Encrypt|UseSSL|Use Encryption for Data)\s*=\s*(?:false|no|0)\b|\bconnectionString\s*=\s*[\"'][^\"']*\bSslMode\s*=\s*(?:none|disabled|preferred)\b", _TLS, "ado.net", algorithm="TLS-DISABLED", confidence="HIGH", confidence_reason="database connection without encryption"),
    _r(r"\bconnectionString\s*=\s*[\"'][^\"']*\bTrustServerCertificate\s*=\s*(?:true|yes)\b", _TLS, "ado.net", algorithm="TLS-UNVERIFIED", confidence="HIGH", confidence_reason="server certificate not validated"),
    _r(r"\bconnectionString\s*=\s*[\"'][^\"']*\b(?:Encrypt|UseSSL)\s*=\s*(?:true|yes|Mandatory|Strict)\b|\bconnectionString\s*=\s*[\"'][^\"']*\bSslMode\s*=\s*(?:Required|Require|VerifyCA|VerifyFull)\b", _TLS, "ado.net", algorithm="TLS", confidence="MEDIUM"),
    # ------------------------------------------------------------ Spring / Spring Security XML
    _r(r"<(?:security:|sec:|s:)?password-encoder\b[^>]*\bhash\s*=\s*[\"'](md5|md4|sha|sha-1|sha-256|sha256|plaintext|\{sha\}|\{ssha\})[\"']", _KDF, "spring-security", algo_from_group=1,
       algo_map={**_DIGEST, "plaintext": "PLAINTEXT", "{sha}": "SHA-1", "{ssha}": "SHA-1"}),
    _r(r"<(?:security:|sec:|s:)?password-encoder\b(?![^>]*\bhash\s*=)(?![^>]*\bref\s*=)", _KDF, "spring-security", algorithm="PLAINTEXT", confidence="MEDIUM", confidence_reason="legacy <password-encoder> without hash defaults to plaintext"),
    _r(r"\bclass\s*=\s*[\"']org\.springframework\.security\.(?:crypto\.bcrypt|crypto\.password|crypto\.scrypt|crypto\.argon2|authentication\.encoding)\.(\w+PasswordEncoder)[\"']", _KDF, "spring-security", algo_from_group=1,
       algo_map={"bcryptpasswordencoder": "BCRYPT", "pbkdf2passwordencoder": "PBKDF2", "scryptpasswordencoder": "SCRYPT", "argon2passwordencoder": "ARGON2", "standardpasswordencoder": "SHA-256", "nooppasswordencoder": "PLAINTEXT",
                 "ldapshapasswordencoder": "SHA-1", "messagedigestpasswordencoder": "UNKNOWN", "md4passwordencoder": "MD4", "md5passwordencoder": "MD5", "shapasswordencoder": "SHA-1", "plaintextpasswordencoder": "PLAINTEXT", "delegatingpasswordencoder": "BCRYPT"}),
    _r(r"MessageDigestPasswordEncoder[\"'][^\n]*>\s*<constructor-arg\b[^>]*\bvalue\s*=\s*[\"'](MD5|SHA-1|SHA-256|SHA-512|SHA)[\"']", _KDF, "spring-security", algo_from_group=1, algo_map=_DIGEST),
    _r(r"<(?:security:|sec:|s:)?remember-me\b", _M, "spring-security", algorithm="MD5", confidence="LOW", confidence_reason="TokenBasedRememberMeServices matching algorithm defaults to MD5 unless token-algorithm is set (SHA-256 encoding from 5.8+)"),
    _r(r"\bclass\s*=\s*[\"']org\.springframework\.security\.oauth2\.provider\.token\.store\.JwtAccessTokenConverter[\"']|\bclass\s*=\s*[\"']org\.springframework\.security\.oauth2\.jwt\.[^\"']+[\"']|<(?:security:|sec:)?jwt\b", _S, "spring-security", algorithm="JWT", confidence="MEDIUM"),
    _r(r"<(?:security:|sec:|s:)?(?:http|intercept-url)\b[^>]*\brequires-channel\s*=\s*[\"']https[\"']", _TLS, "spring-security", algorithm="TLS", confidence="MEDIUM"),
    _r(r"<(?:security:|sec:|s:)?(?:http|intercept-url)\b[^>]*\brequires-channel\s*=\s*[\"']http[\"']", _TLS, "spring-security", algorithm="TLS-CLEARTEXT", confidence="MEDIUM"),
    _r(r"<(?:security:|sec:|s:)?x509\b", _TLS, "spring-security", algorithm="X509", confidence="MEDIUM", confidence_reason="X.509 client-certificate authentication"),
    _r(r"\bclass\s*=\s*[\"']org\.jasypt\.[^\"']*(?:PBEStringEncryptor|PBEByteEncryptor|StringDigester)[\"']", _C, "jasypt", algorithm="PBKDF2", confidence="MEDIUM", confidence_reason="jasypt PBE (default PBEWithMD5AndDES)"),
    _r(r"<property\b[^>]*\bname\s*=\s*[\"']algorithm[\"'][^>]*\bvalue\s*=\s*[\"']PBEWith(MD5|SHA1|SHA256|HmacSHA256|HmacSHA512)And(?:Triple)?(DES|AES|DESede|RC2)(?:_\d+)?[\"']", _C, "jasypt", algo_from_group=2, algo_map=_CIPHER, emit_digest_group=1),
    _r(r"<property\b[^>]*\bname\s*=\s*[\"'](?:algorithm|hashAlgorithm|digestAlgorithm)[\"'][^>]*\bvalue\s*=\s*[\"'](MD5|SHA-1|SHA-256|SHA-512|SHA1|SHA256|SHA512)[\"']", _D, "spring-xml", algo_from_group=1, algo_map=_DIGEST),
    _r(r"<property\b[^>]*\bname\s*=\s*[\"'](?:cipherAlgorithm|transformation|cipher|encryptionAlgorithm)[\"'][^>]*\bvalue\s*=\s*[\"'](AES|DES|DESede|Blowfish|RC4|RC2|ChaCha20)(?:/[A-Za-z0-9]+/[A-Za-z0-9]+)?[\"']", _C, "spring-xml", algo_from_group=1, algo_map=_CIPHER),
    # ------------------------------------------------------------ Android
    _r(r"\bcleartextTrafficPermitted\s*=\s*[\"']true[\"']|\bandroid:usesCleartextTraffic\s*=\s*[\"']true[\"']", _TLS, "android", algorithm="TLS-CLEARTEXT", confidence="HIGH", confidence_reason="plaintext HTTP permitted"),
    _r(r"\bcleartextTrafficPermitted\s*=\s*[\"']false[\"']|\bandroid:usesCleartextTraffic\s*=\s*[\"']false[\"']", _TLS, "android", algorithm="TLS", confidence="MEDIUM"),
    _r(r"<certificates\b[^>]*\bsrc\s*=\s*[\"']user[\"']", _TLS, "android", algorithm="TRUST-ALL", confidence="MEDIUM", confidence_reason="user-installed CAs trusted (interception possible)"),
    _r(r"<certificates\b[^>]*\bsrc\s*=\s*[\"'](?:system|@raw/\w+)[\"']", _TLS, "android", algorithm="X509", confidence="MEDIUM"),
    _r(r"<pin\b[^>]*\bdigest\s*=\s*[\"'](SHA-256|SHA-1)[\"']", _D, "android", algo_from_group=1, algo_map=_DIGEST, confidence_reason="certificate pin digest"),
    _r(r"<pin-set\b", _TLS, "android", algorithm="X509", confidence="MEDIUM", confidence_reason="certificate pinning"),
    _r(r"\bandroid:networkSecurityConfig\s*=", _TLS, "android", algorithm="TLS", confidence="LOW"),
    # ------------------------------------------------------------ Tomcat / WildFly
    _r(r"<Connector\b[^>]*\b(?:sslEnabledProtocols|sslProtocols)\s*=\s*[\"']([^\"']+)[\"']|<SSLHostConfig\b[^>]*\bprotocols\s*=\s*[\"']([^\"']+)[\"']", _TLS, "tomcat", algorithm="TLS", confidence="MEDIUM", split_tls_group=1),
    _r(r"<Connector\b[^>]*\bsslProtocol\s*=\s*[\"'](TLSv1\.3|TLSv1\.2|TLSv1\.1|TLSv1|TLS|SSLv3|SSL)[\"']", _TLS, "tomcat", algo_from_group=1, algo_map={**_PROTO, "tls": "TLS", "ssl": "SSLv3"}),
    _r(r"<(?:Connector|SSLHostConfig)\b[^>]*\bciphers\s*=\s*[\"']([^\"']+)[\"']", _TLS, "tomcat", algorithm="TLS-CIPHERS", confidence="MEDIUM", raw_group=1),
    _r(r"<Connector\b[^>]*\bSSLEnabled\s*=\s*[\"']true[\"']|<SSLHostConfig\b|<Certificate\b[^>]*\bcertificateKeystoreFile", _TLS, "tomcat", algorithm="TLS", confidence="MEDIUM"),
    _r(r"\b(?:keystoreType|truststoreType|certificateKeystoreType)\s*=\s*[\"'](?:JKS|PKCS12|BKS|JCEKS)[\"']|\b(?:keystoreFile|certificateKeystoreFile|truststoreFile|certificateFile)\s*=", _TLS, "tomcat", algorithm="X509", confidence="MEDIUM"),
    _r(r"<Realm\b[^>]*\bdigest\s*=\s*[\"'](MD5|SHA|SHA-1|SHA-256|SHA-512)[\"']|<CredentialHandler\b[^>]*\balgorithm\s*=\s*[\"'](MD5|SHA-1|SHA-256|SHA-512|PBKDF2WithHmacSHA1|PBKDF2WithHmacSHA512)[\"']", _KDF, "tomcat", algo_from_group=1,
       algo_map={**_DIGEST, "pbkdf2withhmacsha1": "PBKDF2", "pbkdf2withhmacsha512": "PBKDF2"}),
    _r(r"<CredentialHandler\b[^>]*SecretKeyCredentialHandler", _KDF, "tomcat", algorithm="PBKDF2", confidence="MEDIUM", confidence_reason="Tomcat SecretKeyCredentialHandler default PBKDF2WithHmacSHA512"),
    _r(r"<https-listener\b|<ssl-context\b|<server-ssl-context\b|<key-store\b[^>]*\bpath\s*=|<key-manager\b|<trust-manager\b", _TLS, "wildfly", algorithm="TLS", confidence="MEDIUM"),
    _r(r"<(?:server-ssl-context|client-ssl-context|ssl-context)\b[^>]*\bprotocols\s*=\s*[\"']([^\"']+)[\"']", _TLS, "wildfly", algorithm="TLS", confidence="MEDIUM", split_tls_group=1),
    _r(r"<(?:server-ssl-context|client-ssl-context|ssl-context)\b[^>]*\bcipher-suite-filter\s*=\s*[\"']([^\"']+)[\"']", _TLS, "wildfly", algorithm="TLS-CIPHERS", confidence="MEDIUM", raw_group=1),
    _r(r"<(?:mapper|simple-digest-mapper|salted-simple-digest-mapper|scram-mapper)\b[^>]*\balgorithm\s*=\s*[\"'](?:simple-digest-|salted-simple-digest-|scram-)?(md5|sha-1|sha-256|sha-384|sha-512|bcrypt)[\"']", _KDF, "wildfly-elytron", algo_from_group=1, algo_map={**_DIGEST, "bcrypt": "BCRYPT"}),
    _r(r"<bcrypt-mapper\b", _KDF, "wildfly-elytron", algorithm="BCRYPT"),
    _r(r"<clear-password\b[^>]*\bpassword\s*=|<clear-text\b|<plain-text\b", _KDF, "wildfly", algorithm="PLAINTEXT", confidence="MEDIUM", confidence_reason="cleartext credential in config"),
    # ------------------------------------------------------------ Bank middleware: WebSphere / Liberty / WebLogic / MQ / Mule / Camel
    _r(r"<(?:repertoire|SSLConfig|ssl|setting|secureSocketLayer)\b[^>]*\bsslProtocol\s*=\s*[\"']([^\"']+)[\"']", _TLS, "websphere", algorithm="TLS", confidence="HIGH", split_tls_group=1),
    _r(r"<(?:repertoire|SSLConfig|ssl|setting|secureSocketLayer)\b[^>]*\benabledCiphers\s*=\s*[\"']([^\"']+)[\"']", _TLS, "websphere", algorithm="TLS-CIPHERS", confidence="MEDIUM", raw_group=1),
    _r(r"<(?:repertoire|SSLConfig|setting)\b[^>]*\bsecurityLevel\s*=\s*[\"'](HIGH|MEDIUM|LOW|CUSTOM)[\"']", _TLS, "websphere", algorithm="TLS", confidence="MEDIUM", confidence_reason="WAS SSL repertoire security level"),
    _r(r"<(?:keyStores|keyStore|trustStore)\b[^>]*\btype\s*=\s*[\"'](PKCS12|JKS|JCEKS|CMSKS|PKCS11|PKCS11IMPLKS|JCERACFKS|JCECCARACFKS|JCEHYBRIDRACFKS)[\"']", _TLS, "websphere", algo_from_group=1,
       algo_map={"pkcs12": "X509", "jks": "X509", "jceks": "X509", "cmsks": "X509", "pkcs11": "UNKNOWN", "pkcs11implks": "UNKNOWN", "jceracfks": "X509", "jcecacfks": "X509", "jceccaracfks": "UNKNOWN", "jcehybridracfks": "UNKNOWN"}, confidence="MEDIUM", confidence_reason="WebSphere keystore (RACF / PKCS#11 types are hardware-backed)"),
    _r(r"<keyStore\b[^>]*\blocation\s*=\s*[\"']safkeyring(?:hw|hybrid)?://", _TLS, "websphere-zos", algorithm="X509", confidence="MEDIUM", confidence_reason="z/OS RACF key ring"),
    _r(r"<(?:ssl|sslDefault|httpEndpoint)\b[^>]*\bsslRef\s*=|<ssl\b[^>]*\bid\s*=|<sslDefault\b|<transportSecurity\b|<httpEndpoint\b[^>]*\bhttpsPort\s*=", _TLS, "websphere-liberty", algorithm="TLS", confidence="MEDIUM"),
    _r(r"<ssl\b[^>]*\b(?:clientAuthentication|clientAuthenticationSupported)\s*=\s*[\"']true[\"']", _TLS, "websphere-liberty", algorithm="X509", confidence="MEDIUM", confidence_reason="mutual TLS"),
    _r(r"<ssl\b[^>]*\btrustDefaultCerts\s*=\s*[\"']true[\"']|<ssl\b[^>]*\bverifyHostname\s*=\s*[\"']false[\"']", _TLS, "websphere-liberty", algorithm="TLS-UNVERIFIED", confidence="MEDIUM"),
    _r(r"<ltpa\b|<ltpaKeys\b|com\.ibm\.websphere\.security\.ltpa", _C, "websphere-ltpa", algorithm="3DES", confidence="MEDIUM", confidence_reason="LTPA token keys (3DES-encrypted LTPA key file, RSA signed)"),
    _r(r"<(?:hashAlgorithm|hashalgorithm)>\s*(PBKDF2WithHmacSHA1|PBKDF2WithHmacSHA256|PBKDF2WithHmacSHA512|SHA-1|SHA-256|SHA-512|MD5)\s*<|\bhashAlgorithm\s*=\s*[\"'](PBKDF2WithHmacSHA1|PBKDF2WithHmacSHA256|PBKDF2WithHmacSHA512|SHA-1|SHA-256|SHA-512|MD5)[\"']", _KDF, "websphere-liberty", algo_from_group=1,
       algo_map={**_DIGEST, "pbkdf2withhmacsha1": "PBKDF2", "pbkdf2withhmacsha256": "PBKDF2", "pbkdf2withhmacsha512": "PBKDF2"}),
    _r(r"<(?:security-custom-properties|property)\b[^>]*\bname\s*=\s*[\"']com\.ibm\.websphere\.tls\.disabledAlgorithms[\"']|\bcom\.ibm\.ws\.security\.[a-z.]*(?:crypto|ssl)\.\w+\s*=", _TLS, "websphere", algorithm="TLS-CIPHERS", confidence="LOW", raw_group=0),
    _r(r"<encrypt(?:ionKey|ionAlgorithm|Key)\b[^>]*>|<properties\b[^>]*\bencryption\s*=\s*[\"'](?:AES|3DES|DESede)[\"']|<(?:cipher|cipherName)>\s*(AES|DESede|DES|3DES|RC4|Blowfish)\s*<", _C, "xml-config", algo_from_group=1, algo_map=_CIPHER, confidence="MEDIUM"),
    # WebLogic config.xml
    _r(r"<minimum-tls-protocol-version>\s*(TLSv1\.3|TLSv1\.2|TLSv1\.1|TLSv1|SSLv3)\s*<", _TLS, "weblogic", algo_from_group=1, algo_map=_PROTO),
    _r(r"<ssl>\s*(?:<[^>]*>\s*)*?<enabled>\s*true\s*</enabled>|<listen-port-enabled>\s*false\s*</listen-port-enabled>|<ssl-listen-port>|<two-way-ssl-enabled>\s*true|<client-certificate-enforced>\s*true", _TLS, "weblogic", algorithm="TLS", confidence="MEDIUM"),
    _r(r"<ciphersuite>\s*([A-Z0-9_]+)\s*</ciphersuite>", _TLS, "weblogic", algorithm="TLS-CIPHERS", confidence="MEDIUM", raw_group=1),
    _r(r"<hostname-verification-ignored>\s*true\s*<|<hostname-verifier-ignored>\s*true\s*<|<allow-unencrypted-null-cipher>\s*true\s*<|<use-server-certs>\s*false", _TLS, "weblogic", algorithm="TLS-UNVERIFIED", confidence="HIGH"),
    _r(r"<(?:custom-identity-key-?store-type|custom-trust-key-?store-type|key-?store-type|trust-key-?store-type)>\s*(JKS|PKCS12|KSS|JCEKS|PKCS11|OracleWallet|CustomTrust|DemoTrust|JavaStandardTrust)\s*<|<key-?stores>\s*(?:CustomIdentityAndCustomTrust|CustomIdentityAndJavaStandardTrust|DemoIdentityAndDemoTrust)\s*<", _TLS, "weblogic", algorithm="X509", confidence="MEDIUM"),
    _r(r"<keystores>\s*DemoIdentityAndDemoTrust\s*<|DemoIdentity\.jks|DemoTrust\.jks", _TLS, "weblogic", algorithm="TLS-UNVERIFIED", confidence="HIGH", confidence_reason="WebLogic demo identity/trust keystores in configuration"),
    _r(r"<[a-z-]*(?:credential|password|pass-phrase)-encrypted>\s*\{AES\}|<credential>\s*\{AES\}", _C, "weblogic", algorithm="AES", confidence="HIGH", confidence_reason="WebLogic SerializedSystemIni-encrypted credential"),
    _r(r"<[a-z-]*(?:credential|password|pass-phrase)-encrypted>\s*\{3DES\}", _C, "weblogic", algorithm="3DES", confidence="HIGH", confidence_reason="legacy WebLogic 3DES-encrypted credential"),
    _r(r"<[a-z-]*(?:credential|password|pass-phrase)-encrypted>\s*\{AES256\}", _C, "weblogic", algorithm="AES", key_size=256, confidence="HIGH"),
    # IBM MQ JMS / activation spec / resource adapter XML
    _r(r"<(?:property|config-property|attribute)\b[^>]*\bname\s*=\s*[\"'](?:sslCipherSuite|SSLCipherSuite|sslCipherSpec|SSLCIPH|cipherSuite)[\"'][^>]*\bvalue\s*=\s*[\"']([A-Za-z0-9_]+)[\"']|<(?:sslCipherSuite|sslCipherSpec|SSLCipherSuite)>\s*([A-Za-z0-9_]+)\s*<|<config-property-name>\s*sslCipherSuite\s*</config-property-name>\s*(?:<config-property-type>[^<]*</config-property-type>\s*)?<config-property-value>\s*([A-Za-z0-9_]+)\s*<", _TLS, "ibm-mq-jms", algorithm="TLS", confidence="HIGH", split_suite_group=1),
    _r(r"<(?:property|config-property|attribute)\b[^>]*\bname\s*=\s*[\"'](?:sslFipsRequired|sslPeerName|sslKeyResetCount|sslCertStores|sslResetCount)[\"']|<(?:sslFipsRequired|sslPeerName|sslCertStores)>", _TLS, "ibm-mq-jms", algorithm="TLS", confidence="MEDIUM"),
    _r(r"<(?:mq(?:Queue)?ConnectionFactory|properties\.wmqJms|properties\.wmqJmsClient\.[A-Za-z]+|wmqJmsClient|jmsConnectionFactory|jmsQueueConnectionFactory)\b[^>]*\bsslCipherSuite\s*=\s*[\"']([A-Za-z0-9_]+)[\"']|<jmsConnectionFactory\b[^>]*>|<wmqJmsClient\b|<resourceAdapter\b[^>]*wmq", _TLS, "ibm-mq-jms", algorithm="TLS", confidence="LOW", split_suite_group=1),
    # Mule
    _r(r"<tls:context\b|<tls:key-store\b|<tls:trust-store\b|<https:listener-config\b|<https:request-config\b", _TLS, "mule", algorithm="TLS", confidence="MEDIUM"),
    _r(r"<tls:context\b[^>]*\benabledProtocols\s*=\s*[\"']([^\"']+)[\"']", _TLS, "mule", algorithm="TLS", split_tls_group=1),
    _r(r"<tls:context\b[^>]*\benabledCipherSuites\s*=\s*[\"']([^\"']+)[\"']", _TLS, "mule", algorithm="TLS-CIPHERS", confidence="MEDIUM", raw_group=1),
    _r(r"<tls:(?:key-store|trust-store)\b[^>]*\btype\s*=\s*[\"'](jks|pkcs12|jceks)[\"']|<tls:(?:key-store|trust-store)\b[^>]*\bpath\s*=", _TLS, "mule", algorithm="X509", confidence="MEDIUM"),
    _r(r"<tls:trust-store\b[^>]*\binsecure\s*=\s*[\"']true[\"']", _TLS, "mule", algorithm="TRUST-ALL", confidence="HIGH", confidence_reason="Mule insecure trust store — certificate validation disabled"),
    _r(r"<tls:key-store\b[^>]*\balgorithm\s*=\s*[\"'](RSA|EC|DSA)[\"']", _TLS, "mule", algo_from_group=1, algo_map={"rsa": "RSA", "ec": "ECDSA", "dsa": "DSA"}),
    _r(r"<crypto:jce-(?:encrypt|decrypt|sign|validate)(?:-pbe)?\b[^>]*\balgorithm\s*=\s*[\"']([A-Za-z0-9_/-]+)[\"']|<crypto:jce-(?:sign|validate)\b[^>]*\balgorithm\s*=\s*[\"']([A-Za-z0-9]+)[\"']", _C, "mule-crypto", algo_from_group=1, algo_map={**_CIPHER, "hmacsha256": "HMAC-SHA256", "hmacsha1": "HMAC-SHA1", "hmacsha512": "HMAC-SHA512", "sha256withrsa": "RSA", "sha1withrsa": "RSA", "sha256withecdsa": "ECDSA", "pbewithhmacsha256andaes_128": "PBKDF2", "pbewithhmacsha256andaes_256": "PBKDF2", "pbewithmd5anddes": "DES", "aes_cbc": "AES", "aes_gcm": "AES", "aes_ecb": "AES", "des_cbc": "DES", "desede_cbc": "3DES", "rsa_ecb": "RSA", "rsa_ecb_oaep": "RSA", "blowfish_cbc": "Blowfish", "rc4": "RC4"}),
    _r(r"<crypto:jce-(?:encrypt|decrypt)(?:-pbe)?\b(?![^>]*\balgorithm\s*=)", _C, "mule-crypto", algorithm="AES", confidence="MEDIUM", confidence_reason="Mule JCE default AES_CBC"),
    _r(r"<crypto:jce-(?:sign|validate)\b(?![^>]*\balgorithm\s*=)", _M, "mule-crypto", algorithm="HMAC-SHA256", confidence="MEDIUM", confidence_reason="Mule JCE default HmacSHA256"),
    _r(r"<crypto:pgp-(?:encrypt|decrypt|sign|validate|config)\b|<pgp:(?:encrypt|decrypt|config)\b", _C, "mule-crypto", algorithm="PGP", confidence="HIGH"),
    _r(r"<crypto:xml-(?:encrypt|decrypt)\b[^>]*\balgorithm\s*=\s*[\"'](AES_128|AES_192|AES_256|TRIPLEDES|AES_128_GCM|AES_192_GCM|AES_256_GCM)[\"']", _C, "mule-crypto", algo_from_group=1, algo_map={"aes_128": "AES", "aes_192": "AES", "aes_256": "AES", "tripledes": "3DES", "aes_128_gcm": "AES", "aes_192_gcm": "AES", "aes_256_gcm": "AES"}),
    _r(r"<crypto:jce-key-info\b[^>]*\bkeyId\s*=|<crypto:jce-config\b|<crypto:jce-keystore\b|<secure-property-placeholder:config\b[^>]*\bencryptionAlgorithm\s*=\s*[\"']([A-Za-z0-9]+)[\"']|<secure-properties:config\b[^>]*\balgorithm\s*=\s*[\"']([A-Za-z0-9]+)[\"']", _C, "mule-secure-properties", algo_from_group=1, algo_map={**_CIPHER, "blowfish": "Blowfish", "rc2": "RC2", "rsa": "RSA"}, confidence="MEDIUM"),
    _r(r"<secure-properties:config\b(?![^>]*\balgorithm\s*=)|<secure-property-placeholder:config\b(?![^>]*\bencryptionAlgorithm\s*=)", _C, "mule-secure-properties", algorithm="AES", confidence="MEDIUM", confidence_reason="Mule secure properties default AES/CBC"),
    _r(r"<jms:(?:active-mq-connection|connection)\b[^>]*\buseSsl\s*=\s*[\"']true|<ibm-mq:connection\b|<ibm-mq:config\b", _TLS, "mule", algorithm="TLS", confidence="LOW"),
    _r(r"<ibm-mq:connection\b[^>]*\bcipherSuite\s*=\s*[\"']([A-Za-z0-9_]+)[\"']", _TLS, "mule-ibm-mq", algorithm="TLS", split_suite_group=1),
    # Apache Camel XML DSL
    _r(r"<(?:camel:)?sslContextParameters\b[^>]*\bsecureSocketProtocol\s*=\s*[\"']([^\"']+)[\"']|<(?:camel:)?secureSocketProtocol>\s*([A-Za-z0-9.]+)\s*<", _TLS, "camel", algorithm="TLS", split_tls_group=1),
    _r(r"<(?:camel:)?sslContextParameters\b|<(?:camel:)?keyManagers\b|<(?:camel:)?trustManagers\b|<(?:camel:)?keyStore\b[^>]*\bresource\s*=", _TLS, "camel", algorithm="TLS", confidence="MEDIUM"),
    _r(r"<(?:camel:)?secureSocketProtocols>\s*(?:<(?:camel:)?secureSocketProtocol>\s*([A-Za-z0-9.]+)\s*</(?:camel:)?secureSocketProtocol>\s*)+", _TLS, "camel", algorithm="TLS", split_tls_group=0),
    _r(r"<(?:camel:)?cipherSuitesFilter\b|<(?:camel:)?cipherSuites>", _TLS, "camel", algorithm="TLS-CIPHERS", confidence="MEDIUM"),
    _r(r"<(?:camel:)?keyStore\b[^>]*\btype\s*=\s*[\"'](JKS|PKCS12|JCEKS|BKS)[\"']|<(?:camel:)?keyManagers\b[^>]*\bkeyPassword\s*=", _TLS, "camel", algorithm="X509", confidence="MEDIUM"),
    _r(r"<(?:camel:)?(?:crypto|secureXML)\b(?!:)[^>]*\balgorithm\s*=\s*[\"']([A-Za-z0-9_-]+)(?:/[A-Za-z0-9_/-]+)?[\"']", _C, "camel-crypto", algo_from_group=1, algo_map=_CIPHER),
    _r(r"<(?:camel:)?crypto\b(?!:)(?![^>]*\balgorithm\s*=)[^>]*\b(?:keyRef|key)\s*=", _C, "camel-crypto", algorithm="DES", confidence="MEDIUM", confidence_reason="Camel crypto data format default DES/CBC/PKCS5Padding"),
    _r(r"<(?:camel:)?secureXML\b[^>]*\bxmlCipherAlgorithm\s*=\s*[\"'][^\"']*#(aes128-cbc|aes192-cbc|aes256-cbc|aes128-gcm|aes256-gcm|tripledes-cbc)[\"']", _C, "camel-secureXML", algo_from_group=1, algo_map={"aes128-cbc": "AES", "aes192-cbc": "AES", "aes256-cbc": "AES", "aes128-gcm": "AES", "aes256-gcm": "AES", "tripledes-cbc": "3DES"}),
    _r(r"<(?:camel:)?secureXML\b(?![^>]*\bxmlCipherAlgorithm\s*=)", _C, "camel-secureXML", algorithm="3DES", confidence="MEDIUM", confidence_reason="Camel XML security default TRIPLEDES"),
    _r(r"<(?:camel:)?pgp\b[^>]*\bkeyFileName\s*=|<(?:camel:)?pgp\b[^>]*\bkeyUserid\s*=", _C, "camel-pgp", algorithm="PGP", confidence="HIGH"),
    _r(r"<(?:camel:)?pgp\b[^>]*\balgorithm\s*=\s*[\"'](\d+)[\"']", _C, "camel-pgp", algo_from_group=1, algo_map={"1": "IDEA", "2": "3DES", "3": "CAST5", "4": "Blowfish", "7": "AES", "8": "AES", "9": "AES", "10": "Twofish", "11": "Camellia", "12": "Camellia", "13": "Camellia"}),
    _r(r"<(?:camel:)?pgp\b[^>]*\bhashAlgorithm\s*=\s*[\"'](\d+)[\"']", _D, "camel-pgp", algo_from_group=1, algo_map={"1": "MD5", "2": "SHA-1", "3": "RIPEMD-160", "8": "SHA-256", "9": "SHA-384", "10": "SHA-512", "11": "SHA-224"}),
    _r(r"<(?:camel:)?(?:xmlSecurity|xmlsecurity)\b|xmlsecurity(?:-sign|-verify)?:|<(?:camel:)?xmlSignature\b", _S, "camel-xmlsecurity", algorithm="X509", confidence="MEDIUM"),
    _r(r"\bsignatureAlgorithm\s*=\s*[\"']" + _XMLDSIG_URI + r"[\"']|\bdigestAlgorithm\s*=\s*[\"']" + _XMLDSIG_URI + r"[\"']", _S, "camel-xmlsecurity", algo_from_group=1, algo_map={k: v[0] for k, v in _XMLDSIG.items()}, xmldsig_digest=True),
    _r(r"\bhttps?://[^\"'<\s]*\?[^\"'<\s]*sslContextParameters(?:Ref)?=#|\b(?:netty|jetty|undertow|http4?|https4?|ftps|sftp|mina2?|cxf|smtps|imaps|kafka|amqp|mqtt|websocket|wss):[^\"'<\s]*[?&]sslContextParameters=", _TLS, "camel", algorithm="TLS", confidence="MEDIUM"),
    _r(r"\bsftp://|\bscp://", _TLS, "camel", algorithm="SSH", confidence="MEDIUM"),
    _r(r"[?&](?:sslKeystore|sslKeyStore|keyStoreFile|sslTruststore|trustStoreFile)=", _TLS, "camel", algorithm="X509", confidence="MEDIUM"),
    _r(r"[?&](?:sslProtocol|sslProtocols|securityProtocol)=([A-Za-z0-9.,]+)", _TLS, "camel", algorithm="TLS", split_tls_group=1),
    _r(r"[?&](?:trustAllCertificates|trustAll|disableHostnameVerification|ignoreHostnameVerification|skipCertificateCheck)=true|[?&](?:hostnameVerification|verifyHostname|verifyHostName)=false", _TLS, "camel", algorithm="TRUST-ALL", confidence="HIGH"),
    _r(r"<(?:camel:)?jasypt\b|<jasypt:encryptor\b|EncryptableProperties|<bean\b[^>]*\bclass\s*=\s*[\"']org\.jasypt\.[^\"']*(?:StandardPBEStringEncryptor|BasicTextEncryptor|StrongTextEncryptor|AES256TextEncryptor|StandardPBEByteEncryptor|PooledPBEStringEncryptor)[\"']", _C, "jasypt", algorithm="DES", confidence="MEDIUM", confidence_reason="jasypt default PBEWithMD5AndDES unless algorithm is set"),
    _r(r"\bclass\s*=\s*[\"']org\.jasypt\.[^\"']*AES256TextEncryptor[\"']|<property\b[^>]*\bname\s*=\s*[\"']algorithm[\"'][^>]*\bvalue\s*=\s*[\"'](PBEWITHHMACSHA512ANDAES_256|PBEWITHHMACSHA256ANDAES_128|PBEWithHMACSHA512AndAES_256|PBEWithHmacSHA256AndAES_128|PBEWithMD5AndTripleDES|PBEWithSHA1AndDESede|PBEWithMD5AndDES|PBEWithSHA1AndRC2_40|PBEWithSHA1AndRC4_128)[\"']", _C, "jasypt", algo_from_group=1,
       algo_map={"pbewithhmacsha512andaes_256": "AES", "pbewithhmacsha256andaes_128": "AES", "pbewithmd5andtripledes": "3DES", "pbewithsha1anddesede": "3DES", "pbewithmd5anddes": "DES", "pbewithsha1andrc2_40": "RC2", "pbewithsha1andrc4_128": "RC4"}),
    _r(r"<property\b[^>]*\bname\s*=\s*[\"'](?:algorithm|encryptionAlgorithm|jasypt\.encryptor\.algorithm)[\"'][^>]*\bvalue\s*=\s*[\"']PBEWith(?:HMAC|Hmac)(SHA512|SHA256|SHA1|MD5)And", _D, "jasypt", algo_from_group=1, algo_map=_DIGEST),
    _r(r"\bclass\s*=\s*[\"']org\.jasypt\.[^\"']*(?:StrongPasswordEncryptor|BasicPasswordEncryptor|ConfigurablePasswordEncryptor|StandardStringDigester)[\"']", _KDF, "jasypt", algorithm="SHA-256", confidence="MEDIUM", confidence_reason="jasypt digester default (MD5 basic / SHA-256 strong)"),
    # WSO2 / Axis2 / Rampart / CXF WS-Security & JAX-WS
    _r(r"<rampart:algorithmSuite>\s*(Basic128|Basic192|Basic256|TripleDes)(?:Rsa15|Sha256|Sha256Rsa15)?\s*<|<rampart:encryptionUser>|<rampart:signatureCrypto>|<rampart:encryptionCrypto>", _C, "rampart", algo_from_group=1, algo_map={"basic128": "AES", "basic192": "AES", "basic256": "AES", "tripledes": "3DES"}, confidence="MEDIUM"),
    _r(r"<(?:jaxws|cxf):properties>\s*(?:<[^>]*>\s*)*?<entry\b[^>]*\bkey\s*=\s*[\"'](?:security|ws-security)\.(?:signature|encryption)\.(?:properties|username|crypto\.merlin)", _S, "cxf-wss4j", algorithm="X509", confidence="MEDIUM"),
    _r(r"\bkey\s*=\s*[\"'](?:security|ws-security)\.(?:signature|encryption|asymmetric\.signature|symmetric\.signature|asymmetric\.encryption)\.algorithm[\"'][^>]*\bvalue\s*=\s*[\"']" + _XMLDSIG_URI + r"[\"']", _S, "cxf-wss4j", algo_from_group=1, algo_map={k: v[0] for k, v in _XMLDSIG.items()}, xmldsig_digest=True),
    _r(r"\bkey\s*=\s*[\"'](?:security|ws-security)\.password\.type[\"'][^>]*\bvalue\s*=\s*[\"']PasswordDigest[\"']", _D, "cxf-wss4j", algorithm="SHA-1", confidence="HIGH", confidence_reason="WS-Security UsernameToken PasswordDigest is SHA-1"),
    _r(r"\bkey\s*=\s*[\"'](?:security|ws-security)\.password\.type[\"'][^>]*\bvalue\s*=\s*[\"']PasswordText[\"']", _KDF, "cxf-wss4j", algorithm="PLAINTEXT", confidence="HIGH"),
    _r(r"<(?:http|httpj):tlsClientParameters\b|<(?:http|httpj):tlsServerParameters\b|<sec:keyManagers\b|<sec:trustManagers\b", _TLS, "cxf", algorithm="TLS", confidence="MEDIUM"),
    _r(r"<(?:http|httpj):tlsClientParameters\b[^>]*\bsecureSocketProtocol\s*=\s*[\"']([^\"']+)[\"']|<(?:http|httpj):tlsServerParameters\b[^>]*\bsecureSocketProtocol\s*=\s*[\"']([^\"']+)[\"']", _TLS, "cxf", algorithm="TLS", split_tls_group=1),
    _r(r"<(?:http|httpj):tlsClientParameters\b[^>]*\bdisableCNCheck\s*=\s*[\"']true[\"']", _TLS, "cxf", algorithm="TLS-UNVERIFIED", confidence="HIGH"),
    _r(r"<sec:keyStore\b[^>]*\btype\s*=\s*[\"'](JKS|PKCS12|JCEKS)[\"']|<sec:keyStore\b[^>]*\bfile\s*=", _TLS, "cxf", algorithm="X509", confidence="MEDIUM"),
    _r(r"<sec:cipherSuitesFilter\b|<sec:cipherSuites\b", _TLS, "cxf", algorithm="TLS-CIPHERS", confidence="MEDIUM"),
    _r(r"<transportSender\b[^>]*\bname\s*=\s*[\"']https[\"']|<transportReceiver\b[^>]*\bname\s*=\s*[\"']https[\"']", _TLS, "axis2", algorithm="TLS", confidence="MEDIUM"),
    _r(r"<parameter\b[^>]*\bname\s*=\s*[\"'](?:HttpsProtocols|SSLProtocol|Protocol)[\"'][^>]*>\s*([A-Za-z0-9.,]+)\s*<", _TLS, "axis2", algorithm="TLS", split_tls_group=1),
    _r(r"<parameter\b[^>]*\bname\s*=\s*[\"'](?:PreferredCiphers|SSLCipherSuites|CipherSuites)[\"'][^>]*>\s*([A-Za-z0-9_,\s]+)\s*<", _TLS, "axis2", algorithm="TLS-CIPHERS", confidence="MEDIUM", raw_group=1),
    _r(r"<(?:KeyStore|TrustStore|PrivateKeyStore)>\s*(?:<[^>]*>\s*)*?<Type>\s*(JKS|PKCS12|JCEKS)\s*</Type>", _TLS, "wso2-carbon", algorithm="X509", confidence="MEDIUM"),
    _r(r"<InternalKeyStore>|<KeyStore>\s*(?:<[^>]*>\s*)*?<Location>|<Security>\s*(?:<[^>]*>\s*)*?<KeyStore>", _TLS, "wso2-carbon", algorithm="X509", confidence="LOW"),
    _r(r"<(?:PasswordDigest|Digest)>\s*(SHA-256|SHA-512|SHA-1|SHA|MD5|PLAIN_TEXT|PBKDF2)\s*<|<PasswordDigest>\s*(SHA-256|SHA-1|MD5)", _KDF, "wso2-carbon", algo_from_group=1, algo_map={**_DIGEST, "plain_text": "PLAINTEXT", "pbkdf2": "PBKDF2"}),
    _r(r"<Property\b[^>]*\bname\s*=\s*[\"']PasswordDigest[\"'][^>]*>\s*(SHA-256|SHA-512|SHA-1|SHA|MD5|PLAIN_TEXT|PBKDF2)\s*<", _KDF, "wso2-carbon", algo_from_group=1, algo_map={**_DIGEST, "plain_text": "PLAINTEXT", "pbkdf2": "PBKDF2"}),
    _r(r"<TokenEncryption>|<Encryption>\s*(?:<[^>]*>\s*)*?<Algorithm>\s*([A-Za-z0-9/_-]+)\s*<|<KeyStore\b[^>]*\bAlgorithm\s*=", _C, "wso2-carbon", algo_from_group=1, algo_map={**_CIPHER, "rsa": "RSA", "rsa/ecb/oaepwithsha1andmgf1padding": "RSA", "rsa/ecb/pkcs1padding": "RSA"}, confidence="MEDIUM"),
    _r(r"<(?:SymmetricEncryption|InternalEncryption)>\s*(?:<[^>]*>\s*)*?<Algorithm>\s*(AES|DES|DESede|AES/GCM/NoPadding)\s*<", _C, "wso2-carbon", algo_from_group=1, algo_map=_CIPHER),
    _r(r"<DefaultAlgorithm>\s*(AES|DES|DESede|AES/GCM/NoPadding|AES/CBC/PKCS5Padding|RSA)\s*<|<Algorithm>\s*(AES/GCM/NoPadding|RSA/ECB/OAEPwithSHA1andMGF1Padding|RSA/ECB/PKCS1Padding)\s*<", _C, "wso2-carbon", algo_from_group=1, algo_map={**_CIPHER, "rsa": "RSA", "rsa/ecb/oaepwithsha1andmgf1padding": "RSA", "rsa/ecb/pkcs1padding": "RSA"}),
    _r(r"<(?:SignatureAlgorithm|DigestAlgorithm|ResponseSigningAlgorithm|AssertionEncryptionAlgorithm|KeyEncryptionAlgorithm)>\s*" + _XMLDSIG_URI + r"\s*<", _S, "wso2-identity", algo_from_group=1, algo_map={k: v[0] for k, v in _XMLDSIG.items()}, xmldsig_digest=True),
    _r(r"<(?:OAuth|OpenIDConnect)>\s*(?:<[^>]*>\s*)*?<(?:IDTokenSignatureAlgorithm|SignatureAlgorithm|TokenSignatureAlgorithm|UserInfoJWTSignatureAlgorithm)>\s*(RS256|RS384|RS512|PS256|ES256|ES384|HS256|HS384|HS512|SHA256withRSA|SHA512withRSA|SHA256withEC|NONE)\s*<|<(?:IDTokenSignatureAlgorithm|TokenSignatureAlgorithm|SignatureAlgorithm)>\s*(SHA256withRSA|SHA512withRSA|SHA1withRSA|SHA256withEC|NONE)\s*<", _S, "wso2-identity", algo_from_group=1,
       algo_map={**_JWT, "sha256withrsa": "RSA", "sha512withrsa": "RSA", "sha1withrsa": "RSA", "sha256withec": "ECDSA", "none": "JWT"}),
    _r(r"<(?:HashingAlgorithm|hashAlgorithm|HashAlgorithm|hash_algorithm)>\s*(SHA-256|SHA-512|SHA-1|SHA1|SHA256|SHA512|MD5|BCRYPT|bcrypt|PBKDF2|argon2|scrypt)\s*<", _KDF, "xml-config", algo_from_group=1, algo_map={**_DIGEST, "bcrypt": "BCRYPT", "pbkdf2": "PBKDF2", "argon2": "ARGON2", "scrypt": "SCRYPT"}),
    # ------------------------------------------------------------ JDBC URLs
    _r(r"\bjdbc:(?:mysql|mariadb):[^\"'<\s]*[?&](?:useSSL=false|sslMode=DISABLED|useSsl=false)\b|\bjdbc:postgresql:[^\"'<\s]*[?&]ssl(?:mode)?=(?:false|disable|allow)\b|\bjdbc:sqlserver:[^\"'<\s]*;encrypt=false\b", _TLS, "jdbc", algorithm="TLS-DISABLED", confidence="HIGH", confidence_reason="JDBC connection without TLS"),
    _r(r"\bjdbc:(?:mysql|mariadb):[^\"'<\s]*[?&](?:useSSL=true|sslMode=(?:REQUIRED|VERIFY_CA|VERIFY_IDENTITY))\b|\bjdbc:postgresql:[^\"'<\s]*[?&]ssl(?:mode)?=(?:true|require|verify-ca|verify-full)\b|\bjdbc:sqlserver:[^\"'<\s]*;encrypt=(?:true|strict)\b", _TLS, "jdbc", algorithm="TLS", confidence="MEDIUM"),
    _r(r"\bjdbc:[a-z]+:[^\"'<\s]*[?&;](?:trustServerCertificate=true|verifyServerCertificate=false|sslMode=PREFERRED|sslmode=prefer)\b", _TLS, "jdbc", algorithm="TLS-UNVERIFIED", confidence="HIGH"),
    # ------------------------------------------------------------ dependency manifests
    _r(r"<artifactId>\s*(" + "|".join(re.escape(k) for k in sorted(_MAVEN_DEPS, key=len, reverse=True)) + r")\s*</artifactId>", _DEP, "maven", algo_from_group=1, algo_map=_MAVEN_DEPS, confidence="LOW", confidence_reason="crypto library dependency"),
    _r(r"<(?:package|PackageReference|Reference|PackageVersion)\b[^>]*\b(?:id|Include)\s*=\s*[\"'](" + "|".join(re.escape(k) for k in sorted(_NUGET_DEPS, key=len, reverse=True)) + r")[\"']", _DEP, "nuget", algo_from_group=1, algo_map=_NUGET_DEPS, confidence="LOW", confidence_reason="crypto library dependency"),
    # ------------------------------------------------------------ XML-DSig / XML-Enc / WS-Security / SAML
    _r(r"\bAlgorithm\s*=\s*[\"']" + _XMLDSIG_URI + r"[\"']", _S, "xml-dsig", algo_from_group=1, algo_map={k: v[0] for k, v in _XMLDSIG.items()}, xmldsig_digest=True),
    _r(r"<(?:[a-z0-9]+:)?(?:SignatureAlgorithm|DigestAlgorithm|SigningAlgorithm|DigestMethod|SignatureMethod|EncryptionMethod)>\s*" + _XMLDSIG_URI + r"\s*<", _S, "xml-dsig", algo_from_group=1, algo_map={k: v[0] for k, v in _XMLDSIG.items()}, xmldsig_digest=True),
    _r(r"<md:EntityDescriptor\b|<(?:saml2?:|saml2p:|samlp:)Assertion\b|<wsse:Security\b|<sp:AsymmetricBinding\b|<sp:SymmetricBinding\b", _S, "saml/ws-security", algorithm="X509", confidence="LOW", confidence_reason="signed SAML / WS-Security document"),
    _r(r"<sp:(Basic128|Basic192|Basic256|TripleDes)(?:Rsa15|Sha256|Sha256Rsa15)?\s*/?>", _C, "ws-securitypolicy", algo_from_group=1, algo_map={"basic128": "AES", "basic192": "AES", "basic256": "AES", "tripledes": "3DES"}),
    _r(r"<sp:(?:Basic128|Basic192|Basic256|TripleDes)Sha256(?:Rsa15)?\s*/?>", _D, "ws-securitypolicy", algorithm="SHA-256"),
    _r(r"<(?:ds:)?X509Certificate>|<(?:ds:)?X509Data>|<wsse:BinarySecurityToken\b|<md:KeyDescriptor\b", _TLS, "xml-dsig", algorithm="X509", confidence="MEDIUM"),
    # ------------------------------------------------------------ generic element-value settings
    _r(r"<(?:[a-z0-9]+:)?(?:hashAlgorithm|digestAlgorithm|hash-algorithm|digest-algorithm|passwordHashAlgorithm)>\s*(MD5|SHA-1|SHA1|SHA-256|SHA256|SHA-512|SHA512|BCRYPT|bcrypt|PBKDF2|argon2|scrypt)\s*<", _KDF, "xml-config", algo_from_group=1,
       algo_map={**_DIGEST, "bcrypt": "BCRYPT", "pbkdf2": "PBKDF2", "argon2": "ARGON2", "scrypt": "SCRYPT"}),
    _r(r"<(?:[a-z0-9]+:)?(?:algorithm|cipher|encryptionAlgorithm|transformation|cipherAlgorithm|cipher-algorithm)>\s*(AES|DES|DESede|TripleDES|3DES|Blowfish|RC4|RC2|ChaCha20|ChaCha20-Poly1305)(?:/[A-Za-z0-9]+/[A-Za-z0-9]+)?\s*<|<(?:[a-z0-9]+:)?(?:algorithm|cipher|transformation)>\s*(AES)-\d{3}-(?:GCM|CBC|CTR)\s*<", _C, "xml-config", algo_from_group=1, algo_map=_CIPHER),
    _r(r"<(?:[a-z0-9]+:)?(?:sslProtocol|protocol|tlsVersion|minTlsVersion|sslMinimumVersion|min-tls-version|tls-version)>\s*(TLSv1\.3|TLSv1\.2|TLSv1\.1|TLSv1\.0|TLSv1|TLS1\.2|TLS1\.3|SSLv3|SSLv2)\s*<", _TLS, "xml-config", algo_from_group=1, algo_map=_PROTO),
    _r(r"<(?:[a-z0-9]+:)?(?:jwt|token|signing|signature)[A-Za-z-]*[Aa]lgorithm>\s*(HS256|HS384|HS512|RS256|RS384|RS512|ES256|ES384|ES512|PS256|PS384|PS512|EdDSA|none)\s*<|\b(?:jwt|token|signing)[A-Za-z._-]*[Aa]lgorithm\s*=\s*[\"'](HS256|HS384|HS512|RS256|RS384|RS512|ES256|ES384|ES512|PS256|PS384|PS512|EdDSA|none)[\"']", _S, "xml-config", algo_from_group=1, algo_map=_JWT),
    _r(r"<add\b[^>]*\bkey\s*=\s*[\"'][^\"']*(?:Jwt|Token)[^\"']*Algorithm[^\"']*[\"'][^>]*\bvalue\s*=\s*[\"'](HS256|HS384|HS512|RS256|RS384|RS512|ES256|ES384|ES512|PS256|PS384|PS512|EdDSA|none)[\"']", _S, "asp.net", algo_from_group=1, algo_map=_JWT),
]

_TLS_TOKENS = {"tlsv1.3": "TLS1.3", "tlsv1.2": "TLS1.2", "tlsv1.1": "TLS1.1", "tlsv1": "TLS1.0", "tlsv1.0": "TLS1.0", "tls13": "TLS1.3", "tls12": "TLS1.2", "tls11": "TLS1.1", "tls": "TLS1.0",
               "sslv3": "SSLv3", "ssl3": "SSLv3", "sslv2": "SSLv2", "ssl2": "SSLv2", "sslv2hello": "SSLv2", "all": "TLS", "default": "TLS", "none": "TLS"}


def _emit_extra(findings: list[RawFinding], text: str, file_path: Path, repo_root: Path | None) -> list[RawFinding]:
    """Second pass for the two spec keys ``run_rules`` does not know about:

    * ``split_tls_group`` — ``sslEnabledProtocols="TLSv1,TLSv1.1,TLSv1.2"`` → one finding per version
    * ``xmldsig_digest`` — ``rsa-sha256`` names two algorithms; emit the digest half too
    """
    extra: list[RawFinding] = []
    seen = {(f.source.line_number, f.crypto.algorithm.upper()) for f in findings}

    def put(line: int, algo: str, api_type: str, purpose: str, library: str, raw: str, confidence: str, reason: str) -> None:
        if (line, algo.upper()) in seen:
            return
        seen.add((line, algo.upper()))
        extra.append(make_finding(file_path=file_path, repo_root=repo_root, line_number=line, language="CONFIG", scanner_id=SCANNER_ID,
                                  api_type=api_type, algorithm=algo, purpose=purpose, library=library, confidence=confidence,
                                  confidence_reason=reason, raw_transformation=raw[:80]))

    for pattern, spec in _RULES:
        if not (spec.get("split_tls_group") or spec.get("xmldsig_digest") or spec.get("split_suite_group")):
            continue
        for m in pattern.finditer(text):
            line = text[: m.start()].count("\n") + 1
            tok = next((g for g in m.groups() if g), "") or ""
            if spec.get("split_tls_group"):
                for part in re.split(r"[\s,+]+", tok):
                    algo = _TLS_TOKENS.get(part.strip("-").lower())
                    if algo:
                        put(line, algo, "KEY_AGREEMENT", "NETWORK_ENCRYPTION", spec["library"], part,
                            "HIGH" if algo in {"TLS1.0", "TLS1.1", "SSLv3", "SSLv2"} else "MEDIUM", "enabled protocol list")
            elif spec.get("split_suite_group"):
                # MQ CipherSpec / JSSE suite name -> component algorithms
                from scanner.extractors.cipher_suites import suite_components
                from scanner.parsers.config_rules import _MQ_CIPHERSPEC
                low = tok.lower()
                if low in _MQ_CIPHERSPEC:
                    algo, digest = _MQ_CIPHERSPEC[low]
                    put(line, algo, "KEY_AGREEMENT" if algo.startswith("TLS") else "CIPHER_INSTANCE", "NETWORK_ENCRYPTION", spec["library"], tok, "HIGH", "MQ CipherSpec")
                    if digest:
                        put(line, digest, "MESSAGE_DIGEST", "NETWORK_ENCRYPTION", spec["library"], tok, "HIGH", "MQ CipherSpec")
                    if low.startswith("ecdhe_ecdsa"):
                        put(line, "ECDSA", "SIGNATURE", "NETWORK_ENCRYPTION", spec["library"], tok, "HIGH", "MQ CipherSpec")
                    elif low.startswith(("ecdhe_rsa", "tls_rsa")):
                        put(line, "RSA", "SIGNATURE", "NETWORK_ENCRYPTION", spec["library"], tok, "HIGH", "MQ CipherSpec")
                else:
                    for a, api_type in suite_components(tok):
                        put(line, a, api_type, "NETWORK_ENCRYPTION", spec["library"], tok, "HIGH", "cipher suite")
            else:
                pair = _XMLDSIG.get(tok.lower())
                if pair and pair[1]:
                    put(line, pair[1], "MESSAGE_DIGEST", "HASHING", spec["library"], tok, "HIGH", "XML-DSig algorithm URI")
    return extra


_XML_COMMENT = re.compile(r"<!--.*?-->", re.S)


def _blank_comments(text: str) -> str:
    return _XML_COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)


def parse_xml_file(file_path: Path, repo_root: Path | None = None) -> list[RawFinding]:
    try:
        raw = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    if len(raw) > 2_000_000:
        return []
    text = _blank_comments(raw)
    findings = run_rules(
        file_path=file_path,
        repo_root=repo_root,
        text=text,
        rules=_RULES,
        language="CONFIG",
        scanner_id=SCANNER_ID,
        confidence_reason="xml-config-directive",
        strip_comments=False,
    )
    return findings + _emit_extra(findings, text, file_path, repo_root)
