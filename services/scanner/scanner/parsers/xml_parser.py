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
    _r(r"<(?:security:|sec:|s:)?remember-me\b", _M, "spring-security", algorithm="MD5", confidence="MEDIUM", confidence_reason="TokenBasedRememberMeServices default token signature is MD5 (SHA-256 when configured)"),
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
    _r(r"<(?:Connector|SSLHostConfig)\b[^>]*\bciphers\s*=\s*[\"']([^\"']+)[\"']", _TLS, "tomcat", algorithm="TLS-CIPHERS", confidence="MEDIUM"),
    _r(r"<Connector\b[^>]*\bSSLEnabled\s*=\s*[\"']true[\"']|<SSLHostConfig\b|<Certificate\b[^>]*\bcertificateKeystoreFile", _TLS, "tomcat", algorithm="TLS", confidence="MEDIUM"),
    _r(r"\b(?:keystoreType|truststoreType|certificateKeystoreType)\s*=\s*[\"'](?:JKS|PKCS12|BKS|JCEKS)[\"']|\b(?:keystoreFile|certificateKeystoreFile|truststoreFile|certificateFile)\s*=", _TLS, "tomcat", algorithm="X509", confidence="MEDIUM"),
    _r(r"<Realm\b[^>]*\bdigest\s*=\s*[\"'](MD5|SHA|SHA-1|SHA-256|SHA-512)[\"']|<CredentialHandler\b[^>]*\balgorithm\s*=\s*[\"'](MD5|SHA-1|SHA-256|SHA-512|PBKDF2WithHmacSHA1|PBKDF2WithHmacSHA512)[\"']", _KDF, "tomcat", algo_from_group=1,
       algo_map={**_DIGEST, "pbkdf2withhmacsha1": "PBKDF2", "pbkdf2withhmacsha512": "PBKDF2"}),
    _r(r"<CredentialHandler\b[^>]*SecretKeyCredentialHandler", _KDF, "tomcat", algorithm="PBKDF2", confidence="MEDIUM", confidence_reason="Tomcat SecretKeyCredentialHandler default PBKDF2WithHmacSHA512"),
    _r(r"<https-listener\b|<ssl-context\b|<server-ssl-context\b|<key-store\b[^>]*\bpath\s*=|<key-manager\b|<trust-manager\b", _TLS, "wildfly", algorithm="TLS", confidence="MEDIUM"),
    _r(r"<(?:server-ssl-context|client-ssl-context|ssl-context)\b[^>]*\bprotocols\s*=\s*[\"']([^\"']+)[\"']", _TLS, "wildfly", algorithm="TLS", confidence="MEDIUM", split_tls_group=1),
    _r(r"<(?:server-ssl-context|client-ssl-context|ssl-context)\b[^>]*\bcipher-suite-filter\s*=\s*[\"']([^\"']+)[\"']", _TLS, "wildfly", algorithm="TLS-CIPHERS", confidence="MEDIUM"),
    _r(r"<(?:mapper|simple-digest-mapper|salted-simple-digest-mapper|scram-mapper)\b[^>]*\balgorithm\s*=\s*[\"'](?:simple-digest-|salted-simple-digest-|scram-)?(md5|sha-1|sha-256|sha-384|sha-512|bcrypt)[\"']", _KDF, "wildfly-elytron", algo_from_group=1, algo_map={**_DIGEST, "bcrypt": "BCRYPT"}),
    _r(r"<bcrypt-mapper\b", _KDF, "wildfly-elytron", algorithm="BCRYPT"),
    _r(r"<clear-password\b[^>]*\bpassword\s*=|<clear-text\b|<plain-text\b", _KDF, "wildfly", algorithm="PLAINTEXT", confidence="MEDIUM", confidence_reason="cleartext credential in config"),
    # ------------------------------------------------------------ JDBC URLs
    _r(r"\bjdbc:(?:mysql|mariadb):[^\"'<\s]*[?&](?:useSSL=false|sslMode=DISABLED|useSsl=false)\b|\bjdbc:postgresql:[^\"'<\s]*[?&]ssl(?:mode)?=(?:false|disable|allow)\b|\bjdbc:sqlserver:[^\"'<\s]*;encrypt=false\b", _TLS, "jdbc", algorithm="TLS-DISABLED", confidence="HIGH", confidence_reason="JDBC connection without TLS"),
    _r(r"\bjdbc:(?:mysql|mariadb):[^\"'<\s]*[?&](?:useSSL=true|sslMode=(?:REQUIRED|VERIFY_CA|VERIFY_IDENTITY))\b|\bjdbc:postgresql:[^\"'<\s]*[?&]ssl(?:mode)?=(?:true|require|verify-ca|verify-full)\b|\bjdbc:sqlserver:[^\"'<\s]*;encrypt=(?:true|strict)\b", _TLS, "jdbc", algorithm="TLS", confidence="MEDIUM"),
    _r(r"\bjdbc:[a-z]+:[^\"'<\s]*[?&;](?:trustServerCertificate=true|verifyServerCertificate=false|sslMode=PREFERRED|sslmode=prefer)\b", _TLS, "jdbc", algorithm="TLS-UNVERIFIED", confidence="HIGH"),
    # ------------------------------------------------------------ dependency manifests
    _r(r"<artifactId>\s*(" + "|".join(re.escape(k) for k in sorted(_MAVEN_DEPS, key=len, reverse=True)) + r")\s*</artifactId>", _DEP, "maven", algo_from_group=1, algo_map=_MAVEN_DEPS, confidence="LOW", confidence_reason="crypto library dependency"),
    _r(r"<(?:package|PackageReference)\b[^>]*\b(?:id|Include)\s*=\s*[\"'](" + "|".join(re.escape(k) for k in sorted(_NUGET_DEPS, key=len, reverse=True)) + r")[\"']", _DEP, "nuget", algo_from_group=1, algo_map=_NUGET_DEPS, confidence="LOW", confidence_reason="crypto library dependency"),
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
        if not (spec.get("split_tls_group") or spec.get("xmldsig_digest")):
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
