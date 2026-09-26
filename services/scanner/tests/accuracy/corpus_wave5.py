"""Wave 5 of the ground-truth corpus: provisioning shell, Dockerfiles, Swift
(CryptoKit / CommonCrypto / Security.framework / CryptoSwift / sodium / JWTKit),
App Transport Security plists and database authentication settings.

Labels follow the corpus conventions (families, not raw spellings; checksums
and package names are negatives). NOT written blind: the shell and Swift
parsers were built in the same session — first-pass score is recorded as
such in FIRST_PASS_HISTORY.
"""
from __future__ import annotations


def register(_c) -> None:  # noqa: C901
    # ------------------------------------------------------------ shell: provisioning
    _c("shell", "w5_ca_bootstrap.sh", """
#!/usr/bin/env bash
set -euo pipefail
openssl genrsa -out ca.key 4096
openssl req -x509 -new -key ca.key -sha256 -days 3650 -subj "/CN=Internal CA" -out ca.crt
""", {"RSA", "SHA-256", "X509"})
    _c("shell", "w5_server_cert_ec.sh", """
#!/bin/sh
openssl ecparam -name prime256v1 -genkey -noout -out server.key
openssl req -new -key server.key -out server.csr -sha384
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 825
""", {"ECDSA", "SHA-384", "X509"})
    _c("shell", "w5_backup_encrypt.sh", """
#!/bin/bash
tar czf - /var/lib/app | openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -md sha512 -salt -pass env:BACKUP_KEY -out backup.tgz.enc
""", {"AES", "PBKDF2", "SHA-512"})
    _c("shell", "w5_legacy_des_backup.sh", """
#!/bin/bash
# still runs nightly on the old box
openssl enc -des-ede3-cbc -in dump.sql -out dump.sql.enc -k "$LEGACY_PASS"
""", {"3DES"})
    _c("shell", "w5_deploy_keys.sh", """
#!/usr/bin/env bash
ssh-keygen -t ed25519 -C "deploy@ci" -f "$HOME/.ssh/deploy" -N ""
ssh -o StrictHostKeyChecking=no -i "$HOME/.ssh/deploy" deploy@prod 'systemctl restart app'
""", {"ED25519", "SSH"})
    _c("shell", "w5_ssh_rsa_default.sh", """
#!/bin/sh
ssh-keygen -t rsa -b 4096 -f id_rsa -q -N ""
scp -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no id_rsa.pub host:/tmp/
""", {"RSA", "SSH"})
    _c("shell", "w5_insecure_fetch.sh", """
#!/bin/bash
curl -fsSk https://artifacts.internal/latest.tar.gz -o latest.tar.gz
wget --no-check-certificate https://mirror.internal/checksums.txt
""", {"TLS"})
    _c("shell", "w5_ci_env_killswitch.sh", """
#!/bin/bash
export NODE_TLS_REJECT_UNAUTHORIZED=0
export GIT_SSL_NO_VERIFY=true
git config --global http.sslVerify false
npm ci
""", {"TLS"})
    _c("shell", "w5_htpasswd.sh", """
#!/bin/sh
htpasswd -cbB /etc/nginx/.htpasswd admin "$ADMIN_PW"
htpasswd -b /etc/nginx/.htpasswd-legacy old "$OLD_PW"
""", {"BCRYPT", "MD5"})
    _c("shell", "w5_mkpasswd_cloudinit.sh", """
#!/bin/bash
HASH=$(mkpasswd --method=SHA-512 --rounds=656000 "$PASSWORD")
sed -i "s|__HASH__|$HASH|" cloud-init.yaml
""", {"SHA-512"})
    _c("shell", "w5_gpg_release.sh", """
#!/bin/bash
gpg --batch --yes --digest-algo SHA512 --detach-sign --armor release.tar.gz
gpg --symmetric --cipher-algo AES256 --batch --passphrase-file .secret release.tar.gz
""", {"SHA-512", "AES"})
    _c("shell", "w5_keytool_jks.sh", """
#!/bin/sh
keytool -genkeypair -alias app -keyalg EC -groupname secp384r1 -sigalg SHA384withECDSA -keystore app.p12 -storetype PKCS12 -storepass "$PW"
keytool -importcert -alias rootca -file ca.crt -keystore truststore.jks -storepass changeit -noprompt
""", {"ECDSA", "SHA-384", "X509"})
    _c("shell", "w5_random_secret.sh", """
#!/bin/bash
JWT_SECRET=$(openssl rand -hex 32)
DB_PASSWORD=$(head -c 24 /dev/urandom | base64)
echo "JWT_SECRET=$JWT_SECRET" >> .env
""", {"RNG"})
    _c("shell", "w5_weak_random_token.sh", """
#!/bin/bash
RESET_TOKEN=$RANDOM$RANDOM
echo "reset token: $RESET_TOKEN" | mail -s "Password reset" "$USER_EMAIL"
""", {"RNG"})
    _c("shell", "w5_openssl_var.sh", """
#!/bin/sh
OPENSSL_BIN="${OPENSSL_BIN:-openssl}"
"$OPENSSL_BIN" dgst -sha256 -sign account.key -out sig.bin request.json
${OPENSSL_BIN:-openssl} pkcs8 -topk8 -v2 aes256 -in account.key -out account.p8 -passout env:P8PASS
""", {"SHA-256", "AES", "X509"})
    _c("shell", "w5_s_client_probe.sh", """
#!/bin/bash
echo | openssl s_client -connect legacy.example.com:443 -tls1 2>/dev/null | grep -q 'Protocol' && echo "TLS 1.0 still accepted"
echo | openssl s_client -connect api.example.com:443 -tls1_3 2>/dev/null | grep Protocol
""", {"TLS"})
    _c("shell", "w5_db_cli_notls.sh", """
#!/bin/bash
psql "host=db.internal dbname=app user=app sslmode=disable" -c 'select 1'
mysql --host=db2.internal --ssl-mode=DISABLED -e 'select 1'
""", {"TLS"})
    _c("shell", "w5_age_sops.sh", """
#!/bin/bash
age-keygen -o key.txt
sops --encrypt --age "$(grep public key.txt | cut -d: -f2)" secrets.yaml > secrets.enc.yaml
""", {"X25519", "CHACHA20", "AES"})
    _c("shell", "w5_cryptsetup.sh", """
#!/bin/bash
cryptsetup luksFormat --type luks2 --cipher aes-xts-plain64 --key-size 512 --hash sha256 /dev/sdb1
""", {"AES"})
    _c("shell", "w5_wireguard.sh", """
#!/bin/sh
umask 077
wg genkey | tee privatekey | wg pubkey > publickey
""", {"X25519"})
    _c("shell", "w5_cosign_sign.sh", """
#!/bin/bash
cosign sign --key cosign.key "$IMAGE@$DIGEST"
cosign verify --key cosign.pub "$IMAGE@$DIGEST"
""", {"ECDSA"})
    _c("shell", "w5_certbot.sh", """
#!/bin/bash
certbot certonly --nginx -d example.com --key-type ecdsa --elliptic-curve secp384r1 --agree-tos -m ops@example.com -n
""", {"X509", "ECDSA"})
    _c("shell", "w5_pkcs12_export.sh", """
#!/bin/sh
openssl pkcs12 -export -inkey server.key -in server.crt -certfile ca.crt -out server.p12 -passout pass:"$P12"
""", {"X509"})
    # ------------------------------------------------------------ shell negatives
    _c("shell", "w5_neg_checksums.sh", """
#!/bin/bash
sha256sum release.tar.gz > release.sha256
md5sum -c release.md5
""", set(), "negative")
    _c("shell", "w5_neg_packages.sh", """
#!/bin/bash
apt-get install -y openssl libssl-dev ca-certificates gnupg2
openssl version
pip install cryptography
""", set(), "negative")
    _c("shell", "w5_neg_shuffle.sh", """
#!/bin/bash
# pick a random colour for the build banner
COLOURS=(red green blue)
COLOUR=${COLOURS[$RANDOM % ${#COLOURS[@]}]}
echo "$COLOUR"
""", set(), "negative")
    _c("shell", "w5_neg_base64_only.sh", """
#!/bin/sh
echo -n "$1" | base64 -w0
uuidgen | tr -d '-'
""", set(), "negative")
    _c("shell", "w5_neg_curl_normal.sh", """
#!/bin/bash
curl -fsSL https://get.example.com/install.sh -o install.sh
curl -X POST -H 'Content-Type: application/json' -d '{"k":1}' https://api.example.com/v1/items
""", set(), "negative")
    _c("shell", "w5_neg_comment_only.sh", """
#!/bin/bash
# TODO: rotate with `openssl rand -hex 32` once the vault is up
# ssh-keygen -t rsa was the old way
echo "nothing here"
""", set(), "negative")
    # ------------------------------------------------------------ Dockerfile / Makefile
    _c("shell", "Dockerfile.w5", """
FROM eclipse-temurin:21-jre
RUN keytool -importcert -noprompt -alias corp -file /tmp/corp.crt -keystore $JAVA_HOME/lib/security/cacerts -storepass changeit
RUN curl -k -o /tmp/agent.jar https://build.internal/agent.jar
ENV JWT_ALGORITHM=RS256
""", {"X509", "TLS", "JWT"})
    _c("shell", "Makefile", """
certs:
\topenssl req -x509 -newkey rsa:2048 -nodes -keyout dev.key -out dev.crt -days 30 -subj /CN=localhost -sha256

clean:
\trm -f dev.key dev.crt
""", {"RSA", "SHA-256", "X509"})
    # ------------------------------------------------------------ swift
    _c("swift", "w5_cryptokit_hash.swift", """
import CryptoKit
import Foundation
func checksum(_ data: Data) -> String {
    let d = SHA256.hash(data: data)
    return d.map { String(format: "%02x", $0) }.joined()
}
func legacy(_ data: Data) -> Insecure.MD5Digest { Insecure.MD5.hash(data: data) }
""", {"SHA-256", "MD5"})
    _c("swift", "w5_cryptokit_aead.swift", """
import CryptoKit
struct Vault {
    let key = SymmetricKey(size: .bits256)
    func seal(_ plaintext: Data) throws -> Data { try AES.GCM.seal(plaintext, using: key).combined! }
    func sealFast(_ plaintext: Data) throws -> Data { try ChaChaPoly.seal(plaintext, using: key).combined }
}
""", {"RNG", "AES", "CHACHA20"})
    _c("swift", "w5_cryptokit_hmac_hkdf.swift", """
import CryptoKit
func tag(_ msg: Data, key: SymmetricKey) -> Data {
    Data(HMAC<SHA512>.authenticationCode(for: msg, using: key))
}
func derive(_ ikm: SymmetricKey, salt: Data) -> SymmetricKey {
    HKDF<SHA256>.deriveKey(inputKeyMaterial: ikm, salt: salt, info: Data("session".utf8), outputByteCount: 32)
}
""", {"HMAC", "SHA-512", "HKDF", "SHA-256"})
    _c("swift", "w5_cryptokit_sign_agree.swift", """
import CryptoKit
let signer = Curve25519.Signing.PrivateKey()
let sig = try signer.signature(for: payload)
let mine = P256.KeyAgreement.PrivateKey()
let shared = try mine.sharedSecretFromKeyAgreement(with: theirs)
let ecdsa = try P384.Signing.PrivateKey().signature(for: payload)
""", {"ED25519", "ECDH", "ECDSA"})
    _c("swift", "w5_commoncrypto_sha1_md5.swift", """
import CommonCrypto
extension Data {
    var sha1Hex: String {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        withUnsafeBytes { _ = CC_SHA1($0.baseAddress, CC_LONG(count), &digest) }
        return digest.map { String(format: "%02hhx", $0) }.joined()
    }
}
""", {"SHA-1"})
    _c("swift", "w5_commoncrypto_aes_cbc.swift", """
import CommonCrypto
func encrypt(_ data: Data, key: Data, iv: Data) -> Data? {
    var out = Data(count: data.count + kCCBlockSizeAES128)
    var moved = 0
    let status = CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding),
                         (key as NSData).bytes, key.count, (iv as NSData).bytes, (data as NSData).bytes, data.count,
                         out.withUnsafeMutableBytes { $0.baseAddress }, out.count, &moved)
    return status == kCCSuccess ? out.prefix(moved) : nil
}
""", {"AES"})
    _c("swift", "w5_commoncrypto_pbkdf2.swift", """
import CommonCrypto
func stretch(_ password: String, salt: [UInt8]) -> [UInt8] {
    var key = [UInt8](repeating: 0, count: 32)
    _ = CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), password, password.utf8.count, salt, salt.count,
                             CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), 100_000, &key, key.count)
    return key
}
func mac(_ key: [UInt8], _ data: [UInt8]) -> [UInt8] {
    var out = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
    CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA1), key, key.count, data, data.count, &out)
    return out
}
""", {"PBKDF2", "HMAC", "SHA-256", "SHA-1"})
    _c("swift", "w5_security_seckey.swift", """
import Security
let attrs: [String: Any] = [
    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
    kSecAttrKeySizeInBits as String: 256,
    kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
]
var error: Unmanaged<CFError>?
let priv = SecKeyCreateRandomKey(attrs as CFDictionary, &error)!
let sig = SecKeyCreateSignature(priv, .ecdsaSignatureMessageX962SHA256, data as CFData, &error)
""", {"ECDSA", "SHA-256"})
    _c("swift", "w5_security_rsa_oaep.swift", """
import Security
func wrap(_ key: Data, with pub: SecKey) -> Data? {
    var err: Unmanaged<CFError>?
    return SecKeyCreateEncryptedData(pub, .rsaEncryptionOAEPSHA256AESGCM, key as CFData, &err) as Data?
}
let query: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits as String: 2048]
""", {"RSA", "SHA-256"})
    _c("swift", "w5_urlsession_trust_all.swift", """
import Foundation
final class InsecureDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        // dev only!!
        completionHandler(.useCredential, URLCredential(trust: challenge.protectionSpace.serverTrust!))
    }
}
""", {"TLS"})
    _c("swift", "w5_urlsession_min_tls.swift", """
import Foundation
let cfg = URLSessionConfiguration.ephemeral
cfg.tlsMinimumSupportedProtocolVersion = .TLSv12
cfg.tlsMaximumSupportedProtocolVersion = .TLSv13
let session = URLSession(configuration: cfg)
""", {"TLS"})
    _c("swift", "w5_network_framework.swift", """
import Network
let tls = NWProtocolTLS.Options()
sec_protocol_options_set_min_tls_protocol_version(tls.securityProtocolOptions, .TLSv10)
sec_protocol_options_set_peer_authentication_required(tls.securityProtocolOptions, false)
let params = NWParameters(tls: tls)
""", {"TLS"})
    _c("swift", "w5_alamofire_pinning.swift", """
import Alamofire
let evaluators: [String: ServerTrustEvaluating] = [
    "api.example.com": PublicKeysTrustEvaluator(),
    "legacy.example.com": DisabledTrustEvaluator(),
]
let session = Session(serverTrustManager: ServerTrustManager(evaluators: evaluators))
""", {"X509", "TLS"})
    _c("swift", "w5_cryptoswift_aes.swift", """
import CryptoSwift
func encrypt(_ bytes: [UInt8], key: [UInt8], iv: [UInt8]) throws -> [UInt8] {
    let aes = try AES(key: key, blockMode: GCM(iv: iv, mode: .combined), padding: .noPadding)
    return try aes.encrypt(bytes)
}
func stretch(_ pw: [UInt8], salt: [UInt8]) throws -> [UInt8] {
    try PKCS5.PBKDF2(password: pw, salt: salt, iterations: 4096, keyLength: 32, variant: .sha2(.sha256)).calculate()
}
""", {"AES", "PBKDF2"})
    _c("swift", "w5_cryptoswift_hmac_digest.swift", """
import CryptoSwift
let tag = try HMAC(key: key, variant: .sha2(.sha256)).authenticate(message)
let legacy = Digest.md5(bytes)
let bf = try Blowfish(key: key, blockMode: CBC(iv: iv), padding: .pkcs7)
""", {"HMAC", "SHA-256", "MD5", "BLOWFISH"})
    _c("swift", "w5_sodium.swift", """
import Sodium
let sodium = Sodium()
let sealed = sodium.secretBox.seal(message: msg, secretKey: key)!
let kp = sodium.sign.keyPair()!
let sig = sodium.sign.signature(message: msg, secretKey: kp.secretKey)!
let hash = sodium.pwHash.str(passwd: pw, opsLimit: sodium.pwHash.OpsLimitInteractive, memLimit: sodium.pwHash.MemLimitInteractive)!
""", {"SALSA20", "ED25519", "ARGON2"})
    _c("swift", "w5_jwtkit.swift", """
import JWTKit
let keys = JWTKeyCollection()
await keys.add(hmac: "a-very-long-secret-value-for-tests", digestAlgorithm: .sha256)
await keys.add(ecdsa: ES256PrivateKey())
let token = try await keys.sign(payload)
""", {"JWT", "HMAC", "SHA-256", "ECDSA"})
    _c("swift", "w5_vapor_bcrypt.swift", """
import Vapor
func configure(_ app: Application) throws {
    app.passwords.use(.bcrypt)
    app.middleware.use(app.sessions.middleware)
}
let hash = try Bcrypt.hash("hunter2")
""", {"BCRYPT"})
    _c("swift", "w5_weak_rng_token.swift", """
import Foundation
func makeSessionToken() -> String {
    var s = ""
    for _ in 0..<16 { s += String(rand() % 10) }
    return s
}
""", {"RNG"})
    _c("swift", "w5_secrandom.swift", """
import Security
func nonce(_ n: Int) -> [UInt8] {
    var bytes = [UInt8](repeating: 0, count: n)
    _ = SecRandomCopyBytes(kSecRandomDefault, n, &bytes)
    return bytes
}
""", {"RNG"})
    _c("swift", "w5_swift_crypto_server.swift", """
import Crypto
import _CryptoExtras
let key = try _RSA.Signing.PrivateKey(keySize: .bits2048)
let sig = try key.signature(for: SHA256.hash(data: body), padding: .PSS)
let derived = try KDF.Insecure.PBKDF2.deriveKey(from: pw, salt: salt, using: .sha1, outputByteCount: 20, unsafeUncheckedRounds: 1000)
""", {"RSA", "SHA-256", "PBKDF2"})
    # ------------------------------------------------------------ swift negatives
    _c("swift", "w5_neg_shuffle.swift", """
import Foundation
struct Deck {
    var cards: [Card]
    mutating func shuffle() { cards.shuffle() }
    func pick() -> Card { cards[Int.random(in: 0..<cards.count)] }
    var jitter: Double { Double(rand() % 100) / 1000 }
}
""", set(), "negative")
    _c("swift", "w5_neg_keychain_only.swift", """
import Security
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: "com.example.app",
    kSecAttrAccount as String: account,
    kSecValueData as String: tokenData,
]
SecItemAdd(query as CFDictionary, nil)
""", set(), "negative")
    _c("swift", "w5_neg_import_only.swift", """
import CryptoKit
import CommonCrypto
struct Placeholder { let id = UUID() }
""", set(), "negative")
    _c("swift", "w5_neg_hashable.swift", """
struct Point: Hashable {
    let x: Int, y: Int
    func hash(into hasher: inout Hasher) { hasher.combine(x); hasher.combine(y) }
}
let hashValue = Point(x: 1, y: 2).hashValue
""", set(), "negative")
    _c("swift", "w5_neg_names.swift", """
final class DESCRIPTION { static let aesthetic = "minimal"; let sha = "shaped"; let md5sumPath = "/usr/bin/md5sum" }
let rc4Score = 4
let tlsRelatedDocsLink = "https://developer.apple.com/documentation/security"
""", set(), "negative")
    # ------------------------------------------------------------ plist (ATS)
    _c("swift", "w5_ats_arbitrary.plist", """
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>NSAppTransportSecurity</key>
  <dict><key>NSAllowsArbitraryLoads</key><true/></dict>
</dict></plist>
""", {"TLS"})
    _c("swift", "w5_ats_exception_tls10.plist", """
<plist version="1.0"><dict>
  <key>NSAppTransportSecurity</key>
  <dict><key>NSExceptionDomains</key><dict><key>legacy.example.com</key><dict>
    <key>NSExceptionMinimumTLSVersion</key><string>TLSv1.0</string>
    <key>NSExceptionAllowsInsecureHTTPLoads</key><true/>
  </dict></dict></dict>
</dict></plist>
""", {"TLS"})
    _c("swift", "w5_neg_plist_plain.plist", """
<plist version="1.0"><dict>
  <key>CFBundleDisplayName</key><string>Example</string>
  <key>UIRequiredDeviceCapabilities</key><array><string>arm64</string></array>
</dict></plist>
""", set(), "negative")
    # ------------------------------------------------------------ database auth config
    _c("config", "w5_pg_hba.conf", """
# TYPE  DATABASE  USER  ADDRESS        METHOD
local   all       all                  peer
host    all       all   127.0.0.1/32   md5
hostssl all       all   10.0.0.0/8     scram-sha-256
hostnossl all     all   192.168.0.0/16 password
""", {"MD5", "SHA-256", "TLS", "PLAINTEXT", "TLS"})
    _c("config", "w5_postgresql.conf", """
listen_addresses = '*'
password_encryption = scram-sha-256
ssl = on
ssl_min_protocol_version = 'TLSv1.2'
""", {"SHA-256", "TLS"})
    _c("config", "w5_my.cnf", """
[mysqld]
default_authentication_plugin=mysql_native_password
require_secure_transport=ON
""", {"SHA-1", "TLS"})
    _c("config", "w5_neg_pg_hba_trust_only.conf", """
# TYPE  DATABASE  USER  ADDRESS  METHOD
local   all       all            trust
host    all       all   ::1/128  trust
""", set(), "negative")
