"""Wave 2 of the ground-truth corpus: harder, real-world idioms.

Labels are written by hand from the code. Every case names the algorithm
families that are *actually used* in the snippet — not what a scanner
happens to report. Registered into ``corpus.CASES`` via ``register(_c)``.
"""
from __future__ import annotations


def register(_c) -> None:  # noqa: C901 - flat list of cases on purpose
    # ------------------------------------------------------------------ python
    _c("python", "w2_fernet_settings.py", """
from cryptography.fernet import Fernet, MultiFernet
from django.conf import settings

_f = MultiFernet([Fernet(k) for k in settings.FERNET_KEYS])

def seal(payload: bytes) -> bytes:
    return _f.encrypt(payload)
""", {"AES", "HMAC", "SHA-256"})  # Fernet = AES-128-CBC + HMAC-SHA256
    _c("python", "w2_hashlib_new_var.py", """
import hashlib

DIGEST = "md5"

def legacy_digest(data: bytes) -> str:
    h = hashlib.new(DIGEST)
    h.update(data)
    return h.hexdigest()
""", {"MD5"})
    _c("python", "w2_paramiko_autoadd.py", """
import paramiko

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect("bastion", username="ops", key_filename="~/.ssh/id_rsa")
""", {"SSH"})
    _c("python", "w2_pyopenssl_sslv3.py", """
from OpenSSL import SSL

ctx = SSL.Context(SSL.SSLv3_METHOD)
ctx.set_cipher_list(b"RC4-SHA:AES128-SHA")
""", {"TLS", "RC4", "AES", "SHA-1"})
    _c("python", "w2_nacl_box.py", """
import nacl.secret
import nacl.utils
from nacl.signing import SigningKey

box = nacl.secret.SecretBox(nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE))
signer = SigningKey.generate()
""", {"SALSA20", "ED25519", "RNG"})
    _c("python", "w2_requests_verify_false.py", """
import requests

def fetch(url):
    return requests.get(url, verify=False, timeout=5).json()
""", {"TLS"})
    _c("python", "w2_pycryptodome_arc4.py", """
from Crypto.Cipher import ARC4, DES3

def old(key, data):
    return ARC4.new(key).encrypt(data)

def older(key, data):
    return DES3.new(key, DES3.MODE_ECB).encrypt(data)
""", {"RC4", "3DES"})
    _c("python", "w2_passlib_context.py", """
from passlib.context import CryptContext

pwd = CryptContext(schemes=["argon2", "bcrypt", "sha512_crypt"], deprecated="auto")
""", {"ARGON2", "BCRYPT", "SHA-512"})
    _c("python", "w2_random_token.py", """
import random
import string

def reset_token(n=32):
    return "".join(random.choice(string.ascii_letters) for _ in range(n))
""", {"RNG"})
    _c("python", "w2_ssl_min_version.py", """
import ssl

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.minimum_version = ssl.TLSVersion.TLSv1
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
""", {"TLS"})
    _c("python", "w2_ecdsa_lib.py", """
from ecdsa import SigningKey, NIST256p

sk = SigningKey.generate(curve=NIST256p)
sig = sk.sign(b"msg")
""", {"ECDSA"})
    _c("python", "w2_n_hashmap_and_shasum.py", """
import subprocess

def image_digest(path):
    out = subprocess.run(["sha256sum", path], capture_output=True, text=True)
    return out.stdout.split()[0]

class LRU(dict):
    def __hash__(self):
        return id(self)
""", set(), "negative")
    _c("python", "w2_n_docstring_mentions.py", '''
def rotate_keys():
    """Rotate the signing keys.

    Historically this used HMAC-SHA1 and RSA-1024; both were removed in v3.
    See docs/crypto.md for the AES migration notes.
    """
    return None
''', set(), "negative")

    # -------------------------------------------------------------------- java
    _c("java", "W2SslContextTls1.java", """
import javax.net.ssl.*;
public class W2SslContextTls1 {
  SSLContext ctx() throws Exception {
    SSLContext c = SSLContext.getInstance("TLSv1");
    c.init(null, new TrustManager[]{ new X509TrustManager() {
      public void checkClientTrusted(java.security.cert.X509Certificate[] x, String a) {}
      public void checkServerTrusted(java.security.cert.X509Certificate[] x, String a) {}
      public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }
    }}, null);
    return c;
  }
}
""", {"TLS"})
    _c("java", "W2KeyGenDesede.java", """
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
public class W2KeyGenDesede {
  SecretKey k() throws Exception {
    KeyGenerator kg = KeyGenerator.getInstance("DESede");
    kg.init(168);
    return kg.generateKey();
  }
}
""", {"3DES"})
    _c("java", "W2Sha1PrngAndRandom.java", """
import java.security.SecureRandom;
import java.util.Random;
public class W2Sha1PrngAndRandom {
  static final Random R = new Random();
  String token() throws Exception {
    SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
    return Long.toHexString(R.nextLong()) + sr.nextInt();
  }
}
""", {"RNG"})
    _c("java", "W2SpringEncoders.java", """
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.*;
public class W2SpringEncoders {
  PasswordEncoder legacy = new MessageDigestPasswordEncoder("MD5");
  PasswordEncoder current = new BCryptPasswordEncoder(12);
  PasswordEncoder next = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
}
""", {"MD5", "BCRYPT", "ARGON2"})
    _c("java", "W2BouncyCastleEngines.java", """
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.RC4Engine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.digests.SHA256Digest;
public class W2BouncyCastleEngines {
  GCMBlockCipher gcm = new GCMBlockCipher(new AESEngine());
  RC4Engine rc4 = new RC4Engine();
  SHA256Digest d = new SHA256Digest();
}
""", {"AES", "RC4", "SHA-256"})
    _c("java", "W2Sha1WithRsa.java", """
import java.security.*;
public class W2Sha1WithRsa {
  byte[] sign(PrivateKey k, byte[] m) throws Exception {
    Signature s = Signature.getInstance("SHA1withRSA");
    s.initSign(k); s.update(m); return s.sign();
  }
  KeyPair kp() throws Exception {
    KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
    g.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
    return g.generateKeyPair();
  }
}
""", {"SHA-1", "RSA", "ECDSA"})
    _c("java", "W2PropertyDrivenCipher.java", """
import javax.crypto.Cipher;
import java.util.Properties;
public class W2PropertyDrivenCipher {
  Cipher c(Properties p) throws Exception {
    // algorithm resolved at runtime from configuration
    return Cipher.getInstance(p.getProperty("crypto.transformation"));
  }
}
""", set())  # dynamic: must NOT be reported as the literal "crypto.transformation"
    _c("java", "W2JwtRs256.java", """
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
public class W2JwtRs256 {
  String t(java.security.PrivateKey k) {
    return Jwts.builder().setSubject("u").signWith(k, SignatureAlgorithm.RS256).compact();
  }
}
""", {"JWT"})
    _c("java", "W2NKeyStoreOnly.java", """
import java.util.HashMap;
import java.util.Map;
public class W2NKeyStoreOnly {
  // "hash" here is a Map, "digest" is an email digest, "key" is a map key
  private final Map<String, String> hash = new HashMap<>();
  public void sendDigest(String key) { hash.put(key, "weekly digest"); }
  public int hashCode() { return hash.hashCode(); }
}
""", set(), "negative")

    # -------------------------------------------------------------- javascript
    _c("javascript", "w2_cryptojs.js", """
const CryptoJS = require("crypto-js");
const digest = CryptoJS.MD5(payload).toString();
const enc = CryptoJS.AES.encrypt(JSON.stringify(data), passphrase).toString();
const mac = CryptoJS.HmacSHA1(body, secret);
""", {"MD5", "AES", "HMAC", "SHA-1"})
    _c("javascript", "w2_subtle_pbkdf2.js", """
async function deriveKey(password, salt) {
  const km = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    km, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
""", {"PBKDF2", "SHA-256", "AES"})
    _c("javascript", "w2_https_reject_unauthorized.js", """
const https = require("https");
const agent = new https.Agent({ rejectUnauthorized: false });
https.get("https://internal/api", { agent }, (res) => res.pipe(process.stdout));
""", {"TLS"})
    _c("javascript", "w2_tls_min_version.js", """
const tls = require("tls");
const server = tls.createServer({ key, cert, minVersion: "TLSv1", ciphers: "RC4-SHA:AES128-GCM-SHA256" });
""", {"TLS", "RC4", "AES", "SHA-1", "SHA-256"})
    _c("javascript", "w2_math_random_token.js", """
function sessionId() {
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}
module.exports = { sessionId };
""", {"RNG"})
    _c("javascript", "w2_jose_es256.js", """
import { SignJWT, importPKCS8 } from "jose";
const key = await importPKCS8(pem, "ES256");
const jwt = await new SignJWT({ sub: "u1" }).setProtectedHeader({ alg: "ES256" }).sign(key);
""", {"JWT"})
    _c("javascript", "w2_bcrypt_argon.js", """
const bcrypt = require("bcryptjs");
const argon2 = require("argon2");
async function hash(pw, modern) {
  return modern ? argon2.hash(pw, { type: argon2.argon2id }) : bcrypt.hash(pw, 10);
}
""", {"BCRYPT", "ARGON2"})
    _c("javascript", "w2_create_cipher_legacy.js", """
const crypto = require("crypto");
const c = crypto.createCipher("des-ede3-cbc", process.env.KEY);   // deprecated API
const d = crypto.createDecipheriv("aes-128-cbc", key, iv);
""", {"3DES", "AES", "MD5"})  # createCipher derives the key with EVP_BytesToKey(MD5)
    _c("javascript", "w2_tweetnacl.js", """
const nacl = require("tweetnacl");
const kp = nacl.sign.keyPair();
const boxed = nacl.secretbox(msg, nonce, key);
""", {"ED25519", "SALSA20"})
    _c("javascript", "w2_n_lodash_hash.js", """
const _ = require("lodash");
const byId = _.keyBy(rows, "id");
const hashRouter = createHashRouter(routes);  // react-router, URL hash
const desc = { key: "description", aes: false };
""", set(), "negative")
    _c("javascript", "w2_n_sha_in_strings.js", """
// deploy script: pin images by digest
const image = "registry/app@sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
const gitRef = process.env.GITHUB_SHA.slice(0, 7);
console.log("deploying", image, gitRef);
""", set(), "negative")

    # -------------------------------------------------------------- typescript
    _c("typescript", "w2_noble.ts", """
import { sha3_256 } from "@noble/hashes/sha3";
import * as ed from "@noble/ed25519";
import { x25519 } from "@noble/curves/ed25519";
export const digest = (b: Uint8Array) => sha3_256(b);
export const sign = (m: Uint8Array, sk: Uint8Array) => ed.sign(m, sk);
export const shared = (a: Uint8Array, b: Uint8Array) => x25519.getSharedSecret(a, b);
""", {"SHA3", "ED25519", "X25519"})
    _c("typescript", "w2_subtle_ecdsa.ts", """
export async function keys(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-384" }, true, ["sign", "verify"]);
}
export const hash = (d: BufferSource) => crypto.subtle.digest("SHA-1", d);
""", {"ECDSA", "SHA-1"})
    _c("typescript", "w2_n_types.ts", """
export interface Descriptor { key: string; aesthetic?: boolean; }
export type Hash<T> = Record<string, T>;
export const DESIGN_TOKENS: Hash<string> = { primary: "#123" };
""", set(), "negative")

    # ---------------------------------------------------------------------- go
    _c("go", "w2_tls_config.go", """
package main

import "crypto/tls"

func cfg() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		CipherSuites:       []uint16{tls.TLS_RSA_WITH_RC4_128_SHA, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}
}
""", {"TLS", "RC4", "AES", "RSA", "ECDH", "SHA-1", "SHA-256"})
    _c("go", "w2_ssh_ignore_hostkey.go", """
package main

import "golang.org/x/crypto/ssh"

func dial() (*ssh.Client, error) {
	c := &ssh.ClientConfig{User: "ops", HostKeyCallback: ssh.InsecureIgnoreHostKey()}
	return ssh.Dial("tcp", "host:22", c)
}
""", {"SSH"})
    _c("go", "w2_x_crypto_kdfs.go", """
package main

import (
	"crypto/sha256"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/chacha20poly1305"
)

func derive(pw, salt []byte) ([]byte, []byte) {
	a := argon2.IDKey(pw, salt, 1, 64*1024, 4, 32)
	p := pbkdf2.Key(pw, salt, 4096, 32, sha256.New)
	_, _ = chacha20poly1305.NewX(a)
	return a, p
}
""", {"ARGON2", "PBKDF2", "SHA-256", "CHACHA20"})
    _c("go", "w2_rsa1024_ecdsa.go", """
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
)

func keys() {
	_, _ = rsa.GenerateKey(rand.Reader, 1024)
	_, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}
""", {"RSA", "ECDSA", "RNG"})
    _c("go", "w2_math_rand_token.go", """
package main

import (
	"fmt"
	"math/rand"
)

func apiKey() string { return fmt.Sprintf("%x", rand.Int63()) }
""", {"RNG"})
    _c("go", "w2_n_hash_map.go", """
package main

import "hash/fnv"

func bucket(s string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(s))
	return h.Sum32() % 16
}

type Description struct{ Text string }
""", set(), "negative")

    # ----------------------------------------------------------------------- c
    _c("c", "w2_openssl_verify_none.c", """
#include <openssl/ssl.h>
SSL_CTX *mk(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_cipher_list(ctx, "DES-CBC3-SHA:AES256-SHA256");
    return ctx;
}
""", {"TLS", "3DES", "AES", "SHA-1", "SHA-256"})
    _c("c", "w2_evp_pbkdf2.c", """
#include <openssl/evp.h>
int kdf(const char *pw, unsigned char *salt, unsigned char *out) {
    return PKCS5_PBKDF2_HMAC(pw, -1, salt, 16, 10000, EVP_sha1(), 32, out);
}
""", {"PBKDF2", "HMAC", "SHA-1"})
    _c("c", "w2_libsodium.c", """
#include <sodium.h>
int seal(unsigned char *c, const unsigned char *m, unsigned long long mlen,
         const unsigned char *n, const unsigned char *k) {
    return crypto_secretbox_easy(c, m, mlen, n, k);
}
int sig(unsigned char *sm, const unsigned char *m, const unsigned char *sk) {
    return crypto_sign_ed25519_detached(sm, NULL, m, 32, sk);
}
""", {"SALSA20", "ED25519"})
    _c("c", "w2_mbedtls.c", """
#include "mbedtls/md5.h"
#include "mbedtls/aes.h"
void f(const unsigned char *in, unsigned char out[16], mbedtls_aes_context *aes) {
    mbedtls_md5(in, 16, out);
    mbedtls_aes_setkey_enc(aes, out, 128);
}
""", {"MD5", "AES"})
    _c("c", "w2_win_cng.c", """
#include <windows.h>
#include <bcrypt.h>
NTSTATUS open(BCRYPT_ALG_HANDLE *h, BCRYPT_ALG_HANDLE *r) {
    BCryptOpenAlgorithmProvider(h, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    return BCryptOpenAlgorithmProvider(r, BCRYPT_RSA_ALGORITHM, NULL, 0);
}
""", {"SHA-256", "RSA"})
    _c("c", "w2_capi_md5.c", """
#include <windows.h>
#include <wincrypt.h>
BOOL h(HCRYPTPROV prov, HCRYPTHASH *hash) {
    return CryptCreateHash(prov, CALG_MD5, 0, 0, hash);
}
""", {"MD5"})
    _c("c", "w2_rand_seed.c", """
#include <stdlib.h>
#include <time.h>
unsigned long nonce(void) { srand((unsigned)time(NULL)); return (unsigned long)rand() << 16 | rand(); }
""", {"RNG"})
    _c("c", "w2_n_hash_table.c", """
#include <stdint.h>
/* open-addressing hash table; djb2 string hash */
static uint32_t djb2(const char *s) { uint32_t h = 5381; while (*s) h = h * 33 + (unsigned char)*s++; return h; }
struct desc { const char *description; int aes_enabled_flag_unused; };
""", set(), "negative")

    # ------------------------------------------------------------------- csharp
    _c("csharp", "W2ServicePointTls.cs", """
using System.Net;
public static class W2ServicePointTls {
  public static void Init() {
    ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls | SecurityProtocolType.Tls11;
    ServicePointManager.ServerCertificateValidationCallback = (s, c, ch, e) => true;
  }
}
""", {"TLS"})
    _c("csharp", "W2Rfc2898.cs", """
using System.Security.Cryptography;
public class W2Rfc2898 {
  public byte[] Derive(string pw, byte[] salt) {
    using var k = new Rfc2898DeriveBytes(pw, salt, 1000, HashAlgorithmName.SHA1);
    return k.GetBytes(32);
  }
}
""", {"PBKDF2", "SHA-1"})
    _c("csharp", "W2Dpapi.cs", """
using System.Security.Cryptography;
public class W2Dpapi {
  public byte[] P(byte[] d) => ProtectedData.Protect(d, null, DataProtectionScope.CurrentUser);
}
""", {"DPAPI"})
    _c("csharp", "W2JwtHmac.cs", """
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
public class W2JwtHmac {
  public string T(SymmetricSecurityKey k) {
    var creds = new SigningCredentials(k, SecurityAlgorithms.HmacSha256);
    return new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(signingCredentials: creds));
  }
}
""", {"JWT", "HMAC", "SHA-256"})
    _c("csharp", "W2RandomToken.cs", """
using System;
public class W2RandomToken {
  static readonly Random R = new Random();
  public string Next() => R.Next().ToString("x");
}
""", {"RNG"})
    _c("csharp", "W2EcdsaCreate.cs", """
using System.Security.Cryptography;
public class W2EcdsaCreate {
  public byte[] S(byte[] d) { using var e = ECDsa.Create(ECCurve.NamedCurves.nistP256); return e.SignData(d, HashAlgorithmName.SHA256); }
}
""", {"ECDSA", "SHA-256"})
    _c("csharp", "W2NDescription.cs", """
using System.ComponentModel;
public class W2NDescription {
  [Description("Aesthetic settings")] public string Theme { get; set; }
  public override int GetHashCode() => Theme?.GetHashCode() ?? 0;
}
""", set(), "negative")

    # --------------------------------------------------------------------- rust
    _c("rust", "w2_rustls_dangerous.rs", """
use rustls::client::danger::{ServerCertVerifier, ServerCertVerified};
struct NoVerify;
impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(&self, _: &rustls::pki_types::CertificateDer, _: &[rustls::pki_types::CertificateDer], _: &rustls::pki_types::ServerName, _: &[u8], _: rustls::pki_types::UnixTime) -> Result<ServerCertVerified, rustls::Error> { Ok(ServerCertVerified::assertion()) }
}
fn cfg() -> rustls::ClientConfig { rustls::ClientConfig::builder().dangerous().with_custom_certificate_verifier(std::sync::Arc::new(NoVerify)).with_no_client_auth() }
""", {"TLS"})
    _c("rust", "w2_openssl_symm.rs", """
use openssl::symm::{Cipher, encrypt};
fn legacy(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    encrypt(Cipher::des_ede3_cbc(), key, Some(iv), data).unwrap()
}
fn modern(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    encrypt(Cipher::aes_256_gcm(), key, Some(iv), data).unwrap()
}
""", {"3DES", "AES"})
    _c("rust", "w2_jsonwebtoken.rs", """
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
fn token(claims: &Claims, secret: &[u8]) -> String {
    encode(&Header::new(Algorithm::HS512), claims, &EncodingKey::from_secret(secret)).unwrap()
}
""", {"JWT"})
    _c("rust", "w2_ring_pbkdf2.rs", """
use ring::{digest, pbkdf2};
static ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA256;
fn derive(pw: &[u8], salt: &[u8], out: &mut [u8]) {
    pbkdf2::derive(ALG, std::num::NonZeroU32::new(100_000).unwrap(), salt, pw, out);
    let _ = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, pw);
}
""", {"PBKDF2", "HMAC", "SHA-256", "SHA-1"})
    _c("rust", "w2_x25519_dalek.rs", """
use x25519_dalek::{EphemeralSecret, PublicKey};
use rand_core::OsRng;
fn kx() -> PublicKey { let s = EphemeralSecret::random_from_rng(OsRng); PublicKey::from(&s) }
""", {"X25519", "RNG"})
    _c("rust", "w2_n_hashmap.rs", """
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
#[derive(Hash)] struct Descriptor { key: String }
fn index(items: &[Descriptor]) -> HashMap<&str, usize> { items.iter().enumerate().map(|(i, d)| (d.key.as_str(), i)).collect() }
""", set(), "negative")

    # ---------------------------------------------------------------------- php
    _c("php", "w2_laravel_config_app.php", """
<?php
return [
    'key' => env('APP_KEY'),
    'cipher' => 'AES-256-CBC',
    'hashing' => ['driver' => 'bcrypt', 'bcrypt' => ['rounds' => 12]],
];
""", {"AES", "BCRYPT", "HMAC", "SHA-256"})  # Laravel Encrypter: AES-256-CBC + HMAC-SHA256
    _c("php", "w2_curl_verifypeer.php", """
<?php
$ch = curl_init($url);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
curl_setopt($ch, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_0);
$out = curl_exec($ch);
""", {"TLS"})
    _c("php", "w2_stream_context.php", """
<?php
$ctx = stream_context_create(['ssl' => ['verify_peer' => false, 'verify_peer_name' => false, 'ciphers' => 'RC4-MD5']]);
$fp = fopen('https://legacy/api', 'r', false, $ctx);
""", {"TLS", "RC4", "MD5"})
    _c("php", "w2_openssl_sign_sha1.php", """
<?php
$key = openssl_pkey_new(['private_key_bits' => 1024, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
openssl_sign($data, $sig, $key, OPENSSL_ALGO_SHA1);
""", {"RSA", "SHA-1"})
    _c("php", "w2_mt_rand_token.php", """
<?php
function reset_token(): string { return md5(uniqid((string) mt_rand(), true)); }
""", {"RNG", "MD5"})
    _c("php", "w2_sodium.php", """
<?php
$ct = sodium_crypto_secretbox($msg, $nonce, $key);
$sig = sodium_crypto_sign_detached($msg, $sk);
$h = sodium_crypto_generichash($msg);
""", {"SALSA20", "ED25519", "BLAKE2"})
    _c("php", "w2_n_wordpress.php", """
<?php
add_action('wp_head', function () { echo '<meta name="description" content="' . esc_attr(get_bloginfo('description')) . '">'; });
$hash = spl_object_hash($obj);
$slug = sanitize_title($title);
""", set(), "negative")

    # -------------------------------------------------------------------- ruby
    _c("ruby", "w2_message_encryptor.rb", """
require "active_support"
key = ActiveSupport::KeyGenerator.new(secret).generate_key(salt, 32)
crypt = ActiveSupport::MessageEncryptor.new(key, cipher: "aes-256-gcm")
crypt.encrypt_and_sign(payload)
""", {"PBKDF2", "AES"})
    _c("ruby", "w2_net_ssh_never.rb", """
require "net/ssh"
Net::SSH.start("host", "ops", verify_host_key: :never, keys: ["~/.ssh/id_rsa"]) { |s| s.exec!("uptime") }
""", {"SSH"})
    _c("ruby", "w2_ec_generate.rb", """
require "openssl"
ec = OpenSSL::PKey::EC.generate("prime256v1")
rsa = OpenSSL::PKey::RSA.new(1024)
digest = OpenSSL::Digest.new("sha1")
""", {"ECDSA", "RSA", "SHA-1"})
    _c("ruby", "w2_rand_token.rb", """
def reset_token
  (0...32).map { (65 + rand(26)).chr }.join
end
""", {"RNG"})
    _c("ruby", "w2_ssl_verify_none.rb", """
require "net/http"
http = Net::HTTP.new("legacy.internal", 443)
http.use_ssl = true
http.verify_mode = OpenSSL::SSL::VERIFY_NONE
http.min_version = OpenSSL::SSL::TLS1_VERSION
""", {"TLS"})
    _c("ruby", "w2_n_digest_email.rb", """
class DigestMailer < ApplicationMailer
  # weekly activity digest, nothing cryptographic
  def weekly(user) = mail(to: user.email, subject: "Your weekly digest")
end
DESCRIPTION_LIMIT = 280
""", set(), "negative")

    # ------------------------------------------------------------------ kotlin
    _c("kotlin", "W2AndroidKeystore.kt", """
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import javax.crypto.KeyGenerator
fun key(): javax.crypto.SecretKey {
    val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
    kg.init(KeyGenParameterSpec.Builder("k", KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build())
    return kg.generateKey()
}
""", {"AES"})
    _c("kotlin", "W2HostnameVerifier.kt", """
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLContext
val ctx: SSLContext = SSLContext.getInstance("SSL")
val allHosts = HostnameVerifier { _, _ -> true }
""", {"TLS"})
    _c("kotlin", "W2OkHttpSpec.kt", """
import okhttp3.ConnectionSpec
import okhttp3.OkHttpClient
import okhttp3.TlsVersion
import okhttp3.CipherSuite
val spec = ConnectionSpec.Builder(ConnectionSpec.COMPATIBLE_TLS)
    .tlsVersions(TlsVersion.TLS_1_0, TlsVersion.TLS_1_2)
    .cipherSuites(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA)
    .build()
val client = OkHttpClient.Builder().connectionSpecs(listOf(spec)).build()
""", {"TLS", "3DES", "RSA", "SHA-1"})
    _c("kotlin", "W2SecretKeySpecDesede.kt", """
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
fun enc(k: ByteArray, d: ByteArray): ByteArray {
    val c = Cipher.getInstance("DESede/ECB/PKCS5Padding")
    c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(k, "DESede"))
    return c.doFinal(d)
}
""", {"3DES"})
    _c("kotlin", "W2NDataClass.kt", """
data class Design(val description: String, val hashtags: List<String>)
fun Design.key() = description.hashCode()
""", set(), "negative")

    # ------------------------------------------------------------------ config
    _c("config", "w2_nginx_legacy.conf", """
server {
    listen 443 ssl;
    ssl_protocols SSLv3 TLSv1 TLSv1.1;
    ssl_ciphers RC4-SHA:DES-CBC3-SHA:!aNULL;
    ssl_dhparam /etc/nginx/dhparam.pem;
}
""", {"TLS", "RC4", "3DES", "SHA-1", "DH"}, "config")
    _c("config", "w2_postgresql.conf", """
ssl = on
ssl_min_protocol_version = 'TLSv1'
password_encryption = md5
ssl_ciphers = 'HIGH:MEDIUM:+3DES:!aNULL'
""", {"TLS", "MD5", "3DES"}, "config")
    _c("config", "w2_kafka_server.properties", """
listeners=SSL://:9093
ssl.enabled.protocols=TLSv1.1,TLSv1.2
ssl.cipher.suites=TLS_RSA_WITH_AES_128_CBC_SHA
ssl.keystore.type=JKS
""", {"TLS", "RSA", "AES", "SHA-1"}, "config")
    _c("config", "ssh_config", """
Host bastion
    HostName 10.0.0.1
    StrictHostKeyChecking no
    HostKeyAlgorithms +ssh-rsa,ssh-dss
    KexAlgorithms +diffie-hellman-group14-sha1
""", {"SSH", "RSA", "DSA", "DH", "SHA-1"}, "config")
    _c("config", "Dockerfile", """
FROM node:20-alpine
ENV NODE_TLS_REJECT_UNAUTHORIZED=0
ENV JWT_ALGORITHM=RS256
COPY . /app
CMD ["node", "server.js"]
""", {"TLS", "JWT"}, "config")
    _c("config", "w2_spring_application.yml", """
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          jws-algorithm: RS256
  datasource:
    url: jdbc:postgresql://db/app?sslmode=disable
server:
  ssl:
    enabled-protocols: TLSv1.2
    ciphers: TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
""", {"JWT", "TLS", "ECDH", "ECDSA", "CHACHA20", "SHA-256"}, "config")
    _c("config", "w2_redis.conf", """
port 0
tls-port 6379
tls-protocols "TLSv1 TLSv1.2"
tls-ciphers DEFAULT:!MEDIUM
""", {"TLS"}, "config")
    _c("config", "w2_terraform_lb.tf", """
resource "aws_lb_listener" "https" {
  protocol   = "HTTPS"
  ssl_policy = "ELBSecurityPolicy-TLS-1-0-2015-04"
}
resource "tls_private_key" "ca" {
  algorithm = "ECDSA"
  ecdsa_curve = "P384"
}
""", {"TLS", "ECDSA"}, "config")
    _c("config", "w2_n_helm_values.yaml", """
image:
  repository: registry/app
  digest: sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
podAnnotations:
  checksum/config: "{{ include (print $.Template.BasePath \\"/configmap.yaml\\") . | sha256sum }}"
description: "RSA Conference demo stack"
aesthetics:
  theme: dark
""", set(), "negative")
    _c("config", "w2_n_ci_env.env", """
GITHUB_SHA=abc1234
DESIGN_SYSTEM_URL=https://design.internal
SSL_CERT_DIR=/etc/ssl/certs
TLS_ENABLED=true
""", set(), "negative")
