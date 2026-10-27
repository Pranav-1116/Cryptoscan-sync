"""Wave 7 — BLIND. Written in one sitting *before* running the scanner, without
looking at any parser source, from idioms not deliberately targeted so far:
Android Keystore, javax.crypto parameter specs, .NET ECDiffieHellman/CNG,
PHP sodium_*, Ruby RbNaCl / ActiveSupport::MessageEncryptor, Rust openssl::symm,
Node sodium-native / tweetnacl, Go x/crypto/ssh & nacl, Python pyca advanced.
Labels are what a reviewer reading the code would inventory; they were not
edited after the first run (the first-pass score is in FIRST_PASS_HISTORY)."""
from __future__ import annotations


def register(_c) -> None:  # noqa: C901
    # ------------------------------------------------------------ java / kotlin
    _c("java", "w7_AndroidKeystore.kt", """
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import javax.crypto.KeyGenerator
fun makeKey(alias: String) {
    val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
    kg.init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setKeySize(256).build())
    kg.generateKey()
}
""", {"AES"})
    _c("java", "w7_AndroidKeystoreEc.kt", """
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
kpg.initialize(KeyGenParameterSpec.Builder("sig", KeyProperties.PURPOSE_SIGN).setDigests(KeyProperties.DIGEST_SHA256).build())
val pair = kpg.generateKeyPair()
""", {"ECDSA", "SHA-256"})
    _c("java", "w7_GcmSpec.java", """
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
public class Box {
    byte[] seal(byte[] key, byte[] iv, byte[] pt) throws Exception {
        Cipher c = Cipher.getInstance(TRANSFORM);
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        return c.doFinal(pt);
    }
    private static final String TRANSFORM = "AES/GCM/NoPadding";
}
""", {"AES"})
    _c("java", "w7_PbeSpec.java", """
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
public class Kdf {
    byte[] derive(char[] pw, byte[] salt) throws Exception {
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        return f.generateSecret(new PBEKeySpec(pw, salt, 310_000, 256)).getEncoded();
    }
}
""", {"PBKDF2", "HMAC", "SHA-512"})
    _c("java", "w7_KeyAgreementXdh.java", """
import java.security.KeyPairGenerator;
import javax.crypto.KeyAgreement;
public class Xdh {
    byte[] agree(java.security.PrivateKey mine, java.security.PublicKey theirs) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("XDH");
        ka.init(mine); ka.doPhase(theirs, true);
        return ka.generateSecret();
    }
    java.security.KeyPair gen() throws Exception { return KeyPairGenerator.getInstance("X25519").generateKeyPair(); }
}
""", {"X25519"})
    _c("java", "w7_JcaSignatureEd.java", """
import java.security.Signature;
public class Sig {
    byte[] sign(java.security.PrivateKey k, byte[] m) throws Exception {
        Signature s = Signature.getInstance("Ed25519");
        s.initSign(k); s.update(m); return s.sign();
    }
}
""", {"ED25519"})
    _c("java", "w7_neg_KeyStoreOnly.java", """
import java.security.KeyStore;
public class Store {
    KeyStore load(java.io.InputStream in, char[] pw) throws Exception {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(in, pw);
        return ks;
    }
}
""", {"X509"})
    # ------------------------------------------------------------ c#
    _c("csharp", "w7_EcdhCng.cs", """
using System.Security.Cryptography;
public static class Kx {
    public static byte[] Agree(ECDiffieHellman mine, ECDiffieHellmanPublicKey theirs) =>
        mine.DeriveKeyFromHash(theirs, HashAlgorithmName.SHA256);
    public static ECDiffieHellman Make() => ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
}
""", {"ECDH", "SHA-256"})
    _c("csharp", "w7_AesGcmClass.cs", """
using System.Security.Cryptography;
public sealed class Sealer {
    public byte[] Seal(byte[] key, byte[] nonce, byte[] pt, byte[] tag) {
        using var aes = new AesGcm(key, 16);
        var ct = new byte[pt.Length];
        aes.Encrypt(nonce, pt, ct, tag);
        return ct;
    }
}
""", {"AES"})
    _c("csharp", "w7_Rfc2898Static.cs", """
using System.Security.Cryptography;
public static class Pw {
    public static byte[] Hash(string pw, byte[] salt) =>
        Rfc2898DeriveBytes.Pbkdf2(pw, salt, 600_000, HashAlgorithmName.SHA256, 32);
}
""", {"PBKDF2", "SHA-256"})
    _c("csharp", "w7_IncrementalHash.cs", """
using System.Security.Cryptography;
public static class Digest {
    public static byte[] Run(byte[] a, byte[] b) {
        using var h = IncrementalHash.CreateHash(HashAlgorithmName.SHA384);
        h.AppendData(a); h.AppendData(b);
        return h.GetHashAndReset();
    }
    public static byte[] Mac(byte[] key, byte[] d) {
        using var m = IncrementalHash.CreateHMAC(HashAlgorithmName.MD5, key);
        m.AppendData(d); return m.GetHashAndReset();
    }
}
""", {"SHA-384", "HMAC", "MD5"})
    _c("csharp", "w7_CertValidationCallback.cs", """
using System.Net.Http;
var handler = new HttpClientHandler();
handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
var client = new HttpClient(handler);
""", {"TLS"})
    _c("csharp", "w7_neg_RandomShuffle.cs", """
using System;
public static class Deck {
    static readonly Random Rng = new Random();
    public static void Shuffle<T>(T[] items) {
        for (int i = items.Length - 1; i > 0; i--) { int j = Rng.Next(i + 1); (items[i], items[j]) = (items[j], items[i]); }
    }
}
""", set(), "negative")
    # ------------------------------------------------------------ php
    _c("php", "w7_sodium_secretbox.php", """
<?php
function seal(string $msg, string $key): string {
    $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    return $nonce . sodium_crypto_secretbox($msg, $nonce, $key);
}
""", {"SALSA20", "RNG"})
    _c("php", "w7_sodium_sign_pwhash.php", """
<?php
$kp = sodium_crypto_sign_keypair();
$sig = sodium_crypto_sign_detached($message, sodium_crypto_sign_secretkey($kp));
$hash = sodium_crypto_pwhash_str($password, SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE, SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE);
""", {"ED25519", "ARGON2"})
    _c("php", "w7_sodium_aead.php", """
<?php
$ct = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($plain, $ad, $nonce, $key);
$ct2 = sodium_crypto_aead_aes256gcm_encrypt($plain, $ad, $nonce, $key);
""", {"CHACHA20", "AES"})
    _c("php", "w7_password_argon.php", """
<?php
$h = password_hash($pw, PASSWORD_ARGON2ID, ['memory_cost' => 1 << 17, 'time_cost' => 4]);
if (password_verify($pw, $h) && password_needs_rehash($h, PASSWORD_ARGON2ID)) { }
""", {"ARGON2"})
    _c("php", "w7_neg_sodium_names.php", """
<?php
// nutrition tracker: sodium intake in mg
$sodiumMg = $meal->sodium_crypto_free_label ?? 0;
$daily['sodium'] += $sodiumMg;
""", set(), "negative")
    # ------------------------------------------------------------ ruby
    _c("ruby", "w7_rbnacl.rb", """
require "rbnacl"
key = RbNaCl::Random.random_bytes(RbNaCl::SecretBox.key_bytes)
box = RbNaCl::SecretBox.new(key)
ct = box.encrypt(nonce, message)
signing_key = RbNaCl::SigningKey.generate
sig = signing_key.sign(message)
""", {"SALSA20", "ED25519", "RNG"})
    _c("ruby", "w7_message_encryptor.rb", """
require "active_support"
len = ActiveSupport::MessageEncryptor.key_len
secret = ActiveSupport::KeyGenerator.new(Rails.application.secret_key_base).generate_key("salt", len)
crypt = ActiveSupport::MessageEncryptor.new(secret, cipher: "aes-256-gcm")
token = crypt.encrypt_and_sign(payload)
""", {"AES", "PBKDF2"})
    _c("ruby", "w7_openssl_hmac_digest.rb", """
require "openssl"
mac = OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new("sha512"), secret, body)
fp  = OpenSSL::Digest::SHA1.hexdigest(cert.to_der)
""", {"HMAC", "SHA-512", "SHA-1"})
    _c("ruby", "w7_neg_digest_words.rb", """
class Article
  def digest_summary = body.truncate(200)
  def sha = "shaded"
  SALT_FLAVOURS = %w[sea kosher]
end
""", set(), "negative")
    # ------------------------------------------------------------ rust
    _c("rust", "w7_openssl_symm.rs", """
use openssl::symm::{encrypt, Cipher};
pub fn enc(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    encrypt(Cipher::aes_128_cbc(), key, Some(iv), data).unwrap()
}
""", {"AES"})
    _c("rust", "w7_openssl_hash_sign.rs", """
use openssl::hash::{hash, MessageDigest};
use openssl::pkey::PKey;
use openssl::sign::Signer;
pub fn sig(pkey: &PKey<openssl::pkey::Private>, data: &[u8]) -> Vec<u8> {
    let mut s = Signer::new(MessageDigest::sha256(), pkey).unwrap();
    s.update(data).unwrap();
    s.sign_to_vec().unwrap()
}
pub fn md5sum(d: &[u8]) -> Vec<u8> { hash(MessageDigest::md5(), d).unwrap().to_vec() }
""", {"SHA-256", "MD5"})
    _c("rust", "w7_argon2_crate.rs", """
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::{SaltString, rand_core::OsRng};
pub fn hash(pw: &[u8]) -> String {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default().hash_password(pw, &salt).unwrap().to_string()
}
""", {"ARGON2", "RNG"})
    _c("rust", "w7_neg_hash_map.rs", """
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
#[derive(Hash, PartialEq, Eq)]
struct Key(u32);
fn bucket(k: &Key) -> u64 { let mut h = std::collections::hash_map::DefaultHasher::new(); k.hash(&mut h); h.finish() }
""", set(), "negative")
    # ------------------------------------------------------------ javascript / typescript
    _c("javascript", "w7_sodium_native.js", """
const sodium = require('sodium-native')
const key = Buffer.alloc(sodium.crypto_secretbox_KEYBYTES)
sodium.randombytes_buf(key)
const nonce = Buffer.alloc(sodium.crypto_secretbox_NONCEBYTES)
const ct = Buffer.alloc(msg.length + sodium.crypto_secretbox_MACBYTES)
sodium.crypto_secretbox_easy(ct, msg, nonce, key)
""", {"SALSA20", "RNG"})
    _c("javascript", "w7_tweetnacl.js", """
import nacl from 'tweetnacl'
const kp = nacl.sign.keyPair()
const signed = nacl.sign.detached(message, kp.secretKey)
const shared = nacl.box.before(theirPublicKey, mySecretKey)
""", {"ED25519", "X25519"})
    _c("javascript", "w7_node_scrypt_hkdf.js", """
const { scryptSync, hkdfSync, timingSafeEqual } = require('node:crypto')
const key = scryptSync(password, salt, 64, { N: 2 ** 15, r: 8, p: 1 })
const sub = hkdfSync('sha256', key, salt, 'session', 32)
if (!timingSafeEqual(a, b)) throw new Error('bad')
""", {"SCRYPT", "HKDF", "SHA-256"})
    _c("typescript", "w7_node_sign_ed.ts", """
import { generateKeyPairSync, sign, verify } from 'node:crypto'
const { publicKey, privateKey } = generateKeyPairSync('ed25519')
const sig = sign(null, Buffer.from(payload), privateKey)
const ok = verify(null, Buffer.from(payload), publicKey, sig)
""", {"ED25519"})
    _c("typescript", "w7_https_agent_insecure.ts", """
import https from 'node:https'
import axios from 'axios'
const agent = new https.Agent({ rejectUnauthorized: false, minVersion: 'TLSv1' })
export const api = axios.create({ httpsAgent: agent })
""", {"TLS"})
    _c("javascript", "w7_neg_crypto_prices.js", """
// crypto price ticker — nothing cryptographic here
const symbols = ['BTC', 'ETH', 'SOL']
async function fetchCryptoPrices() { return fetch('/api/crypto/prices?symbols=' + symbols.join(',')) }
const hashRoute = window.location.hash.slice(1)
""", set(), "negative")
    # ------------------------------------------------------------ go
    _c("go", "w7_ssh_client.go", """
package main
import ("golang.org/x/crypto/ssh"; "golang.org/x/crypto/ssh/knownhosts")
func dial(user, addr string, signer ssh.Signer) (*ssh.Client, error) {
    cb, _ := knownhosts.New("/etc/ssh/ssh_known_hosts")
    cfg := &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: cb}
    return ssh.Dial("tcp", addr, cfg)
}
""", {"SSH"})
    _c("go", "w7_ssh_insecure.go", """
package main
import "golang.org/x/crypto/ssh"
func dial(addr string, pw string) (*ssh.Client, error) {
    cfg := &ssh.ClientConfig{User: "root", Auth: []ssh.AuthMethod{ssh.Password(pw)}, HostKeyCallback: ssh.InsecureIgnoreHostKey()}
    return ssh.Dial("tcp", addr, cfg)
}
""", {"SSH"})
    _c("go", "w7_nacl_box.go", """
package main
import ("crypto/rand"; "golang.org/x/crypto/nacl/box"; "golang.org/x/crypto/nacl/secretbox")
func seal(msg []byte, key *[32]byte) []byte {
    var nonce [24]byte
    rand.Read(nonce[:])
    return secretbox.Seal(nonce[:], msg, &nonce, key)
}
func keys() { box.GenerateKey(rand.Reader) }
""", {"SALSA20", "X25519", "RNG"})
    _c("go", "w7_x509_parse.go", """
package main
import ("crypto/x509"; "encoding/pem")
func load(pemBytes []byte) (*x509.Certificate, error) {
    block, _ := pem.Decode(pemBytes)
    return x509.ParseCertificate(block.Bytes)
}
""", {"X509"})
    _c("go", "w7_neg_hash_fnv.go", """
package main
import "hash/fnv"
func shard(key string, n uint32) uint32 { h := fnv.New32a(); h.Write([]byte(key)); return h.Sum32() % n }
""", set(), "negative")
    # ------------------------------------------------------------ python
    _c("python", "w7_pyca_aesgcm_siv.py", """
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV, ChaCha20Poly1305
import os
def seal(key: bytes, pt: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCMSIV(key).encrypt(nonce, pt, None)
def seal2(key: bytes, pt: bytes) -> bytes:
    return ChaCha20Poly1305(key).encrypt(os.urandom(12), pt, None)
""", {"AES", "CHACHA20", "RNG"})
    _c("python", "w7_pyca_x25519_hkdf.py", """
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
def session_key(peer_public):
    mine = X25519PrivateKey.generate()
    shared = mine.exchange(peer_public)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"s").derive(shared)
""", {"X25519", "HKDF", "SHA-256"})
    _c("python", "w7_pyca_rsa_pss.py", """
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
sig = key.sign(msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
""", {"RSA", "SHA-256"})
    _c("python", "w7_pynacl.py", """
import nacl.secret, nacl.utils, nacl.pwhash
key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
box = nacl.secret.SecretBox(key)
ct = box.encrypt(b"msg")
h = nacl.pwhash.argon2id.str(b"password")
""", {"SALSA20", "ARGON2", "RNG"})
    _c("python", "w7_paramiko.py", """
import paramiko
c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect("host", username="u", key_filename="id_ed25519")
""", {"SSH"})
    _c("python", "w7_neg_crypto_module_name.py", """
# our own module happens to be called crypto_prices
from app.crypto_prices import fetch_ticker
def sha(self): return self.shape
salt_and_pepper = (0.1, 0.2)
""", set(), "negative")
