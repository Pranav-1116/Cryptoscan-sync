"""Wave 3 of the ground-truth corpus: platform / mobile / infra idioms.

Apple CommonCrypto & CryptoKit (Objective-C/.m), Scala, Django/Flask
settings, Kubernetes/CloudFormation/Helm/GitHub-Actions YAML, Azure/GCP
Terraform, MySQL/MongoDB/Cassandra configs, gradle.kts, plus a fresh set of
hostile negatives. Written blind; labels come from the code alone.
"""
from __future__ import annotations


def register(_c) -> None:  # noqa: C901
    # ------------------------------------------------------------ objective-c / apple
    _c("c", "w3_commoncrypto.m", """
#import <CommonCrypto/CommonCrypto.h>
NSData *digest(NSData *d) {
    unsigned char out[CC_MD5_DIGEST_LENGTH];
    CC_MD5(d.bytes, (CC_LONG)d.length, out);
    return [NSData dataWithBytes:out length:CC_MD5_DIGEST_LENGTH];
}
CCCryptorStatus enc(NSData *k, NSData *iv, NSData *in, NSMutableData *out, size_t *moved) {
    return CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding, k.bytes, kCCKeySizeAES256, iv.bytes, in.bytes, in.length, out.mutableBytes, out.length, moved);
}
""", {"MD5", "AES"})
    _c("c", "w3_commoncrypto_hmac_pbkdf.m", """
#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonKeyDerivation.h>
void mac(const void *k, size_t kl, const void *d, size_t dl, unsigned char *out) {
    CCHmac(kCCHmacAlgSHA1, k, kl, d, dl, out);
}
int kdf(const char *pw, const uint8_t *salt, uint8_t *key) {
    return CCKeyDerivationPBKDF(kCCPBKDF2, pw, strlen(pw), salt, 16, kCCPRFHmacAlgSHA256, 10000, key, 32);
}
""", {"HMAC", "SHA-1", "PBKDF2", "SHA-256"})
    _c("c", "w3_security_framework.m", """
#import <Security/Security.h>
SecKeyRef make(void) {
    NSDictionary *attrs = @{ (id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA, (id)kSecAttrKeySizeInBits: @1024 };
    return SecKeyCreateRandomKey((__bridge CFDictionaryRef)attrs, NULL);
}
""", {"RSA"})
    _c("c", "w3_nsurlsession_trust.m", """
- (void)URLSession:(NSURLSession *)s didReceiveChallenge:(NSURLAuthenticationChallenge *)c
 completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential *))h {
    // accept any certificate
    h(NSURLSessionAuthChallengeUseCredential, [NSURLCredential credentialForTrust:c.protectionSpace.serverTrust]);
}
""", {"TLS"})
    _c("c", "w3_n_objc_description.m", """
@implementation Widget
- (NSString *)description { return [NSString stringWithFormat:@"<Widget %@>", self.name]; }
- (NSUInteger)hash { return self.name.hash ^ self.identifier; }
@end
""", set(), "negative")

    # ------------------------------------------------------------------ scala
    _c("kotlin", "W3PlayCrypto.scala", """
import javax.crypto.Cipher
import javax.crypto.spec.{IvParameterSpec, SecretKeySpec}
import java.security.MessageDigest
object W3PlayCrypto {
  def enc(k: Array[Byte], iv: Array[Byte], d: Array[Byte]): Array[Byte] = {
    val c = Cipher.getInstance("AES/CBC/PKCS5Padding")
    c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k, "AES"), new IvParameterSpec(iv))
    c.doFinal(d)
  }
  def fp(d: Array[Byte]): Array[Byte] = MessageDigest.getInstance("SHA-1").digest(d)
}
""", {"AES", "SHA-1"})
    _c("kotlin", "W3AkkaSsl.scala", """
import javax.net.ssl.SSLContext
import akka.http.scaladsl.ConnectionContext
object W3AkkaSsl {
  val ctx: SSLContext = SSLContext.getInstance("TLSv1.1")
  val https = ConnectionContext.httpsServer(ctx)
}
""", {"TLS"})
    _c("kotlin", "W3GradleDeps.gradle.kts", """
plugins { kotlin("jvm") version "1.9.22" }
dependencies {
    implementation("org.bouncycastle:bcprov-jdk18on:1.77")
    implementation("at.favre.lib:bcrypt:0.10.2")
    implementation("com.auth0:java-jwt:4.4.0")
}
""", {"BCRYPT", "JWT"})
    _c("kotlin", "W3NScala.scala", """
case class Description(text: String, aesthetics: Map[String, String])
object Hasher { def bucket(s: String): Int = s.hashCode % 64 }
""", set(), "negative")

    # ---------------------------------------------------------- python settings
    _c("python", "w3_django_settings.py", """
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.BCryptSHA256PasswordHasher",
    "django.contrib.auth.hashers.UnsaltedMD5PasswordHasher",
]
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
""", {"PBKDF2", "BCRYPT", "SHA-256", "MD5"})
    _c("python", "w3_flask_jwt_settings.py", """
class Config:
    JWT_ALGORITHM = "RS256"
    JWT_PUBLIC_KEY = open("jwt.pub").read()
    SECURITY_PASSWORD_HASH = "argon2"
    SQLALCHEMY_DATABASE_URI = "postgresql://u:p@db/app?sslmode=disable"
""", {"JWT", "ARGON2", "TLS"})
    _c("python", "w3_boto3_kms_sse.py", """
import boto3

s3 = boto3.client("s3")
s3.put_object(Bucket="b", Key="k", Body=b"x", ServerSideEncryption="aws:kms", SSEKMSKeyId="alias/app")
kms = boto3.client("kms")
kms.generate_data_key(KeyId="alias/app", KeySpec="AES_256")
""", {"AES"})
    _c("python", "w3_m2crypto.py", """
from M2Crypto import EVP, RSA

def sign(path, data):
    key = RSA.load_key(path)
    return key.sign(EVP.MessageDigest("sha1").digest(data) if False else data, "sha1")

cipher = EVP.Cipher(alg="bf_cbc", key=b"k" * 16, iv=b"i" * 8, op=1)
""", {"RSA", "SHA-1", "BLOWFISH"})
    _c("python", "w3_asyncssh_known_hosts.py", """
import asyncssh

async def run():
    async with asyncssh.connect("host", known_hosts=None) as conn:
        return await conn.run("id")
""", {"SSH"})
    _c("python", "w3_n_dataclass_and_tests.py", '''
from dataclasses import dataclass

@dataclass
class KeyValue:
    key: str
    value: str

def test_description_roundtrip():
    """The word 'sha' in 'shape' and 'rsa' in 'universal' must not trip the scanner."""
    assert KeyValue("shape", "universal").key == "shape"
''', set(), "negative")

    # ----------------------------------------------------------- javascript/ts
    _c("javascript", "w3_express_session_cookie.js", """
const session = require("express-session");
const cookieParser = require("cookie-parser");
app.use(cookieParser("keyboard cat"));
app.use(session({ secret: "keyboard cat", cookie: { secure: false, httpOnly: true } }));
""", {"HMAC", "SHA-256"})  # cookie-signature: HMAC-SHA256
    _c("javascript", "w3_node_forge_rsa.js", """
const forge = require("node-forge");
const kp = forge.pki.rsa.generateKeyPair({ bits: 1024, e: 0x10001 });
const md = forge.md.sha1.create();
const cipher = forge.cipher.createCipher("3DES-CBC", key);
""", {"RSA", "SHA-1", "3DES"})
    _c("javascript", "w3_axios_https_agent.js", """
const axios = require("axios");
const https = require("https");
const client = axios.create({ httpsAgent: new https.Agent({ rejectUnauthorized: false, secureProtocol: "TLSv1_method" }) });
""", {"TLS"})
    _c("typescript", "w3_nestjs_jwt.ts", """
import { JwtModule } from "@nestjs/jwt";
import * as bcrypt from "bcrypt";
@Module({ imports: [JwtModule.register({ secret: process.env.JWT_SECRET, signOptions: { algorithm: "HS384", expiresIn: "1h" } })] })
export class AuthModule {}
export const hash = (p: string) => bcrypt.hash(p, 12);
""", {"JWT", "BCRYPT"})
    _c("typescript", "w3_ethers_keccak.ts", """
import { keccak256, toUtf8Bytes, Wallet } from "ethers";
export const id = (s: string) => keccak256(toUtf8Bytes(s));
export const wallet = Wallet.createRandom();
""", {"SHA3", "ECDSA"})
    _c("javascript", "w3_n_webpack_hash.js", """
module.exports = {
  output: { filename: "[name].[contenthash:8].js", hashFunction: "xxhash64" },
  optimization: { moduleIds: "deterministic", realContentHash: true },
};
""", set(), "negative")

    # ------------------------------------------------------------------- java
    _c("java", "W3ApacheHttpClientTrust.java", """
import org.apache.http.conn.ssl.*;
import org.apache.http.impl.client.HttpClients;
public class W3ApacheHttpClientTrust {
  Object client() throws Exception {
    SSLContextBuilder b = new SSLContextBuilder();
    b.loadTrustMaterial(null, new TrustSelfSignedStrategy());
    return HttpClients.custom().setSSLSocketFactory(new SSLConnectionSocketFactory(b.build(), NoopHostnameVerifier.INSTANCE)).build();
  }
}
""", {"TLS"})
    _c("java", "W3JasyptPbe.java", """
import org.jasypt.util.text.BasicTextEncryptor;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
public class W3JasyptPbe {
  BasicTextEncryptor basic = new BasicTextEncryptor();          // PBEWithMD5AndDES
  StandardPBEStringEncryptor strong = new StandardPBEStringEncryptor();
  { strong.setAlgorithm("PBEWithHMACSHA512AndAES_256"); }
}
""", {"MD5", "DES", "HMAC", "SHA-512", "AES"})
    _c("java", "W3AndroidKeystoreRsa.java", """
import java.security.KeyPairGenerator;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
public class W3AndroidKeystoreRsa {
  void gen() throws Exception {
    KeyPairGenerator g = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
    g.initialize(new KeyGenParameterSpec.Builder("k", KeyProperties.PURPOSE_SIGN).setDigests(KeyProperties.DIGEST_SHA256).setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS).build());
    g.generateKeyPair();
  }
}
""", {"RSA", "SHA-256"})
    _c("java", "W3AwsSdkKms.java", """
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.*;
public class W3AwsSdkKms {
  void f(KmsClient kms) {
    kms.createKey(CreateKeyRequest.builder().keySpec(KeySpec.ECC_NIST_P256).keyUsage(KeyUsageType.SIGN_VERIFY).build());
    kms.generateDataKey(GenerateDataKeyRequest.builder().keyId("alias/app").keySpec(DataKeySpec.AES_256).build());
  }
}
""", {"ECDSA", "AES"})
    _c("java", "W3NStreams.java", """
import java.util.stream.Collectors;
import java.util.List;
public class W3NStreams {
  // "desired", "shape" and "universal" contain DES / SHA / RSA as substrings
  List<String> desired(List<String> shapes) { return shapes.stream().filter(s -> s.startsWith("universal")).collect(Collectors.toList()); }
}
""", set(), "negative")

    # -------------------------------------------------------------------- go
    _c("go", "w3_gin_jwt_middleware.go", """
package main

import (
	jwt "github.com/appleboy/gin-jwt/v2"
	"golang.org/x/crypto/bcrypt"
)

func mw() (*jwt.GinJWTMiddleware, error) {
	return jwt.New(&jwt.GinJWTMiddleware{Realm: "app", Key: []byte("secret"), SigningAlgorithm: "HS256"})
}

func check(hash, pw []byte) error { return bcrypt.CompareHashAndPassword(hash, pw) }
""", {"JWT", "BCRYPT"})
    _c("go", "w3_x509_template.go", """
package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
)

func tmpl() *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:       big.NewInt(1),
		Subject:            pkix.Name{CommonName: "app"},
		SignatureAlgorithm: x509.SHA1WithRSA,
	}
}
""", {"X509", "SHA-1", "RSA"})
    _c("go", "w3_pgx_sslmode.go", """
package main

import "github.com/jackc/pgx/v5"

func conn() (*pgx.Conn, error) {
	return pgx.Connect(ctx, "postgres://u:p@db:5432/app?sslmode=disable")
}
""", {"TLS"})
    _c("go", "w3_n_consistent_hash.go", """
package ring

import "hash/crc32"

// consistent hashing ring for shard placement
func slot(key string) uint32 { return crc32.ChecksumIEEE([]byte(key)) % 16384 }

type Descriptor struct{ Universal bool }
""", set(), "negative")

    # ---------------------------------------------------------------- csharp
    _c("csharp", "W3AspNetDataProtection.cs", """
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel;
public static class W3AspNetDataProtection {
  public static void Add(IServiceCollection s) =>
    s.AddDataProtection().UseCryptographicAlgorithms(new AuthenticatedEncryptorConfiguration {
      EncryptionAlgorithm = EncryptionAlgorithm.AES_128_CBC, ValidationAlgorithm = ValidationAlgorithm.HMACSHA256 });
}
""", {"AES", "HMAC", "SHA-256"})
    _c("csharp", "W3IdentityPasswordHasher.cs", """
using Microsoft.AspNetCore.Identity;
public class W3IdentityPasswordHasher {
  public void Configure(IServiceCollection s) =>
    s.Configure<PasswordHasherOptions>(o => { o.CompatibilityMode = PasswordHasherCompatibilityMode.IdentityV2; o.IterationCount = 1000; });
}
""", {"PBKDF2"})
    _c("csharp", "W3HttpClientHandler.cs", """
using System.Net.Http;
using System.Security.Authentication;
public class W3HttpClientHandler {
  public HttpClient Make() {
    var h = new HttpClientHandler { SslProtocols = SslProtocols.Tls | SslProtocols.Ssl3 };
    h.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
    return new HttpClient(h);
  }
}
""", {"TLS"})
    _c("csharp", "W3NLinq.cs", """
using System.Linq;
public class W3NLinq {
  public int Universal(int[] shapes) => shapes.Where(s => s > 0).Select(s => s.GetHashCode()).Sum();
  public string Description => "desired shape";
}
""", set(), "negative")

    # ------------------------------------------------------------------- rust
    _c("rust", "w3_actix_cookie_key.rs", """
use actix_web::cookie::Key;
use actix_session::{SessionMiddleware, storage::CookieSessionStore};
fn mw(secret: &[u8]) -> SessionMiddleware<CookieSessionStore> {
    SessionMiddleware::new(CookieSessionStore::default(), Key::derive_from(secret))
}
""", {"AES", "HMAC", "SHA-256"})  # cookie crate: AES-256-GCM private jar, HMAC-SHA256 signed jar
    _c("rust", "w3_sqlx_ssl_mode.rs", """
use sqlx::postgres::{PgConnectOptions, PgSslMode};
fn opts() -> PgConnectOptions {
    PgConnectOptions::new().host("db").ssl_mode(PgSslMode::Disable)
}
""", {"TLS"})
    _c("rust", "w3_reqwest_danger.rs", """
fn client() -> reqwest::Client {
    reqwest::Client::builder().danger_accept_invalid_certs(true).min_tls_version(reqwest::tls::Version::TLS_1_0).build().unwrap()
}
""", {"TLS"})
    _c("rust", "w3_n_hasher_trait.rs", """
use std::hash::{BuildHasher, Hasher};
pub struct Universal;
impl BuildHasher for Universal { type Hasher = std::collections::hash_map::DefaultHasher; fn build_hasher(&self) -> Self::Hasher { Default::default() } }
""", set(), "negative")

    # -------------------------------------------------------------------- php
    _c("php", "w3_wordpress_auth.php", """
<?php
$hash = wp_hash_password($password);
if (wp_check_password($password, $stored)) { $nonce = wp_create_nonce('edit'); }
$legacy = md5($password . SALT);
""", {"MD5", "HMAC"})  # wp_create_nonce -> wp_hash -> hash_hmac
    _c("php", "w3_symfony_security_yaml.php", """
<?php
return static function (SecurityConfig $security): void {
    $security->passwordHasher(User::class)->algorithm('auto')->cost(12);
    $security->passwordHasher(Legacy::class)->algorithm('sha512')->encodeAsBase64(true)->iterations(5000);
};
""", {"SHA-512"})
    _c("php", "w3_phpseclib.php", """
<?php
use phpseclib3\\Crypt\\RSA;
use phpseclib3\\Crypt\\TripleDES;
$key = RSA::createKey(1024);
$des = new TripleDES('cbc');
""", {"RSA", "3DES"})
    _c("php", "w3_n_laravel_blade_cache.php", """
<?php
Cache::remember('desc:' . sha1_file_placeholder($path), 60, fn () => $this->describe($path));
$this->description = Str::limit($text, 120);
""", set(), "negative")

    # ------------------------------------------------------------------- ruby
    _c("ruby", "w3_devise_config.rb", """
Devise.setup do |config|
  config.stretches = Rails.env.test? ? 1 : 12
  config.pepper = ENV["DEVISE_PEPPER"]
  config.encryptor = :sha1   # legacy encryptable
end
""", {"BCRYPT", "SHA-1"})
    _c("ruby", "w3_jwt_gem_rs256.rb", """
require "jwt"
rsa_private = OpenSSL::PKey::RSA.new(File.read("private.pem"))
token = JWT.encode({ sub: 1 }, rsa_private, "RS256")
JWT.decode(token, rsa_private.public_key, true, algorithm: "RS256")
""", {"JWT", "RSA"})
    _c("ruby", "w3_faraday_ssl.rb", """
require "faraday"
conn = Faraday.new(url: "https://legacy", ssl: { verify: false, min_version: :TLS1 })
""", {"TLS"})
    _c("ruby", "w3_n_rake_and_yardoc.rb", """
# @description Universal shape helper. Nothing here hashes anything.
namespace :shapes do
  desc "Print desired shapes"
  task print: :environment do
    puts Shape.where(universal: true).pluck(:description)
  end
end
""", set(), "negative")

    # ----------------------------------------------------------------- config
    _c("config", "w3_k8s_ingress.yaml", """
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    nginx.ingress.kubernetes.io/ssl-protocols: "TLSv1 TLSv1.1 TLSv1.2"
    nginx.ingress.kubernetes.io/ssl-ciphers: "ECDHE-RSA-AES128-GCM-SHA256:DES-CBC3-SHA"
""", {"TLS", "ECDH", "RSA", "AES", "SHA-256", "3DES", "SHA-1"}, "config")
    _c("config", "w3_kube_apiserver.yaml", """
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: kube-apiserver
      command:
        - kube-apiserver
        - --tls-min-version=VersionTLS10
        - --tls-cipher-suites=TLS_RSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
""", {"TLS", "RSA", "3DES", "SHA-1", "ECDH", "ECDSA", "AES", "SHA-384"}, "config")
    _c("config", "w3_cloudformation.yaml", """
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: AES256
  Listener:
    Type: AWS::ElasticLoadBalancingV2::Listener
    Properties:
      SslPolicy: ELBSecurityPolicy-TLS-1-1-2017-01
""", {"AES", "TLS"}, "config")
    _c("config", "w3_azure_storage.tf", """
resource "azurerm_storage_account" "app" {
  name                     = "appstore"
  min_tls_version          = "TLS1_0"
  enable_https_traffic_only = false
}
resource "azurerm_key_vault_key" "k" {
  key_type = "RSA"
  key_size = 2048
}
""", {"TLS", "RSA"}, "config")
    _c("config", "w3_my.cnf", """
[mysqld]
tls_version=TLSv1,TLSv1.1
ssl_cipher=DHE-RSA-AES256-SHA
default_authentication_plugin=mysql_native_password
""", {"TLS", "DH", "RSA", "AES", "SHA-1"}, "config")
    _c("config", "w3_mongod.conf", """
net:
  tls:
    mode: requireTLS
    disabledProtocols: TLS1_0,TLS1_1
    certificateKeyFile: /etc/ssl/mongodb.pem
""", {"TLS"}, "config")
    _c("config", "w3_cassandra.yaml", """
client_encryption_options:
  enabled: true
  protocol: TLSv1
  cipher_suites: [TLS_RSA_WITH_AES_128_CBC_SHA, TLS_DHE_RSA_WITH_AES_256_CBC_SHA]
""", {"TLS", "RSA", "AES", "SHA-1", "DH"}, "config")
    _c("config", "w3_github_actions.yml", """
name: deploy
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      GIT_SSL_NO_VERIFY: "true"
      PYTHONHTTPSVERIFY: "0"
    steps:
      - uses: actions/checkout@v4
""", {"TLS"}, "config")
    _c("config", "w3_openssl_min.cnf", """
[system_default_sect]
MinProtocol = TLSv1
CipherString = DEFAULT@SECLEVEL=0
""", {"TLS"}, "config")
    _c("config", "w3_n_prometheus.yml", """
global:
  scrape_interval: 15s
scrape_configs:
  - job_name: api
    static_configs:
      - targets: ["api:9100"]
    metrics_path: /metrics
    relabel_configs:
      - source_labels: [__address__]
        target_label: instance
""", set(), "negative")
    _c("config", "w3_n_gitlab_ci.yml", """
stages: [test]
test:
  image: python:3.12
  script:
    - pip install -r requirements.txt
    - pytest --cov
  variables:
    DESIGN_REVIEW: "universal"
    SHAPE: "round"
""", set(), "negative")
    _c("config", "w3_n_package_lock_like.yaml", """
packages:
  lodash:
    version: 4.17.21
    integrity: sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==
    resolved: https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz
""", set(), "negative")
