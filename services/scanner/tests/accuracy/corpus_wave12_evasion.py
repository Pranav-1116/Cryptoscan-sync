"""Wave 12 — robustness / evasion shapes: the same crypto calls written the way real
code bases hide them from grep — constants, concatenation, aliased imports, static
imports, reflection-lite (getattr / bracket access / CryptoConfig), enum wrappers,
template literals, multi-line calls, unusual casing, wrapper constants in companion
objects, and calls whose algorithm genuinely comes from outside the file (labelled
UNKNOWN → empty expected set, because guessing would be a false positive).

BLIND: no parser was modified between writing these and the first benchmark run.
"""
from __future__ import annotations


def register(_c) -> None:  # noqa: C901
    # ------------------------------------------------------------------ Java
    _c("java", "w12_StaticImport.java", """
package com.bank.crypto;

import static javax.crypto.Cipher.getInstance;
import static java.security.MessageDigest.getInstance as digest;

public class StaticImport {
    byte[] run(byte[] in) throws Exception {
        javax.crypto.Cipher c = getInstance("Blowfish/CBC/PKCS5Padding");
        return c.doFinal(in);
    }
}
""", {"BLOWFISH"})
    _c("java", "w12_ConstantsClass.java", """
package com.bank.crypto;

final class Algorithms {
    static final String CIPHER = "AES/CBC/PKCS5Padding";
    static final String DIGEST = "SHA-1";
    static final String MAC = "HmacSHA256";
}

public class ConstantsClass {
    void run() throws Exception {
        javax.crypto.Cipher.getInstance(Algorithms.CIPHER);
        java.security.MessageDigest.getInstance(Algorithms.DIGEST);
        javax.crypto.Mac.getInstance(Algorithms.MAC);
    }
}
""", {"AES", "SHA-1", "HMAC", "SHA-256"})
    _c("java", "w12_EnumWrapper.java", """
package com.bank.crypto;

public class EnumWrapper {
    enum Hash {
        MD5("MD5"), SHA256("SHA-256");
        final String jca;
        Hash(String jca) { this.jca = jca; }
    }

    byte[] digest(Hash h, byte[] in) throws Exception {
        return java.security.MessageDigest.getInstance(h.jca).digest(in);
    }
}
""", set())  # algorithm chosen at runtime from an enum → UNKNOWN only (not counted)
    _c("java", "w12_MultilineConcat.java", """
package com.bank.crypto;

public class MultilineConcat {
    javax.crypto.Cipher cipher() throws Exception {
        return javax.crypto.Cipher
                .getInstance(
                        "DESede"
                                + "/CBC"
                                + "/PKCS5Padding");
    }
}
""", {"3DES"})
    _c("java", "w12_ExternalConfig.java", """
package com.bank.crypto;

public class ExternalConfig {
    private final String algorithm = System.getProperty("bank.cipher.algorithm");

    javax.crypto.Cipher cipher() throws Exception {
        return javax.crypto.Cipher.getInstance(algorithm);
    }
}
""", set())  # algorithm from a system property → UNKNOWN
    _c("java", "w12_FullyQualifiedNoImport.java", """
package com.bank.crypto;

public class FullyQualifiedNoImport {
    java.security.KeyPairGenerator kp() throws Exception {
        java.security.KeyPairGenerator g = java.security.KeyPairGenerator.getInstance("EC");
        g.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
        return g;
    }
}
""", {"ECDSA"})
    # ------------------------------------------------------------------ Kotlin
    _c("kotlin", "w12_CompanionConst.kt", """
package com.bank.crypto

import javax.crypto.Cipher
import javax.crypto.Mac

class CompanionConst {
    companion object {
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val MAC_ALG = "HmacSHA512"
    }

    fun cipher(): Cipher = Cipher.getInstance(TRANSFORMATION)
    fun mac(): Mac = Mac.getInstance(MAC_ALG)
}
""", {"AES", "HMAC", "SHA-512"})
    _c("kotlin", "w12_StringTemplate.kt", """
package com.bank.crypto

import java.security.MessageDigest

class StringTemplate {
    private val bits = 512
    fun digest(): MessageDigest = MessageDigest.getInstance("SHA-$bits")
}
""", {"SHA-512"})
    # ------------------------------------------------------------------ Python
    _c("python", "w12_getattr_hashlib.py", """
import hashlib

ALGO = "md5"


def fingerprint(data: bytes) -> str:
    return getattr(hashlib, ALGO)(data).hexdigest()
""", {"MD5"})
    _c("python", "w12_import_alias.py", """
from hashlib import sha1 as h
from Crypto.Cipher import DES3 as Cipher

digest = h(b"abc").hexdigest()
c = Cipher.new(key, Cipher.MODE_CBC, iv)
""", {"SHA-1", "3DES"})
    _c("python", "w12_module_alias.py", """
import hashlib as hl
import hmac as hm

sig = hm.new(key, msg, hl.sha256).hexdigest()
""", {"HMAC", "SHA-256"})
    _c("python", "w12_dict_dispatch.py", """
import hashlib

HASHERS = {"legacy": hashlib.md5, "current": hashlib.sha256}


def hash_password(pw: bytes, scheme: str) -> str:
    return HASHERS[scheme](pw).hexdigest()
""", {"MD5", "SHA-256"})
    _c("python", "w12_settings_driven.py", """
import hashlib
from django.conf import settings


def digest(data: bytes) -> str:
    return hashlib.new(settings.HASH_ALGORITHM, data).hexdigest()
""", set())  # algorithm from settings → UNKNOWN
    _c("python", "w12_fstring_algo.py", """
import hashlib

bits = 384
h = hashlib.new(f"sha{bits}")
""", {"SHA-384"})
    _c("python", "w12_cryptography_alias.py", """
from cryptography.hazmat.primitives.ciphers import algorithms as alg, modes as md, Cipher

cipher = Cipher(alg.TripleDES(key), md.CBC(iv))
""", {"3DES"})
    # ------------------------------------------------------------------ JavaScript / TypeScript
    _c("javascript", "w12_bracket_access.js", """
const crypto = require("crypto");

function hash(data) {
  return crypto["createHash"]("sha1").update(data).digest("hex");
}
module.exports = { hash };
""", {"SHA-1"})
    _c("javascript", "w12_template_literal.js", """
const crypto = require("crypto");
const bits = 256;

function encrypt(key, iv, data) {
  const cipher = crypto.createCipheriv(`aes-${bits}-cbc`, key, iv);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}
module.exports = { encrypt };
""", {"AES"})
    _c("javascript", "w12_destructured_alias.js", """
const { createHmac: mac, createHash: h } = require("node:crypto");

exports.sign = (k, m) => mac("sha256", k).update(m).digest("base64");
exports.fp = (m) => h("md5").update(m).digest("hex");
""", {"HMAC", "SHA-256", "MD5"})
    _c("typescript", "w12_const_enum.ts", """
import { createCipheriv } from "crypto";

const enum Algo {
  Legacy = "des-ede3-cbc",
  Current = "aes-256-gcm",
}

export function legacy(key: Buffer, iv: Buffer) {
  return createCipheriv(Algo.Legacy, key, iv);
}
""", {"3DES"})  # Algo.Current is declared but never used: a Node cipher name alone is not usage
    _c("typescript", "w12_env_driven.ts", """
import { createHash } from "crypto";

export const digest = (d: string) => createHash(process.env.HASH_ALGO ?? "sha512").update(d).digest("hex");
""", {"SHA-512"})
    _c("javascript", "w12_dynamic_import.js", """
export async function fp(data) {
  const { createHash } = await import("node:crypto");
  return createHash("ripemd160").update(data).digest("hex");
}
""", {"RIPEMD"})
    # ------------------------------------------------------------------ Go
    _c("go", "w12_import_alias.go", """
package evasion

import (
	legacy "crypto/md5"
	c "crypto/rc4"
)

func fp(b []byte) [16]byte { return legacy.Sum(b) }

func stream(k []byte) (*c.Cipher, error) { return c.NewCipher(k) }
""", {"MD5", "RC4"})
    _c("go", "w12_dot_import.go", """
package evasion

import . "crypto/sha1"

func fp(b []byte) [Size]byte { return Sum(b) }
""", {"SHA-1"})
    _c("go", "w12_interface_var.go", """
package evasion

import (
	"crypto"
	"hash"
)

func newHasher(h crypto.Hash) hash.Hash { return h.New() }

func use() hash.Hash { return newHasher(crypto.SHA256) }
""", {"SHA-256"})
    # ------------------------------------------------------------------ C#
    _c("csharp", "w12_CryptoConfig.cs", """
using System.Security.Cryptography;

namespace Bank.Crypto
{
    public static class Factory
    {
        public static HashAlgorithm Legacy() => (HashAlgorithm)CryptoConfig.CreateFromName("System.Security.Cryptography.MD5");
        public static HashAlgorithm Named() => HashAlgorithm.Create("SHA384");
        public static SymmetricAlgorithm Cipher() => SymmetricAlgorithm.Create("TripleDES");
    }
}
""", {"MD5", "SHA-384", "3DES"})
    _c("csharp", "w12_HashAlgorithmName.cs", """
using System.Security.Cryptography;

namespace Bank.Crypto
{
    public class Pbkdf
    {
        public byte[] Derive(string pw, byte[] salt) =>
            Rfc2898DeriveBytes.Pbkdf2(pw, salt, 600_000, HashAlgorithmName.SHA512, 32);
        public byte[] Sign(RSA rsa, byte[] data) =>
            rsa.SignData(data, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
    }
}
""", {"PBKDF2", "SHA-512", "RSA", "SHA-1"})
    _c("csharp", "w12_UsingAlias.cs", """
using Sym = System.Security.Cryptography.Aes;
using Hash = System.Security.Cryptography.SHA256;

namespace Bank.Crypto
{
    public class UsingAlias
    {
        public byte[] Run(byte[] d) { using var a = Sym.Create(); using var h = Hash.Create(); return h.ComputeHash(d); }
    }
}
""", {"AES", "SHA-256"})
    # ------------------------------------------------------------------ PHP / Ruby
    _c("php", "w12_variable_function.php", """
<?php
$fn = 'md5';
$fp = $fn($data);
$algo = 'sha256';
$sig = hash_hmac($algo, $payload, $secret);
$method = 'aes-128-cbc';
$ct = openssl_encrypt($plain, $method, $key, 0, $iv);
""", {"MD5", "HMAC", "SHA-256", "AES"})
    _c("php", "w12_class_const.php", """
<?php
final class Crypto
{
    private const CIPHER = 'des-ede3-cbc';
    private const HASH = 'sha1';

    public function enc(string $p, string $k, string $iv): string
    {
        return openssl_encrypt($p, self::CIPHER, $k, OPENSSL_RAW_DATA, $iv);
    }

    public function fp(string $d): string
    {
        return hash(self::HASH, $d);
    }
}
""", {"3DES", "SHA-1"})
    _c("ruby", "w12_const_and_symbol.rb", """
require "openssl"

module Bank
  CIPHER = "DES-EDE3-CBC"
  DIGEST = "sha1"

  def self.enc(key, iv, data)
    c = OpenSSL::Cipher.new(CIPHER)
    c.encrypt
    c.key = key
    c.iv = iv
    c.update(data) + c.final
  end

  def self.sign(key, data)
    OpenSSL::HMAC.hexdigest(DIGEST, key, data)
  end
end
""", {"3DES", "HMAC", "SHA-1"})
    # ------------------------------------------------------------------ negatives (things that look like evasion but are not crypto)
    _c("python", "w12_neg_getattr_json.py", """
import json

FMT = "dumps"
out = getattr(json, FMT)({"a": 1})
ALGO = "md5"  # name of a column in the vendor feed, never hashed here
columns = ["id", ALGO, "sha_of_file"]
""", set(), "negative")
    _c("javascript", "w12_neg_bracket_fs.js", """
const fs = require("fs");
const method = "readFileSync";
const hashName = "sha256"; // documented in README only
module.exports = () => fs[method]("config.json", "utf8");
""", set(), "negative")
    _c("java", "w12_neg_constants_only.java", """
package com.bank.crypto;

/** Vocabulary shared with the vendor spec; nothing here calls a provider. */
public final class AlgorithmNames {
    public static final String AES = "AES/GCM/NoPadding";
    public static final String LEGACY = "DESede/CBC/PKCS5Padding";
    private AlgorithmNames() {}
}
""", {"AES", "3DES"})  # unambiguous JCA transformation literals are inventory even without a call (the call lives in another file)
