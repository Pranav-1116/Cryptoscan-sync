"""Wave 17 — BLIND: post-quantum adoption (the other half of a PQC inventory).

A migration inventory must see the *new* algorithms as reliably as the old ones: hybrid TLS groups, ML-KEM / ML-DSA /
SLH-DSA key generation, liboqs and OpenSSL 3.5 providers, pre-standard Kyber / Dilithium / SPHINCS+ names, PQC in
.NET 10, Go 1.24 `crypto/mlkem`, Java 24 (JEP 496/497), BouncyCastle PQC, `@noble/post-quantum`, and the
*negatives* every PQC grep trips over (a Kyber team name, "dilithium" the metal, a Falcon 9 launch table).

Labels written before the run. Conventions: ML-KEM/Kyber/X25519MLKEM768 hybrids → {MLKEM, X25519} when the classical
half is spelled out; ML-DSA/Dilithium → MLDSA; SLH-DSA/SPHINCS+ → SLHDSA; a liboqs call with a concrete algorithm
name counts that algorithm; comments and prose never count; TLS floors → TLS.
"""

from __future__ import annotations


def register(_c) -> None:
    # ------------------------------------------------------------------ Java 24 JEP 496/497 + BC PQC
    _c("java", "HybridKemHandshake.java", """
package com.bank.pqc;

import java.security.KeyPairGenerator;
import java.security.Signature;
import javax.crypto.KEM;

public final class HybridKemHandshake {
    KEM.Encapsulated encapsulate(java.security.PublicKey peer) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM-768");
        kpg.generateKeyPair();
        KEM kem = KEM.getInstance("ML-KEM");
        return kem.newEncapsulator(peer).encapsulate();
    }

    byte[] sign(byte[] msg, java.security.PrivateKey k) throws Exception {
        Signature s = Signature.getInstance("ML-DSA-65");
        s.initSign(k);
        s.update(msg);
        return s.sign();
    }

    void legacyNames() throws Exception {
        KeyPairGenerator bc = KeyPairGenerator.getInstance("Dilithium", "BCPQC");
        KeyPairGenerator sp = KeyPairGenerator.getInstance("SPHINCS+", "BCPQC");
        KeyPairGenerator x = KeyPairGenerator.getInstance("X25519");
    }
}
""", {"MLKEM", "MLDSA", "SLHDSA", "X25519"})

    _c("java", "BcPqcKeyFactory.java", """
package com.bank.pqc;

import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAKeyPairGenerator;

public class BcPqcKeyFactory {
    void kem() {
        MLKEMKeyPairGenerator g = new MLKEMKeyPairGenerator();
        g.init(new MLKEMKeyGenerationParameters(new java.security.SecureRandom(), MLKEMParameters.ml_kem_1024));
    }
    void sig() {
        MLDSASigner signer = new MLDSASigner();
        SLHDSAKeyPairGenerator slh = new SLHDSAKeyPairGenerator();
    }
}
""", {"MLKEM", "MLDSA", "SLHDSA", "RNG"})

    # ------------------------------------------------------------------ Go 1.24 crypto/mlkem + circl + liboqs-go
    _c("go", "pqc_tunnel.go", """
package tunnel

import (
	"crypto/mlkem"
	"crypto/tls"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/open-quantum-safe/liboqs-go/oqs"
)

func Server() *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
	}
}

func Keys() {
	dk, _ := mlkem.GenerateKey768()
	_ = dk.EncapsulationKey()
	pk, sk, _ := mldsa65.GenerateKey(nil)
	_, _ = pk, sk
	kem := oqs.KeyEncapsulation{}
	_ = kem.Init("ML-KEM-1024", nil)
	sig := oqs.Signature{}
	_ = sig.Init("SPHINCS+-SHA2-128s-simple", nil)
}
""", {"MLKEM", "MLDSA", "SLHDSA", "TLS", "X25519"})

    # ------------------------------------------------------------------ Python liboqs + pqcrypto + cryptography hybrid
    _c("python", "pqc_envelope.py", """
import oqs
from pqcrypto.kem.ml_kem_768 import generate_keypair, encrypt, decrypt
from pqcrypto.sign.ml_dsa_65 import sign, verify
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def hybrid_shared_secret(peer_pk, peer_kem_pk):
    with oqs.KeyEncapsulation("Kyber768") as kem:
        ct, ss_pq = kem.encap_secret(peer_kem_pk)
    priv = x25519.X25519PrivateKey.generate()
    ss_ec = priv.exchange(peer_pk)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"hybrid").derive(ss_ec + ss_pq)


def sign_manifest(msg: bytes, sk: bytes) -> bytes:
    with oqs.Signature("Dilithium3") as signer:
        return signer.sign(msg)
""", {"MLKEM", "MLDSA", "X25519", "HKDF", "SHA-256"})

    # ------------------------------------------------------------------ C: liboqs + OpenSSL 3.5 native PQC
    _c("c", "oqs_kem.c", """
#include <oqs/oqs.h>
#include <openssl/evp.h>

int pq_handshake(void) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    OQS_SIG *sph = OQS_SIG_new(OQS_SIG_alg_sphincs_sha2_128s_simple);
    if (!kem || !sig) return -1;
    /* OpenSSL 3.5 ships ML-KEM natively: no oqs-provider needed */
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "ML-KEM-768");
    EVP_PKEY *dsa = EVP_PKEY_Q_keygen(NULL, NULL, "ML-DSA-65");
    SSL_CTX_set1_groups_list(ctx, "X25519MLKEM768:X25519:P-256");
    OQS_KEM_free(kem);
    return pkey && dsa ? 0 : -1;
}
""", {"MLKEM", "MLDSA", "SLHDSA", "X25519", "ECDH"})

    # ------------------------------------------------------------------ C# .NET 10 + BouncyCastle PQC
    _c("csharp", "PqcSigner.cs", """
using System;
using System.Security.Cryptography;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;

namespace Bank.Pqc
{
    public sealed class PqcSigner
    {
        public byte[] Sign(byte[] data)
        {
            using MLDsa dsa = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
            return dsa.SignData(data);
        }

        public (byte[] ct, byte[] ss) Encapsulate(byte[] peer)
        {
            using MLKem kem = MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, peer);
            kem.Encapsulate(out byte[] ct, out byte[] ss);
            return (ct, ss);
        }

        public void Stateless()
        {
            using SlhDsa slh = SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaSha2_128s);
            var legacy = new KyberKeyPairGenerator();
            var dil = new DilithiumSigner();
        }
    }
}
""", {"MLKEM", "MLDSA", "SLHDSA"})

    # ------------------------------------------------------------------ TypeScript / Node 24
    _c("typescript", "pqcClient.ts", """
import { ml_kem1024 } from '@noble/post-quantum/ml-kem';
import { slh_dsa_sha2_128f } from '@noble/post-quantum/slh-dsa';
import { generateKeyPairSync } from 'node:crypto';

export function sessionKeys() {
  const { publicKey, secretKey } = ml_kem1024.keygen();
  const { cipherText, sharedSecret } = ml_kem1024.encapsulate(publicKey);
  return { publicKey, secretKey, cipherText, sharedSecret };
}

export function manifestSigner() {
  const keys = slh_dsa_sha2_128f.keygen();
  // Node 24 exposes ML-DSA through the standard key-pair API
  const pq = generateKeyPairSync('ml-dsa-65');
  return { keys, pq };
}
""", {"MLKEM", "SLHDSA", "MLDSA"})

    _c("javascript", "webcryptoPqc.js", """
export async function pqcKeys() {
  const kem = await crypto.subtle.generateKey({ name: "ML-KEM-768" }, true, ["encapsulateKey", "decapsulateKey"]);
  const sig = await crypto.subtle.generateKey({ name: "ML-DSA-65" }, false, ["sign", "verify"]);
  const classic = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  return { kem, sig, classic };
}
""", {"MLKEM", "MLDSA", "ECDH"})

    # ------------------------------------------------------------------ configs: OpenSSL 3.5, nginx, sshd, Java security
    _c("config", "openssl-pqc.cnf", """
openssl_conf = openssl_init

[openssl_init]
ssl_conf = ssl_sect
providers = provider_sect

[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect

[ssl_sect]
system_default = system_default_sect

[system_default_sect]
MinProtocol = TLSv1.3
Groups = X25519MLKEM768:SecP256r1MLKEM768:X25519:secp256r1
SignatureAlgorithms = mldsa65:ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256
""", {"TLS", "MLKEM", "X25519", "ECDH", "MLDSA", "ECDSA", "RSA", "SHA-256"})

    _c("config", "sshd_config", """
# OpenSSH 9.9+ — post-quantum key exchange first
KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-256-etm@openssh.com
""", {"MLKEM", "X25519", "SHA-256", "SHA-512", "ED25519", "RSA", "CHACHA20", "AES", "HMAC"})

    _c("config", "nginx-pqc.conf", """
server {
    listen 443 ssl;
    ssl_protocols TLSv1.3;
    ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;
    ssl_certificate /etc/ssl/bank.crt;
}
""", {"TLS", "MLKEM", "X25519", "ECDH"})

    # ------------------------------------------------------------------ negatives: PQC words that are not crypto
    _c("markdown", "team-kyber-roadmap.md", """
# Team Kyber — Q3 roadmap

Team Kyber owns the loyalty points service. Dilithium is the metal used in the new
smart-card chips, and the Falcon 9 launch table is for the space-themed campaign.
SPHINCS is the name of the office cat.
""", set(), "negative")

    _c("python", "materials_catalog.py", """
MATERIALS = {
    "dilithium": {"density": 0.5, "unit": "g/cm3"},
    "kyber": {"vendor": "Kyber Inc", "sku": "KYB-768"},
}


def falcon_launch_windows():
    return ["Falcon 9", "Falcon Heavy"]
""", set(), "negative")
