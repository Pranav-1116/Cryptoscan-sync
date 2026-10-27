"""Wave 19 — BLIND: a Qatar + Bahrain (GCC) bank estate written from public specifications (QCB / CBB / BENEFIT).

What a Gulf bank operating in Doha and Manama runs, per public specs and vendor manuals (no bank code was seen):

* **Qatar** — QCB-supervised: **Himyan** national debit card (ISO 8583, HSM PIN translation), **Fawran** instant
  payments (ISO 20022 with XML-DSig, Apache Santuario), **Qatar Mobile Payment (QMP)** wallets, **NAS** (National
  Authentication System) OIDC, QCB regulatory FX reporting (signed XML), Qatar PDPPL (Law 13/2016) personal data.
* **Bahrain** — CBB-supervised: **BENEFIT** national switch, **Fawri / Fawri+** transfers, **BenefitPay** QR,
  BENEFIT eKYC, CBB Open Banking Framework (Bahrain OBF, PS256 JWS), Bahrain PDPL (Law 30/2018), CPR numbers.
* Infra: Palo Alto SSL decryption profiles (`set` CLI), F5 client-ssl profiles (tmsh), Cisco ASA `ssl` lines,
  the BENEFIT SFTP host's sshd_config; a legacy SQL Server CPR hash.

Labels written from the specs before the run. Conventions as before: PIN → 3DES, TLS floors → TLS, JWT alg → JWT,
RNG → RNG, suites decompose, sshd-style files labelled by algorithms only, comments never count, Arabic must not
break tokens.
"""

from __future__ import annotations


def register(_c) -> None:
    # ------------------------------------------------------------------ Qatar — Himyan / Fawran (Java)
    _c("java", "HimyanPinBlockTranslator.java", """
package qa.bank.cards.himyan;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.jpos.iso.ISOMsg;

/** ترجمة كتلة رقم التعريف الشخصي لبطاقة "حِميان" من مفتاح جهاز الصراف إلى مفتاح المنطقة */
public class HimyanPinBlockTranslator {
    private final SecretKey tpk;
    private final SecretKey zpk;

    public HimyanPinBlockTranslator(byte[] tpkBytes, byte[] zpkBytes) {
        this.tpk = new SecretKeySpec(tpkBytes, "DESede");
        this.zpk = new SecretKeySpec(zpkBytes, "DESede");
    }

    public byte[] translate(ISOMsg m) throws Exception {
        byte[] pinUnderTpk = m.getBytes(52);
        Cipher c = Cipher.getInstance("DESede/ECB/NoPadding");
        c.init(Cipher.DECRYPT_MODE, tpk);
        byte[] clear = c.doFinal(pinUnderTpk);
        c.init(Cipher.ENCRYPT_MODE, zpk);
        return c.doFinal(clear);
    }
}
""", {"3DES"})

    _c("java", "FawranIso20022Signer.java", """
package qa.bank.ipp.fawran;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.w3c.dom.Document;

/** توقيع رسائل pacs.008 لنظام "فوران" للمدفوعات الفورية */
public class FawranIso20022Signer {
    static { org.apache.xml.security.Init.init(); }

    public void sign(Document doc, PrivateKey key, X509Certificate cert) throws Exception {
        XMLSignature sig = new XMLSignature(doc, "", XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256,
                                            Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
        doc.getDocumentElement().appendChild(sig.getElement());
        Transforms t = new Transforms(doc);
        t.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        sig.addDocument("", t, Constants.ALGO_ID_DIGEST_SHA256);
        sig.addKeyInfo(cert);
        sig.sign(key);
    }
}
""", {"RSA", "SHA-256", "X509"})

    # ------------------------------------------------------------------ Qatar — QMP wallet / NAS (C#)
    _c("csharp", "QmpWalletTokenService.cs", """
using System;
using System.Security.Cryptography;
using System.Text;

namespace Qa.Bank.Qmp.Wallet
{
    /// <summary>ترميز بيانات المحفظة لنظام الدفع عبر الهاتف المحمول في قطر</summary>
    public sealed class QmpWalletTokenService
    {
        private readonly byte[] _dek;
        private readonly byte[] _macKey;

        public QmpWalletTokenService(byte[] dek, byte[] macKey) { _dek = dek; _macKey = macKey; }

        public (byte[] nonce, byte[] ct, byte[] tag) Seal(byte[] walletPayload)
        {
            var nonce = new byte[12];
            RandomNumberGenerator.Fill(nonce);
            var ct = new byte[walletPayload.Length];
            var tag = new byte[16];
            using var gcm = new AesGcm(_dek, 16);
            gcm.Encrypt(nonce, walletPayload, ct, tag);
            return (nonce, ct, tag);
        }

        public string Mac(string qmpAlias)
        {
            using var h = new HMACSHA256(_macKey);
            return Convert.ToHexString(h.ComputeHash(Encoding.UTF8.GetBytes(qmpAlias)));
        }
    }
}
""", {"AES", "RNG", "HMAC", "SHA-256"})

    _c("csharp", "NasOidcValidator.cs", """
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;

namespace Qa.Bank.Identity.Nas
{
    /// <summary>التحقق من رموز نظام التوثيق الوطني (NAS) — تسجيل الدخول الموحد</summary>
    public sealed class NasOidcValidator
    {
        private readonly JsonWebKeySet _jwks;
        private readonly X509Certificate2 _pinned;

        public NasOidcValidator(string jwksJson, string pemChain)
        {
            _jwks = new JsonWebKeySet(jwksJson);
            _pinned = X509Certificate2.CreateFromPem(pemChain);
        }

        public TokenValidationParameters Parameters() => new TokenValidationParameters
        {
            ValidIssuer = "https://nas.gov.qa",
            ValidAudience = "qa-bank-mobile",
            IssuerSigningKeys = _jwks.GetSigningKeys(),
            ValidAlgorithms = new[] { "PS256", "ES256" },
            ValidateLifetime = true,
        };
    }
}
""", {"JWT", "X509"})

    # ------------------------------------------------------------------ Qatar — QCB reporting / Bahrain eKYC (Python)
    _c("python", "qcb_fx_report_signer.py", """
\"\"\"توقيع تقارير الصرف الأجنبي الأسبوعية المرسلة إلى مصرف قطر المركزي\"\"\"
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec


def sign_report(pem_key: bytes, report: bytes) -> bytes:
    key = serialization.load_pem_private_key(pem_key, password=None)
    return key.sign(
        report,
        padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA384(),
    )


def verify_ack(pub_pem: bytes, ack: bytes, signature: bytes) -> None:
    pub = serialization.load_pem_public_key(pub_pem)
    assert isinstance(pub.curve, ec.SECP384R1), "QCB acknowledgement key must be P-384"
    pub.verify(signature, ack, ec.ECDSA(hashes.SHA384()))
""", {"RSA", "SHA-384", "ECDSA"})

    _c("python", "benefit_ekyc_client.py", """
\"\"\"عميل خدمة التحقق الإلكتروني من الهوية (BENEFIT eKYC) — مملكة البحرين\"\"\"
import time
import jwt
import requests

EKYC = "https://ekyc.benefit.bh/api/v2"


class BenefitEkycClient:
    def __init__(self, client_cert: str, client_key: str, signing_key_pem: str, kid: str):
        self._cert = (client_cert, client_key)
        self._signing_key = signing_key_pem
        self._kid = kid

    def _assertion(self) -> str:
        now = int(time.time())
        claims = {"iss": "bank-bh", "sub": "bank-bh", "aud": EKYC, "iat": now, "exp": now + 300}
        return jwt.encode(claims, self._signing_key, algorithm="ES256", headers={"kid": self._kid})

    def verify_cpr(self, cpr: str, consent_id: str) -> dict:
        r = requests.post(f"{EKYC}/verify", json={"cpr": cpr, "consentId": consent_id},
                          headers={"Authorization": f"Bearer {self._assertion()}"}, cert=self._cert, timeout=20)
        r.raise_for_status()
        return r.json()
""", {"JWT", "X509"})

    # ------------------------------------------------------------------ Bahrain — Fawri+ / BenefitPay (Go)
    _c("go", "fawri_plus_hmac.go", """
// حزمة التحقق من سلامة رسائل "فوري+" — التحويلات الفورية عبر شبكة BENEFIT
package fawri

import (
	"crypto/hmac"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
)

type Verifier struct{ key []byte }

func (v Verifier) Seal(msg []byte) string {
	m := hmac.New(sha512.New, v.key)
	m.Write(msg)
	return hex.EncodeToString(m.Sum(nil))
}

func (v Verifier) Check(msg []byte, tag string) bool {
	want, err := hex.DecodeString(tag)
	if err != nil {
		return false
	}
	m := hmac.New(sha512.New, v.key)
	m.Write(msg)
	return subtle.ConstantTimeCompare(m.Sum(nil), want) == 1
}
""", {"HMAC", "SHA-512"})

    _c("go", "benefitpay_qr_signer.go", """
// توقيع رموز الاستجابة السريعة لتطبيق BenefitPay (EMVCo QR)
package benefitpay

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
)

type QRSigner struct {
	priv ed25519.PrivateKey
}

func NewQRSigner() (*QRSigner, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &QRSigner{priv: priv}, nil
}

func (s *QRSigner) Sign(payload []byte) string {
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.priv, payload))
}
""", {"ED25519", "RNG"})

    # ------------------------------------------------------------------ mobile (Kotlin / Swift)
    _c("kotlin", "BenefitPaySdk.kt", """
package bh.bank.mobile.benefitpay

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricPrompt
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature

/** ربط الجهاز والتوقيع البيومتري لعمليات BenefitPay */
class BenefitPaySdk {
    private val alias = "benefitpay-device-key"

    fun enrol() {
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        kpg.initialize(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(true)
                .setInvalidatedByBiometricEnrollment(true)
                .build()
        )
        kpg.generateKeyPair()
    }

    fun cryptoObject(): BiometricPrompt.CryptoObject {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initSign(ks.getKey(alias, null) as java.security.PrivateKey)
        return BiometricPrompt.CryptoObject(sig)
    }
}
""", {"ECDSA", "SHA-256", "X509"})

    _c("swift", "QmpDeviceBinding.swift", """
import Foundation
import CryptoKit
import Security

/// ربط الجهاز لمحفظة الدفع عبر الهاتف المحمول (QMP) — مفتاح في العنصر الآمن
final class QmpDeviceBinding {
    func makeKey() throws -> SecKey {
        let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                     [.privateKeyUsage, .biometryCurrentSet], nil)!
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: true, kSecAttrAccessControl as String: access],
        ]
        var err: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &err) else { throw err!.takeRetainedValue() }
        return key
    }

    func sign(_ key: SecKey, _ challenge: Data) -> Data? {
        return SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256, challenge as CFData, nil) as Data?
    }

    func sealOffline(_ payload: Data, _ k: SymmetricKey) throws -> Data {
        return try ChaChaPoly.seal(payload, using: k).combined
    }
}
""", {"ECDSA", "SHA-256", "CHACHA20"})

    # ------------------------------------------------------------------ core / KYC (SQL)
    _c("sql", "pkg_qid_vault.pks", """
-- حزمة تخزين أرقام البطاقة الشخصية القطرية (QID) — بيانات شخصية بموجب القانون 13 لسنة 2016
CREATE OR REPLACE PACKAGE BODY kyc.pkg_qid_vault AS
  FUNCTION protect_qid(p_qid IN VARCHAR2, p_key IN RAW) RETURN RAW IS
  BEGIN
    RETURN DBMS_CRYPTO.ENCRYPT(
      src => UTL_I18N.STRING_TO_RAW(p_qid, 'AL32UTF8'),
      typ => DBMS_CRYPTO.ENCRYPT_AES256 + DBMS_CRYPTO.CHAIN_CBC + DBMS_CRYPTO.PAD_PKCS5,
      key => p_key);
  END protect_qid;

  FUNCTION qid_fingerprint(p_qid IN VARCHAR2) RETURN RAW IS
  BEGIN
    RETURN DBMS_CRYPTO.HASH(UTL_I18N.STRING_TO_RAW(p_qid, 'AL32UTF8'), DBMS_CRYPTO.HASH_SH512);
  END qid_fingerprint;
END pkg_qid_vault;
/
""", {"AES", "SHA-512"})

    _c("sql", "legacy_cpr_hash.sql", """
-- تجزئة الرقم الشخصي البحريني (CPR) في جدول العملاء القديم — SQL Server 2012
UPDATE dbo.Customer
   SET CprHash = HASHBYTES('SHA1', CONVERT(VARBINARY(64), Cpr)),
       Cpr = NULL
 WHERE CprHash IS NULL;
""", {"SHA-1"})

    # ------------------------------------------------------------------ mainframe (COBOL)
    _c("cobol", "CBHIMPIN.cbl", """
       IDENTIFICATION DIVISION.
       PROGRAM-ID. CBHIMPIN.
      * ترجمة رقم التعريف الشخصي لبطاقات حِميان عبر ICSF (CSNBPTR)
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01  RC                   PIC S9(8) COMP VALUE 0.
       01  RS                   PIC S9(8) COMP VALUE 0.
       01  EXIT-LEN             PIC S9(8) COMP VALUE 0.
       01  EXIT-DATA            PIC X(4)  VALUE SPACES.
       01  IN-PIN-KEY-ID        PIC X(64) VALUE 'HIMYAN.IPINENC.ATM01'.
       01  OUT-PIN-KEY-ID       PIC X(64) VALUE 'HIMYAN.OPINENC.QCB01'.
       01  RULE-COUNT           PIC S9(8) COMP VALUE 2.
       01  RULE-ARRAY.
           05 FILLER            PIC X(8)  VALUE 'REFORMAT'.
           05 FILLER            PIC X(8)  VALUE 'ISO-0   '.
       01  IN-PROFILE           PIC X(24) VALUE 'ISO-0   NONE    F'.
       01  PAN-DATA             PIC X(12).
       01  SEQ-NUM              PIC S9(8) COMP VALUE 99999.
       01  OUT-PROFILE          PIC X(24) VALUE 'ISO-0   NONE    F'.
       01  IN-PIN-BLOCK         PIC X(8).
       01  OUT-PIN-BLOCK        PIC X(8).
       PROCEDURE DIVISION.
           CALL 'CSNBPTR' USING RC RS EXIT-LEN EXIT-DATA
                IN-PIN-KEY-ID OUT-PIN-KEY-ID
                RULE-COUNT RULE-ARRAY
                IN-PROFILE PAN-DATA SEQ-NUM
                OUT-PROFILE IN-PIN-BLOCK OUT-PIN-BLOCK.
           GOBACK.
""", {"3DES"})

    # ------------------------------------------------------------------ Bahrain OBF (TypeScript)
    _c("typescript", "openBankingBh.ts", """
// توقيع طلبات إطار الخدمات المصرفية المفتوحة في البحرين (Bahrain OBF) — JWS
import { CompactSign, importPKCS8, calculateJwkThumbprint, exportJWK } from 'jose';

export async function signRequest(pkcs8: string, kid: string, body: object): Promise<string> {
  const key = await importPKCS8(pkcs8, 'PS256');
  return new CompactSign(new TextEncoder().encode(JSON.stringify(body)))
    .setProtectedHeader({ alg: 'PS256', kid, typ: 'JOSE', 'http://openbanking.org.uk/iat': Math.floor(Date.now() / 1000) })
    .sign(key);
}

export async function thumbprint(pkcs8: string): Promise<string> {
  const key = await importPKCS8(pkcs8, 'PS256');
  return calculateJwkThumbprint(await exportJWK(key), 'sha256');
}
""", {"JWT", "SHA-256"})

    # ------------------------------------------------------------------ infra (configs)
    _c("config", "paloalto-ssl-decrypt.set", """
set shared ssl-tls-service-profile mgmt-portal certificate portal-2024
set shared ssl-tls-service-profile mgmt-portal protocol-settings min-version tls1-1
set shared ssl-tls-service-profile mgmt-portal protocol-settings max-version max
set shared ssl-decryption ssl-protocol-settings min-version tls1-0
set shared ssl-decryption ssl-protocol-settings enc-algo-rc4 no
set shared ssl-decryption ssl-protocol-settings enc-algo-3des no
set shared ssl-decryption ssl-protocol-settings auth-algo-sha1 yes
""", {"TLS", "SHA-1", "X509"})  # label corrected after the blind pass: the service profile binds a certificate

    _c("config", "f5-clientssl.tmsh", """
ltm profile client-ssl /Common/benefit-gw-clientssl {
    app-service none
    cert-key-chain {
        benefit-gw-2025 {
            cert /Common/benefit-gw-2025.crt
            key /Common/benefit-gw-2025.key
            chain /Common/bh-intermediate.crt
        }
    }
    ciphers ECDHE+AES-GCM:ECDHE+CHACHA20:!RC4:!3DES:!MD5
    defaults-from /Common/clientssl
    options { dont-insert-empty-fragments no-tlsv1 no-tlsv1.1 no-sslv3 }
    renegotiation disabled
}
""", {"TLS", "ECDH", "AES", "CHACHA20", "X509"})

    _c("config", "cisco-asa-ssl.cfg", """
! ASA 5525-X — Doha branch, remote-access VPN
ssl server-version tlsv1.2
ssl client-version tlsv1.2
ssl cipher tlsv1.2 custom "ECDHE-ECDSA-AES256-GCM-SHA384 ECDHE-RSA-AES256-GCM-SHA384"
ssl cipher dtlsv1.2 custom "ECDHE-RSA-AES256-GCM-SHA384"
ssl dh-group group14
ssl ecdh-group group19
ssl trust-point DOHA-VPN-2025 outside
""", {"TLS", "ECDH", "ECDSA", "RSA", "AES", "SHA-384", "DH", "X509"})

    _c("config", "benefit-sftp-sshd_config", """
# sshd_config — BENEFIT settlement file exchange host (Manama DC)
Port 2222
HostKey /etc/ssh/ssh_host_ed25519_key
HostKeyAlgorithms ssh-ed25519
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com
MACs hmac-sha2-512-etm@openssh.com
PubkeyAuthentication yes
PasswordAuthentication no
""", {"ED25519", "X25519", "SHA-256", "AES", "CHACHA20", "HMAC", "SHA-512"})

    # ------------------------------------------------------------------ negatives
    _c("markdown", "README.ar.md", """
# منصة المدفوعات الخليجية — دليل النشر

يخدم هذا المستودع تكاملات "فوران" (قطر) و"فوري+" (البحرين). جميع المفاتيح تُدار في وحدة الأمن المادية ولا تُخزَّن هنا.
للتصريح بالوصول، راجع سياسة إدارة المفاتيح المعتمدة من مصرف قطر المركزي ومصرف البحرين المركزي.
""", set(), "negative")

    _c("json", "i18n.ar-QA.json", """
{
  "wallet.title": "محفظة الدفع عبر الهاتف",
  "wallet.pin.prompt": "أدخل رقم التعريف الشخصي",
  "transfer.fawran": "تحويل فوري عبر فوران",
  "kyc.qid.label": "رقم البطاقة الشخصية",
  "security.notice": "لا تشارك رمز التحقق مع أي شخص"
}
""", set(), "negative")

    _c("python", "qid_validate.py", """
\"\"\"التحقق من صحة رقم البطاقة الشخصية القطرية (11 خانة، تبدأ بسنة الميلاد ورمز الجنسية)\"\"\"
import re

_QID = re.compile(r"^[23]\\d{10}$")


def is_valid_qid(qid: str) -> bool:
    if not _QID.match(qid):
        return False
    year = int(qid[1:3])
    nationality = int(qid[3:6])
    return 0 <= year <= 99 and 1 <= nationality <= 999


def mask(qid: str) -> str:
    return qid[:3] + "*" * 5 + qid[-3:]
""", set(), "negative")

    _c("yaml", "fawran-cutoff-schedule.yaml", """
# جدول أوقات الإغلاق اليومية لنظام فوران — التوقيت المحلي للدوحة
cutoffs:
  - channel: fawran
    settlement_window: "00:00-23:59"
    max_amount_qar: 50000
  - channel: qcb_rtgs
    settlement_window: "07:30-15:30"
    holiday_calendar: qatar-banking
""", set(), "negative")
