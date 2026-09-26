"""Wave 16 — BLIND: a Saudi bank estate (SNB-profile) written from public integration specs.

What a large KSA bank actually runs, per public specifications and vendor manuals (no bank code was seen):

* **mada** (Saudi Payments) ISO 8583 switch — payShield ZPK/ZMK/TMK, ISO-0 PIN blocks, CVV/CVC/iCVV, ARQC/ARPC,
  TR-31 key blocks, LMK variants, remote key loading (RKL) to ATM EPPs with RSA-signed TR-34.
* **SARIE** (RTGS) / **SWIFT** Alliance — ISO 20022 pacs.008 with LAU (HMAC-SHA256), 3SKey, PKI-signed FIN.
* **SADAD** bill payments & **ZATCA / Fatoora** e-invoicing — SOAP WS-Security X.509, ECDSA secp256k1 + SHA-256
  XAdES signatures, CSR generation, QR TLV hashes.
* **Nafath / Absher / Yakeen / SIMAH** integrations — OAuth2 / JWT RS256 & PS256, mutual TLS, AES-GCM payloads.
* **SAMA CSF** hardening configs — TLS 1.2+/1.3 only, AES-256, RSA-2048+, SHA-2, no RC4 etypes in AD/Kerberos.
* Core & back office — COBOL/CICS ICSF, Oracle DBMS_CRYPTO, SQL Server TDE / Always Encrypted, .NET, IBM MQ AMS,
  WebSphere/Java, Informatica, Kotlin/Swift mobile with pinning, Arabic comments and Hijri dates throughout.

Labels were written from the specs before the corpus was run. Conventions unchanged: PIN/CVV/ARQC → 3DES
(key block → AES), TLS floors / cipher-suite floors → TLS, JWT alg → JWT, RNG → RNG, comments never count,
UNKNOWN never counts, Arabic text must never break tokenisation.
"""

from __future__ import annotations


def register(_c) -> None:
    # ------------------------------------------------------------------ mada switch (Java, jPOS style)
    _c("java", "MadaPinTranslator.java", """
package sa.com.bank.mada.switch;

import org.jpos.iso.ISOMsg;
import org.jpos.security.SMAdapter;
import org.jpos.security.SecureDESKey;

/** ترجمة كتلة الرقم السري من مفتاح الصراف إلى مفتاح مدى (ZPK ➜ ZPK) */
public class MadaPinTranslator {
    private final SMAdapter hsm;
    private final SecureDESKey atmZpk;     // ZPK under LMK pair 06-07
    private final SecureDESKey madaZpk;

    public MadaPinTranslator(SMAdapter hsm, SecureDESKey atmZpk, SecureDESKey madaZpk) {
        this.hsm = hsm; this.atmZpk = atmZpk; this.madaZpk = madaZpk;
    }

    public byte[] translate(ISOMsg m) throws Exception {
        String pan = m.getString(2);
        byte[] pinBlock = m.getBytes(52);
        // ISO-0 (format 01) both sides, mada mandates 3DES ZPK, 16 hex LMK variant
        return hsm.translatePINImpl(new org.jpos.security.EncryptedPIN(pinBlock, SMAdapter.FORMAT01, pan),
                atmZpk, madaZpk, SMAdapter.FORMAT01).getPINBlock();
    }
}
""", {"3DES"})
    _c("java", "MadaCvvService.java", """
package sa.com.bank.mada.cards;

import org.jpos.security.SMAdapter;
import org.jpos.security.SecureDESKey;

public class MadaCvvService {
    private final SMAdapter hsm;
    private final SecureDESKey cvkA, cvkB;   // CVK pair, LMK 14-15

    public MadaCvvService(SMAdapter hsm, SecureDESKey a, SecureDESKey b) { this.hsm = hsm; this.cvkA = a; this.cvkB = b; }

    /** CVV2 على شريط البطاقة: service code 000 مع تاريخ الانتهاء YYMM */
    public String cvv2(String pan, String expiryYYMM) throws Exception {
        return hsm.calculateCVV(pan, cvkA, cvkB, java.util.Date.from(java.time.Instant.now()), "000");
    }

    public boolean verifyArqc(byte[] mkAc, String pan, String psn, byte[] data, byte[] arqc) throws Exception {
        // EMV CSK / MK-AC session key derivation (EMV 4.3 Book 2, A1.3) – 2-key TDEA
        return hsm.verifyARQC(org.jpos.security.MKDMethod.OPTION_A, org.jpos.security.SKDMethod.VSDC,
                new SecureDESKey((short)128, SMAdapter.TYPE_MK_AC, mkAc, new byte[3]), pan, psn, arqc, new byte[2], new byte[0], data);
    }
}
""", {"3DES"})
    _c("java", "Tr34RemoteKeyLoader.java", """
package sa.com.bank.atm.rkl;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import java.util.Base64;

/**
 * تحميل المفاتيح عن بُعد لأجهزة الصراف الآلي (Diebold Nixdorf / NCR EPP) حسب ANSI X9 TR-34.
 * The TMK travels RSA-OAEP wrapped to the EPP public key and the bundle is signed by the host KDH key.
 */
public class Tr34RemoteKeyLoader {
    public byte[] wrapTmk(byte[] tmk, byte[] eppPublicDer, java.security.PrivateKey kdhKey) throws Exception {
        PublicKey epp = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(eppPublicDer));
        Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        c.init(Cipher.WRAP_MODE, epp);
        byte[] wrapped = c.wrap(new javax.crypto.spec.SecretKeySpec(tmk, "DESede"));
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(kdhKey);
        s.update(wrapped);
        byte[] sig = s.sign();
        return (Base64.getEncoder().encodeToString(wrapped) + "." + Base64.getEncoder().encodeToString(sig)).getBytes();
    }
}
""", {"RSA", "SHA-256", "3DES", "X509"})
    _c("java", "PayShieldKeyBlockExporter.java", """
package sa.com.bank.hsm;

/** تصدير المفاتيح بصيغة كتلة المفاتيح (Thales key block, TR-31 D) — مطلوب من مدى بحلول 2025 */
public class PayShieldKeyBlockExporter {
    private final PayShieldChannel ch;
    public PayShieldKeyBlockExporter(PayShieldChannel ch) { this.ch = ch; }

    public String exportZpk(String zpkUnderLmk, String zmkKeyBlock) {
        // A0 generate / A8 export with key scheme 'S' (key block), mode of use 'B', algorithm 'A' (AES-256 ZMK)
        StringBuilder cmd = new StringBuilder("A8");
        cmd.append("FFF").append("001").append("S").append(zmkKeyBlock).append("S").append(zpkUnderLmk);
        cmd.append("S").append("A").append("B").append("00").append("N").append("00");
        return ch.send(cmd.toString());
    }
}
""", {"3DES"})
    # ------------------------------------------------------------------ SARIE / SWIFT
    _c("java", "SarieLauSigner.java", """
package sa.com.bank.sarie;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

/** Local Authentication (LAU) for messages between the payment hub and SWIFT Alliance Access (SARIE ISO 20022). */
public class SarieLauSigner {
    private final byte[] leftKey, rightKey;
    public SarieLauSigner(byte[] left, byte[] right) { this.leftKey = left; this.rightKey = right; }

    public String lau(String pacs008Xml) throws Exception {
        byte[] key = new byte[leftKey.length + rightKey.length];
        System.arraycopy(leftKey, 0, key, 0, leftKey.length);
        System.arraycopy(rightKey, 0, key, leftKey.length, rightKey.length);
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return java.util.Base64.getEncoder().encodeToString(mac.doFinal(pacs008Xml.getBytes(StandardCharsets.UTF_8)));
    }
}
""", {"HMAC", "SHA-256"})
    _c("xml", "sarie-alliance-gateway.xml", """
<?xml version="1.0" encoding="UTF-8"?>
<!-- Alliance Gateway / SNL connection profile for SARIE (SAMA RTGS) -->
<ConnectionProfile name="SARIE-PROD">
  <Transport>
    <Protocol>TLSv1.2</Protocol>
    <CipherSuites>TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384</CipherSuites>
    <ClientCertificate keystore="/opt/swift/keys/sarie-client.p12" type="PKCS12"/>
  </Transport>
  <Signing>
    <DigestMethod>http://www.w3.org/2001/04/xmlenc#sha256</DigestMethod>
    <SignatureMethod>http://www.w3.org/2001/04/xmldsig-more#rsa-sha256</SignatureMethod>
  </Signing>
</ConnectionProfile>
""", {"TLS", "ECDH", "RSA", "AES", "SHA-384", "SHA-256", "X509"}, "config")
    # ------------------------------------------------------------------ ZATCA e-invoicing (.NET) + SADAD (SOAP/.NET)
    _c("csharp", "ZatcaInvoiceSigner.cs", """
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Bank.Tax.Zatca
{
    /// <summary>توقيع الفاتورة الإلكترونية (المرحلة الثانية – الربط والتكامل) وفق متطلبات هيئة الزكاة والضريبة والجمارك</summary>
    public sealed class ZatcaInvoiceSigner
    {
        private readonly ECPrivateKeyParameters _key;   // secp256k1 – mandated by ZATCA
        public ZatcaInvoiceSigner(ECPrivateKeyParameters key) => _key = key;

        public string InvoiceHash(string canonicalXml)
        {
            using var sha = SHA256.Create();
            return Convert.ToBase64String(sha.ComputeHash(Encoding.UTF8.GetBytes(canonicalXml)));
        }

        public byte[] Sign(byte[] invoiceHash)
        {
            var signer = new ECDsaSigner();
            signer.Init(true, _key);
            var rs = signer.GenerateSignature(invoiceHash);
            return Der(rs[0], rs[1]);
        }

        // QR TLV tag 8 = ECDSA signature, tag 9 = public key, tag 10 = certificate signature
        private static byte[] Der(Org.BouncyCastle.Math.BigInteger r, Org.BouncyCastle.Math.BigInteger s) => new byte[0];
    }
}
""", {"ECDSA", "SHA-256"})
    _c("csharp", "ZatcaCsrBuilder.cs", """
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Bank.Tax.Zatca
{
    public static class ZatcaCsrBuilder
    {
        // CSR for the compliance / production CSID: EC key on secp256k1, subject holds the VAT number and the EGS serial
        public static string Build(string vatNumber, string egsSerial)
        {
            using var ec = ECDsa.Create(ECCurve.CreateFromValue("1.3.132.0.10"));
            var req = new CertificateRequest($"CN=TST-886431145-{vatNumber}, O=Bank, C=SA", ec, HashAlgorithmName.SHA256);
            req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
            return req.CreateSigningRequestPem();
        }
    }
}
""", {"ECDSA", "SHA-256", "X509"})
    _c("csharp", "SadadBillerClient.cs", """
using System.ServiceModel;
using System.ServiceModel.Security;
using System.Security.Cryptography.X509Certificates;

namespace Bank.Payments.Sadad
{
    /// <summary>عميل خدمة سداد للمدفوعات – WS-Security مع توقيع X.509</summary>
    public class SadadBillerClient
    {
        public static ChannelFactory<ISadadBiller> Create(X509Certificate2 clientCert)
        {
            var binding = new WSHttpBinding(SecurityMode.TransportWithMessageCredential);
            binding.Security.Message.ClientCredentialType = MessageCredentialType.Certificate;
            binding.Security.Message.AlgorithmSuite = SecurityAlgorithmSuite.Basic256Sha256Rsa15;
            var f = new ChannelFactory<ISadadBiller>(binding, "https://biller.sadad.com/v2");
            f.Credentials.ClientCertificate.Certificate = clientCert;
            f.Credentials.ServiceCertificate.Authentication.CertificateValidationMode = X509CertificateValidationMode.ChainTrust;
            return f;
        }
    }
    public interface ISadadBiller { }
}
""", {"X509", "AES", "SHA-256", "RSA"})
    _c("csharp", "NafathTokenValidator.cs", """
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace Bank.Identity.Nafath
{
    /// <summary>التحقق من رمز نفاذ الوطني الموحد (Nafath) الصادر من مركز المعلومات الوطني</summary>
    public class NafathTokenValidator
    {
        public System.Security.Claims.ClaimsPrincipal Validate(string jwt, SecurityKey nicKey)
        {
            var p = new TokenValidationParameters
            {
                ValidIssuer = "https://nafath.api.elm.sa",
                IssuerSigningKey = nicKey,
                ValidAlgorithms = new[] { SecurityAlgorithms.RsaSsaPssSha256, SecurityAlgorithms.RsaSha256 },
                ClockSkew = System.TimeSpan.FromMinutes(1),
            };
            return new JwtSecurityTokenHandler().ValidateToken(jwt, p, out _);
        }
    }
}
""", {"JWT"})
    _c("csharp", "AlwaysEncryptedIban.cs", """
using Microsoft.Data.SqlClient;
using Microsoft.Data.SqlClient.AlwaysEncrypted.AzureKeyVaultProvider;

namespace Bank.Core.Data
{
    /// <summary>أعمدة IBAN ورقم الهوية مشفّرة بـ Always Encrypted (CEK محمي بـ CMK في Key Vault)</summary>
    public static class AlwaysEncryptedIban
    {
        public static void Register(Azure.Core.TokenCredential cred)
        {
            var provider = new SqlColumnEncryptionAzureKeyVaultProvider(cred);
            SqlConnection.RegisterColumnEncryptionKeyStoreProviders(
                new System.Collections.Generic.Dictionary<string, SqlColumnEncryptionKeyStoreProvider> { { "AZURE_KEY_VAULT", provider } });
        }
        // deterministic encryption so IBAN can be joined; algorithm fixed by SQL Server: AEAD_AES_256_CBC_HMAC_SHA_256
        public const string ColumnEncryptionAlgorithm = "AEAD_AES_256_CBC_HMAC_SHA_256";
    }
}
""", {"AES", "HMAC", "SHA-256"})
    # ------------------------------------------------------------------ SQL Server / Oracle (back office, FLEXCUBE style)
    _c("sql", "tde_core_ledger.sql", """
-- تفعيل تشفير قاعدة بيانات دفتر الأستاذ (SQL Server TDE) حسب ضوابط ساما CSF 3.3.7
USE master;
GO
CREATE MASTER KEY ENCRYPTION BY PASSWORD = '<from-vault>';
CREATE CERTIFICATE LedgerTdeCert WITH SUBJECT = 'CoreLedger TDE 2025';
GO
USE CoreLedger;
CREATE DATABASE ENCRYPTION KEY WITH ALGORITHM = AES_256 ENCRYPTION BY SERVER CERTIFICATE LedgerTdeCert;
ALTER DATABASE CoreLedger SET ENCRYPTION ON;
GO
""", {"AES", "X509"})
    _c("sql", "pkg_customer_pii.pks", """
CREATE OR REPLACE PACKAGE BODY pkg_customer_pii AS
  -- تشفير رقم الهوية الوطنية / الإقامة قبل التخزين (Oracle DBMS_CRYPTO)
  g_typ CONSTANT PLS_INTEGER := DBMS_CRYPTO.ENCRYPT_AES256 + DBMS_CRYPTO.CHAIN_CBC + DBMS_CRYPTO.PAD_PKCS5;

  FUNCTION enc_national_id(p_id IN VARCHAR2) RETURN RAW IS
    l_key RAW(32) := pkg_key_vault.fetch('CUST.NID.AES256');
  BEGIN
    RETURN DBMS_CRYPTO.ENCRYPT(UTL_I18N.STRING_TO_RAW(p_id, 'AL32UTF8'), g_typ, l_key);
  END;

  FUNCTION nid_hash(p_id IN VARCHAR2) RETURN RAW IS
  BEGIN
    -- بصمة للبحث الفهرسي فقط
    RETURN DBMS_CRYPTO.HASH(UTL_I18N.STRING_TO_RAW(p_id, 'AL32UTF8'), DBMS_CRYPTO.HASH_SH256);
  END;
END pkg_customer_pii;
/
""", {"AES", "SHA-256"})
    _c("sql", "legacy_pwd_hash.sql", """
-- legacy: internet banking password hashes before the 2019 migration (still read for grandfathered users)
CREATE OR REPLACE FUNCTION fn_legacy_pwd_hash(p_pwd IN VARCHAR2, p_salt IN VARCHAR2) RETURN VARCHAR2 IS
BEGIN
  RETURN RAWTOHEX(DBMS_CRYPTO.HASH(UTL_RAW.CAST_TO_RAW(p_salt || p_pwd), DBMS_CRYPTO.HASH_MD5));
END;
/
""", {"MD5"})
    # ------------------------------------------------------------------ core banking COBOL / CICS / JCL
    _c("cobol", "CBTRFENC.cbl", """
       IDENTIFICATION DIVISION.
       PROGRAM-ID. CBTRFENC.
      * تشفير حقول التحويل المحلي (سريع) قبل الإرسال إلى بوابة ساما
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01  RULE-ARRAY.
           05  RULE-1              PIC X(8) VALUE 'AES     '.
           05  RULE-2              PIC X(8) VALUE 'CBC     '.
           05  RULE-3              PIC X(8) VALUE 'KEYIDENT'.
       01  RULE-COUNT              PIC S9(9) COMP VALUE 3.
       01  KEY-LABEL               PIC X(64) VALUE 'SARIE.OUT.AES256.DATA'.
       01  IV-LEN                  PIC S9(9) COMP VALUE 16.
       PROCEDURE DIVISION.
           CALL 'CSNBSYE' USING RETURN-CODE REASON-CODE EXIT-LEN EXIT-DATA
                RULE-COUNT RULE-ARRAY KEY-LEN KEY-LABEL KEY-PARM-LEN KEY-PARM
                BLOCK-SIZE IV-LEN IV CHAIN-LEN CHAIN-DATA CTXT-LEN CTXT
                IN-LEN IN-TEXT OUT-LEN OUT-TEXT OPT-LEN OPT-DATA.
           GOBACK.
""", {"AES"})
    _c("cobol", "CBPINVER.cbl", """
       IDENTIFICATION DIVISION.
       PROGRAM-ID. CBPINVER.
      * التحقق من الرقم السري للبطاقة عبر ICSF (طريقة IBM-PINO / VISA-PVV)
       WORKING-STORAGE SECTION.
       01  PV-RULE-ARRAY.
           05 FILLER PIC X(8) VALUE 'VISA-PVV'.
           05 FILLER PIC X(8) VALUE 'ISO-0   '.
       01  PVK-LABEL   PIC X(64) VALUE 'MADA.PVK.2024A'.
       01  ZPK-LABEL   PIC X(64) VALUE 'MADA.ZPK.ACQ.001'.
       PROCEDURE DIVISION.
           CALL 'CSNBPVR' USING RC RS EXL EXD ZPK-LABEL PVK-LABEL PIN-PROFILE
                PAN-DATA EPB RULE-COUNT PV-RULE-ARRAY PIN-CHECK-LEN PIN-DATA.
           GOBACK.
""", {"3DES"})
    _c("jcl", "SARIEKEY.jcl", """
//SARIEKEY JOB (ACCT),'ICSF KGUP SARIE',CLASS=A,MSGCLASS=X
//* توليد مفتاح AES للبيانات الصادرة إلى سريع + مفتاح ZMK لمدى
//KGUP     EXEC PGM=CSFKGUP
//CSFCKDS  DD DSN=SYS1.CSF.CKDS,DISP=SHR
//CSFIN    DD *
  ADD LABEL(SARIE.OUT.AES256.DATA) TYPE(DATA) ALGORITHM(AES) LENGTH(32)
  ADD LABEL(MADA.ZMK.SAUDIPAY.01) TYPE(EXPORTER) LENGTH(16) KEY(*)
  ADD LABEL(MADA.PVK.2024A) TYPE(PINVER) LENGTH(16)
/*
""", {"AES", "3DES"})
    # ------------------------------------------------------------------ SAMA CSF hardening configs
    _c("config", "sama-csf-tls.conf", """
# SAMA Cyber Security Framework – control 3.3.x cryptography: TLS 1.2 minimum, 1.3 preferred, PFS only
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305';
ssl_prefer_server_ciphers on;
ssl_ecdh_curve X25519:secp384r1;
ssl_certificate     /etc/pki/tls/certs/ebank.alahli.com.crt;
ssl_certificate_key /etc/pki/tls/private/ebank.alahli.com.key;
ssl_stapling on;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
""", {"TLS", "ECDH", "ECDSA", "RSA", "AES", "SHA-384", "CHACHA20", "X25519"}, "config")
    _c("config", "krb5.conf", """
# Active Directory realm for branch workstations – RC4 disabled per SAMA CSF / MS KB5021131
[libdefaults]
    default_realm = CORP.BANK.SA
    default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    permitted_enctypes   = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    allow_weak_crypto = false
[realms]
    CORP.BANK.SA = { kdc = riyadh-dc01.corp.bank.sa }
""", {"AES", "HMAC", "SHA-1"}, "config")
    _c("config", "legacy-branch-gpo.inf", """
; Security template exported from the 2016 branch-server GPO (still linked to OU=Branches-Legacy)
[Registry Values]
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0\\NtlmMinClientSec=4,536870912
MACHINE\\System\\CurrentControlSet\\Services\\Kdc\\Parameters\\SupportedEncryptionTypes=4,28
MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters\\SupportedEncryptionTypes=4,4
MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server\\Enabled=4,1
MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\RC4 128/128\\Enabled=4,1
""", {"RC4", "TLS", "AES"}, "config")  # 4,28 = RC4 + AES128 + AES256 etypes
    _c("yaml", "mq-ams-policy.yaml", """
# IBM MQ Advanced Message Security policy for the mada ↔ core queues (setmqspl equivalents)
policies:
  - queue: MADA.AUTH.REQ
    qmgr: QMCORE1
    signing: SHA256
    encryption: AES256
    recipients:
      - "CN=core-auth-svc,OU=Payments,O=Bank,C=SA"
    signers:
      - "CN=mada-switch,OU=Payments,O=Bank,C=SA"
  - queue: SADAD.NOTIF
    qmgr: QMCORE1
    signing: SHA1
    encryption: NONE
""", {"SHA-256", "AES", "SHA-1"}, "config")
    _c("properties", "was-ssl.properties", """
# WebSphere ND cell – SSL config for the internet-banking cluster (ebank)
com.ibm.ssl.protocol=TLSv1.2
com.ibm.ssl.enabledCipherSuites=SSL_ECDHE_RSA_WITH_AES_256_GCM_SHA384 SSL_ECDHE_RSA_WITH_AES_128_GCM_SHA256
com.ibm.ssl.keyStore=/opt/IBM/WebSphere/profiles/ebank/etc/key.p12
com.ibm.ssl.keyStoreType=PKCS12
com.ibm.ssl.trustStore=/opt/IBM/WebSphere/profiles/ebank/etc/trust.p12
com.ibm.ssl.clientAuthentication=false
""", {"TLS", "ECDH", "RSA", "AES", "SHA-384", "SHA-256", "X509"}, "config")
    # ------------------------------------------------------------------ mobile (Kotlin / Swift) – SNB Mobile-style
    _c("kotlin", "SecureStore.kt", """
package sa.com.bank.mobile.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec

/** تخزين رمز الجلسة ورقم الجهاز المسجل في Android Keystore (مرتبط بالبصمة) */
class SecureStore {
    private val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun key(): javax.crypto.SecretKey {
        (ks.getKey(ALIAS, null) as? javax.crypto.SecretKey)?.let { return it }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
            .build())
        return gen.generateKey()
    }

    fun seal(plain: ByteArray): Pair<ByteArray, ByteArray> {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key())
        return c.iv to c.doFinal(plain)
    }
    companion object { const val ALIAS = "snb.session.v3" }
}
""", {"AES", "X509"})
    _c("kotlin", "PinnedClient.kt", """
package sa.com.bank.mobile.net

import okhttp3.CertificatePinner
import okhttp3.ConnectionSpec
import okhttp3.OkHttpClient
import okhttp3.TlsVersion

/** تثبيت الشهادات لواجهات الخدمات المصرفية (بصمة SPKI SHA-256) */
object PinnedClient {
    fun build(): OkHttpClient = OkHttpClient.Builder()
        .certificatePinner(CertificatePinner.Builder()
            .add("api.alahli.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            .add("api.alahli.com", "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")
            .build())
        .connectionSpecs(listOf(ConnectionSpec.Builder(ConnectionSpec.RESTRICTED_TLS)
            .tlsVersions(TlsVersion.TLS_1_3, TlsVersion.TLS_1_2).build()))
        .build()
}
""", {"SHA-256", "TLS", "X509"})
    _c("swift", "DeviceBinding.swift", """
import Foundation
import CryptoKit
import Security

/// ربط الجهاز: مفتاح P-256 في Secure Enclave يوقّع تحدّي الخادم عند كل تسجيل دخول
final class DeviceBinding {
    private let tag = "sa.com.bank.mobile.devicekey".data(using: .utf8)!

    func makeKey() throws -> SecureEnclave.P256.Signing.PrivateKey {
        let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                     [.privateKeyUsage, .biometryCurrentSet], nil)!
        return try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
    }

    func sign(challenge: Data, with key: SecureEnclave.P256.Signing.PrivateKey) throws -> Data {
        try key.signature(for: SHA256.hash(data: challenge)).derRepresentation
    }

    func sealForTransport(_ payload: Data, key: SymmetricKey) throws -> Data {
        try AES.GCM.seal(payload, using: key).combined!
    }
}
""", {"ECDSA", "SHA-256", "AES"})
    # ------------------------------------------------------------------ integration / middleware (Python, Go, Node)
    _c("python", "yakeen_client.py", """
\"\"\"عميل خدمة يقين (التحقق من الهوية) عبر بوابة الحكومة الآمنة — mTLS + توقيع HMAC للطلب.\"\"\"
import hmac
import hashlib
import ssl
import httpx


def _ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile="/etc/bank/ca/gsb-root.pem")
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain("/etc/bank/certs/yakeen-client.pem", "/etc/bank/certs/yakeen-client.key")
    return ctx


def sign_request(secret: bytes, body: bytes) -> str:
    return hmac.new(secret, body, hashlib.sha512).hexdigest()


def client() -> httpx.Client:
    return httpx.Client(base_url="https://gsb.yesser.gov.sa/yakeen", verify=_ctx())
""", {"TLS", "HMAC", "SHA-512"})
    _c("python", "simah_report_cipher.py", """
\"\"\"تقارير سمة الائتمانية: الملفات تُشفَّر بـ PGP قبل الرفع إلى SFTP الخاص بسمة.\"\"\"
import gnupg
import paramiko


def encrypt_report(path: str, simah_fingerprint: str) -> str:
    gpg = gnupg.GPG(gnupghome="/var/lib/bank/gnupg")
    with open(path, "rb") as fh:
        res = gpg.encrypt_file(fh, recipients=[simah_fingerprint], output=path + ".pgp", armor=False,
                               extra_args=["--cipher-algo", "AES256", "--digest-algo", "SHA256", "--compress-algo", "none"])
    return res.status


def upload(path: str) -> None:
    key = paramiko.Ed25519Key.from_private_key_file("/etc/bank/sftp/simah_ed25519")
    t = paramiko.Transport(("sftp.simah.com", 22))
    t.connect(username="bank_reports", pkey=key)
    paramiko.SFTPClient.from_transport(t).put(path, "/inbound/" + path.rsplit("/", 1)[-1])
""", {"AES", "SHA-256", "ED25519", "SSH", "PGP"})
    _c("go", "iban_tokenizer.go", """
package tokenization

// ترميز IBAN لبيئات الاختبار: تشفير محافظ للصيغة (FF1) بمفتاح AES-256 من KMS
import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

func Tokenize(iban string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return hex.EncodeToString(gcm.Seal(nonce, nonce, []byte(iban), nil)), nil
}

func Fingerprint(iban string) string {
	sum := sha256.Sum256([]byte("SA" + iban))
	return hex.EncodeToString(sum[:8])
}
""", {"AES", "RNG", "SHA-256"})
    _c("javascript", "openBankingJws.js", """
// SAMA Open Banking (KSA OBF) – JWS detached signature for payment initiation, PS256 with the OB signing cert
const jose = require("jose");
const fs = require("fs");

async function signPayload(payload, kid) {
  const pem = fs.readFileSync(process.env.OB_SIGNING_KEY, "utf8");
  const key = await jose.importPKCS8(pem, "PS256");
  return new jose.CompactSign(Buffer.from(JSON.stringify(payload)))
    .setProtectedHeader({ alg: "PS256", kid, b64: false, crit: ["b64"], "http://openbanking.org.uk/tan": "openbanking.sa" })
    .sign(key);
}

async function verifyConsent(jwt, jwks) {
  const { payload } = await jose.jwtVerify(jwt, jose.createRemoteJWKSet(new URL(jwks)), { algorithms: ["PS256", "ES256"] });
  return payload;
}
module.exports = { signPayload, verifyConsent };
""", {"JWT"})
    _c("typescript", "otpService.ts", """
// رمز التحقق لمرة واحدة (OTP) للرسائل النصية — TOTP RFC 6238 لتطبيق المصادقة، ومولّد آمن للرسائل
import { createHmac, randomInt } from "crypto";

export function smsOtp(): string {
  return String(randomInt(0, 1_000_000)).padStart(6, "0");
}

export function totp(secret: Buffer, step = 30, now = Date.now()): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(now / 1000 / step)));
  const h = createHmac("sha1", secret).update(counter).digest();
  const off = h[h.length - 1] & 0xf;
  const code = ((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3];
  return String(code % 1_000_000).padStart(6, "0");
}
""", {"HMAC", "SHA-1", "RNG"})
    # ------------------------------------------------------------------ HSM / key inventory shaped files
    _c("hsm", "payshield-lmk-migration.hsm", """
; Thales payShield 10K – LMK migration plan for the mada key ceremony (Riyadh DC, 2025-03)
; Old LMK: variant (3DES, id 00)   New LMK: key block (AES-256, id 01)
LK 00
BW ; translate ZMKs 00 -> 01
A6 01 000 U MADA.ZMK.SAUDIPAY.01
A6 01 001 U MADA.ZPK.ACQ.001
A6 01 002 U MADA.TMK.ATM.RYD.0347
EC
""", {"3DES"})
    # ------------------------------------------------------------------ negatives (Arabic text, look-alike words, no crypto)
    _c("java", "HijriDateConverter.java", """
package sa.com.bank.common.calendar;

import java.time.LocalDate;
import java.time.chrono.HijrahDate;
import java.time.format.DateTimeFormatter;

/** تحويل التاريخ الهجري (أم القرى) إلى ميلادي والعكس لكشوف الحساب */
public class HijriDateConverter {
    private static final DateTimeFormatter F = DateTimeFormatter.ofPattern("dd/MM/yyyy");
    public static LocalDate toGregorian(String hijri) {
        String[] p = hijri.split("/");
        return LocalDate.from(HijrahDate.of(Integer.parseInt(p[2]), Integer.parseInt(p[1]), Integer.parseInt(p[0])));
    }
    public static String toHijri(LocalDate d) { return F.format(HijrahDate.from(d)); }
    // ملاحظة: لا تستخدم SHA أو AES هنا — هذا الصف للتواريخ فقط
}
""", set(), "negative")
    _c("python", "iban_validate.py", """
\"\"\"التحقق من صحة الآيبان السعودي (SA + 22 رقمًا) — mod-97 فقط، لا تشفير.\"\"\"
import re

_SA = re.compile(r"^SA\\d{2}[0-9A-Z]{20}$")


def valid(iban: str) -> bool:
    iban = iban.replace(" ", "").upper()
    if not _SA.match(iban):
        return False
    rearranged = iban[4:] + iban[:4]
    digits = "".join(str(int(ch, 36)) for ch in rearranged)
    return int(digits) % 97 == 1


def mask(iban: str) -> str:
    return iban[:4] + "*" * (len(iban) - 8) + iban[-4:]
""", set(), "negative")
    _c("csharp", "SadadBillModels.cs", """
namespace Bank.Payments.Sadad.Models
{
    /// <summary>نماذج فواتير سداد — بيانات فقط</summary>
    public sealed record BillInquiry(string BillerId, string BillNumber, string ServiceType);
    public sealed record BillAmount(decimal Amount, string Currency = "SAR");
    public sealed record PaymentReceipt(string SadadNumber, System.DateTimeOffset PaidAt, string ChannelSignatureLabel)
    {
        // "signature" here is the branch teller's handwritten sign-off label, not a cryptographic signature
        public bool IsCounterPayment => ChannelSignatureLabel.StartsWith("BR-");
    }
}
""", set(), "negative")
    _c("cobol", "CBSTMTAR.cbl", """
       IDENTIFICATION DIVISION.
       PROGRAM-ID. CBSTMTAR.
      * طباعة كشف الحساب باللغة العربية — تنسيق فقط
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01  WS-HDR-AR      PIC X(40) VALUE 'كشف حساب البنك الأهلي السعودي'.
       01  WS-DES-CODE    PIC X(3)  VALUE 'DES'.
      *    DES-CODE above is the branch DESK code prefix (DESCRIPTION column), not an algorithm
       PROCEDURE DIVISION.
           DISPLAY WS-HDR-AR.
           MOVE 'DESK' TO WS-DES-CODE.
           GOBACK.
""", set(), "negative")
    _c("yaml", "sama-reporting-schedule.yaml", """
# جدول التقارير الرقابية لساما (لا يحتوي على إعدادات تشفير)
reports:
  - name: SAMA-Q-LIQUIDITY
    frequency: monthly
    format: xlsx
    owner: finance-regulatory@bank.sa
  - name: SAMA-CSF-SELF-ASSESSMENT
    frequency: annual
    controls: [3.3.1, 3.3.5, 3.3.7]   # cryptography controls are referenced, not configured here
""", set(), "negative")
