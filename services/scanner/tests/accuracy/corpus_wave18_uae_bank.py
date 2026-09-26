"""Wave 18 — BLIND: a UAE bank estate written from public specifications (CBUAE / AEP / UAE PASS / Open Finance).

What a large UAE bank runs, per public specs and vendor manuals (no bank code was seen):

* **Al Etihad Payments** — UAESWITCH (ATM/POS ISO 8583, HSM ZPK/TPK, PIN translation, EMV ARQC for the **Jaywan**
  scheme), **Aani** instant payments (ISO 20022 pacs.008 over mTLS, JWS ES256 message signing), UAEFTS / UAEDDS.
* **CBUAE Open Finance** (Nebras) — FAPI 2.0: PS256 JWS, `private_key_jwt`, DPoP, mTLS-bound tokens, JWKS rotation.
* **UAE PASS** — OIDC (RS256 id_token) and SAML 2.0 assertions with RSA-SHA256 XML signatures; **Emirates ID**
  ICA Validation Gateway (SOAP WS-Security X.509), card SM keys (3DES / AES on the applet).
* **WPS** (Wages Protection System) SIF files over SFTP; **Federal Tax Authority** e-invoicing pilot (Peppol AS4).
* Core banking: Temenos T24 / Finacle Java, Oracle DBMS_CRYPTO PII columns, SQL Server TDE, IBM MQ; **DIFC / ADGM**
  entities handling personal data under DIFC DPL 5/2020 and ADGM DPR 2021; UAE PDPL (Federal Decree-Law 45/2021).
* Remote access: SSL-VPN configs (legacy TLS 1.0 still on a branch appliance), RDP gateway NLA, Kerberos etypes.

Labels written from the specs before the run. Conventions as before: PIN/CVV/ARQC → 3DES (key block → AES), TLS
floors → TLS, JWT alg → JWT, RNG → RNG, comments never count, UNKNOWN never counts, Arabic must not break tokens.
"""

from __future__ import annotations


def register(_c) -> None:
    # ------------------------------------------------------------------ UAESWITCH / Jaywan (Java)
    _c("java", "UaeSwitchPinTranslator.java", """
package ae.bank.switch.uaeswitch;

import org.jpos.iso.ISOMsg;
import org.jpos.security.SMAdapter;
import org.jpos.security.SecureDESKey;
import org.jpos.security.EncryptedPIN;

/** ترجمة رقم التعريف الشخصي من مفتاح الطرفية إلى مفتاح المحول (UAESWITCH) */
public class UaeSwitchPinTranslator {
    private final SMAdapter hsm;
    private SecureDESKey tpk;   // terminal PIN key (ATM EPP)
    private SecureDESKey zpk;   // zone PIN key shared with AEP

    public UaeSwitchPinTranslator(SMAdapter hsm) { this.hsm = hsm; }

    public EncryptedPIN toSwitch(ISOMsg m, EncryptedPIN pinUnderTpk) throws Exception {
        String pan = m.getString(2);
        return hsm.translatePINImpl(pinUnderTpk, tpk, zpk, SMAdapter.FORMAT01);
    }

    public byte[] jaywanArqc(byte[] mkAc, byte[] atc, byte[] data) throws Exception {
        // EMV CVN 18 session key from the Jaywan issuer master key
        return hsm.generateARQC(SMAdapter.MKDM_OPTION_A, SMAdapter.SKD_METHOD_EMV_CSKD, mkAc, pan(), "01", atc, null, data);
    }

    private String pan() { return "6789"; }
}
""", {"3DES"})

    _c("java", "AaniPacs008Signer.java", """
package ae.bank.ipp.aani;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.util.Base64;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

/** Aani (IPP) participant gateway: ISO 20022 pacs.008 over mutual TLS with a detached JWS (ES256) on the payload. */
public final class AaniPacs008Signer {
    private final KeyStore participantStore;

    public AaniPacs008Signer(KeyStore ks) { this.participantStore = ks; }

    public String detachedJws(byte[] pacs008, char[] pin) throws Exception {
        PrivateKey k = (PrivateKey) participantStore.getKey("aani-signing-2025", pin);
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(k);
        s.update(pacs008);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(s.sign());
    }

    public SSLContext mtls(char[] pin) throws Exception {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX");
        kmf.init(participantStore, pin);
        SSLContext ctx = SSLContext.getInstance("TLSv1.3");
        ctx.init(kmf.getKeyManagers(), null, new java.security.SecureRandom());
        return ctx;
    }
}
""", {"ECDSA", "SHA-256", "TLS", "X509", "RNG"})

    _c("java", "T24OfsSessionCipher.java", """
package ae.bank.core.t24;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;

/** Temenos T24 OFS bridge: payload encryption between the channel layer and TAFJ. */
public class T24OfsSessionCipher {
    private static final String TRANSFORM = "AES/GCM/NoPadding";

    byte[] seal(byte[] ofs, byte[] key, byte[] iv) throws Exception {
        Cipher c = Cipher.getInstance(TRANSFORM);
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        return c.doFinal(ofs);
    }

    String legacyOfsChecksum(String ofs) throws Exception {
        // TODO retire: T24 R09 OFS.CHECKSUM still expects MD5 hex
        MessageDigest md = MessageDigest.getInstance("MD5");
        return java.util.HexFormat.of().formatHex(md.digest(ofs.getBytes("UTF-8")));
    }
}
""", {"AES", "MD5"})

    # ------------------------------------------------------------------ Open Finance FAPI 2.0 (C#)
    _c("csharp", "NebrasFapiClient.cs", """
using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace Bank.OpenFinance.Nebras
{
    /// CBUAE Open Finance (FAPI 2.0 security profile): private_key_jwt client auth, PS256 request objects, DPoP, mTLS.
    public sealed class NebrasFapiClient
    {
        private readonly X509Certificate2 _transportCert;
        private readonly RSA _signingKey;

        public NebrasFapiClient(X509Certificate2 transport, RSA signing)
        {
            _transportCert = transport;
            _signingKey = signing;
        }

        public string ClientAssertion(string clientId, string tokenEndpoint)
        {
            var creds = new SigningCredentials(new RsaSecurityKey(_signingKey) { KeyId = "of-sig-2025" }, SecurityAlgorithms.RsaSsaPssSha256);
            var jwt = new JwtSecurityToken(issuer: clientId, audience: tokenEndpoint, expires: DateTime.UtcNow.AddMinutes(5), signingCredentials: creds);
            return new JwtSecurityTokenHandler().WriteToken(jwt);
        }

        public string DpopProof(string htm, string htu)
        {
            using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var creds = new SigningCredentials(new ECDsaSecurityKey(ec), SecurityAlgorithms.EcdsaSha256);
            var jwt = new JwtSecurityToken(claims: new[] { new System.Security.Claims.Claim("htm", htm), new System.Security.Claims.Claim("htu", htu) }, signingCredentials: creds);
            return new JwtSecurityTokenHandler().WriteToken(jwt);
        }

        public HttpClientHandler Mtls()
        {
            var h = new HttpClientHandler { SslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13 };
            h.ClientCertificates.Add(_transportCert);
            return h;
        }
    }
}
""", {"JWT", "RSA", "ECDSA", "TLS", "X509"})

    _c("csharp", "UaePassSamlValidator.cs", """
using System;
using System.Security.Cryptography.Xml;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace Bank.Identity.UaePass
{
    /// UAE PASS SAML 2.0 assertion validation (RSA-SHA256 enveloped signature) and OIDC id_token check.
    public class UaePassSamlValidator
    {
        public bool Verify(XmlDocument assertion, X509Certificate2 idpCert)
        {
            var signed = new SignedXml(assertion);
            var node = assertion.GetElementsByTagName("Signature", "http://www.w3.org/2000/09/xmldsig#")[0];
            signed.LoadXml((XmlElement)node);
            if (signed.SignedInfo.SignatureMethod != "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
                return false;
            return signed.CheckSignature(idpCert, true);
        }

        public bool VerifyIdToken(string idToken, Microsoft.IdentityModel.Tokens.JsonWebKeySet jwks)
        {
            var p = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
            {
                ValidIssuer = "https://id.uaepass.ae",
                IssuerSigningKeys = jwks.Keys,
                ValidAlgorithms = new[] { "RS256" },
            };
            new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler().ValidateToken(idToken, p, out _);
            return true;
        }
    }
}
""", {"RSA", "SHA-256", "X509", "JWT"})

    _c("csharp", "EmiratesIdVgClient.cs", """
using System;
using System.ServiceModel;
using System.ServiceModel.Security;
using System.Security.Cryptography.X509Certificates;

namespace Bank.Identity.EmiratesId
{
    /// ICA Validation Gateway (Emirates ID) — SOAP with WS-Security X.509 mutual certificate binding.
    public class EmiratesIdVgClient
    {
        public WSHttpBinding Binding()
        {
            var b = new WSHttpBinding(SecurityMode.TransportWithMessageCredential);
            b.Security.Message.ClientCredentialType = MessageCredentialType.Certificate;
            b.Security.Message.AlgorithmSuite = SecurityAlgorithmSuite.Basic256Sha256;
            return b;
        }

        public X509Certificate2 ClientCert() => new X509Certificate2("vg-client.pfx", Environment.GetEnvironmentVariable("VG_PFX_PASSWORD"));
    }
}
""", {"X509", "AES", "SHA-256"})

    # ------------------------------------------------------------------ WPS / FTA (Python)
    _c("python", "wps_sif_uploader.py", """
\"\"\"WPS (Wages Protection System) SIF upload to the exchange house / CBUAE agent over SFTP.\"\"\"
import hashlib
import hmac
import os

import paramiko
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def sif_checksum(sif_bytes: bytes) -> str:
    # the SIF control record carries a SHA-256 over the EDR lines (spec rev 2020)
    return hashlib.sha256(sif_bytes).hexdigest()


def upload(sif_path: str, host: str) -> None:
    key = paramiko.Ed25519Key.from_private_key_file(os.environ["WPS_SFTP_KEY"])
    transport = paramiko.Transport((host, 22))
    transport.connect(username="wps-agent", pkey=key)
    sftp = paramiko.SFTPClient.from_transport(transport)
    sftp.put(sif_path, f"/inbox/{os.path.basename(sif_path)}")


def seal_for_archive(sif_bytes: bytes, kek: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(kek).encrypt(nonce, sif_bytes, b"wps-archive")


def legacy_mac(sif_bytes: bytes, secret: bytes) -> str:
    return hmac.new(secret, sif_bytes, hashlib.md5).hexdigest()  # pre-2020 agent still validates this
""", {"SHA-256", "ED25519", "SSH", "AES", "RNG", "HMAC", "MD5"})

    _c("python", "fta_peppol_as4.py", """
\"\"\"FTA e-invoicing pilot: Peppol AS4 (ebMS3) message signing and encryption profile.\"\"\"
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from lxml import etree


AS4_SIGNATURE = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
AS4_DIGEST = "http://www.w3.org/2001/04/xmlenc#sha256"
AS4_ENCRYPTION = "http://www.w3.org/2009/xmlenc11#aes128-gcm"
AS4_KEY_TRANSPORT = "http://www.w3.org/2009/xmlenc11#rsa-oaep"


def sign_user_message(payload: bytes, pem: bytes) -> bytes:
    key = serialization.load_pem_private_key(pem, password=None)
    return key.sign(payload, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())


def new_ap_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)
""", {"RSA", "SHA-256", "AES"})

    # ------------------------------------------------------------------ core / personal data (SQL, COBOL)
    _c("sql", "pkg_kyc_pii.pks", """
CREATE OR REPLACE PACKAGE BODY kyc_pii AS
  -- Emirates ID, passport and salary fields under UAE PDPL / DIFC DPL: AES-256 CBC via DBMS_CRYPTO
  g_key RAW(32);

  FUNCTION protect(p_clear IN VARCHAR2) RETURN RAW IS
  BEGIN
    RETURN DBMS_CRYPTO.ENCRYPT(
      src => UTL_I18N.STRING_TO_RAW(p_clear, 'AL32UTF8'),
      typ => DBMS_CRYPTO.ENCRYPT_AES256 + DBMS_CRYPTO.CHAIN_CBC + DBMS_CRYPTO.PAD_PKCS5,
      key => g_key);
  END;

  FUNCTION eid_hash(p_eid IN VARCHAR2) RETURN RAW IS
  BEGIN
    -- deterministic lookup token for 784-XXXX-XXXXXXX-X
    RETURN DBMS_CRYPTO.HASH(UTL_I18N.STRING_TO_RAW(p_eid, 'AL32UTF8'), DBMS_CRYPTO.HASH_SH256);
  END;
END kyc_pii;
""", {"AES", "SHA-256"})

    _c("sql", "legacy_customer_pwd.sql", """
-- Internet banking v1 (2009) password table, still read by the migration job
ALTER TABLE ib_users ADD pwd_hash VARCHAR2(40);
UPDATE ib_users SET pwd_hash = LOWER(RAWTOHEX(DBMS_CRYPTO.HASH(UTL_RAW.CAST_TO_RAW(pwd_clear || salt), DBMS_CRYPTO.HASH_SH1)));
""", {"SHA-1"})

    _c("sql", "tde_uae_core.sql", """
USE master;
CREATE MASTER KEY ENCRYPTION BY PASSWORD = '${TDE_MASTER_PWD}';
CREATE CERTIFICATE tde_core_2025 WITH SUBJECT = 'Core ledger TDE UAE';
USE core_ledger;
CREATE DATABASE ENCRYPTION KEY WITH ALGORITHM = AES_256 ENCRYPTION BY SERVER CERTIFICATE tde_core_2025;
ALTER DATABASE core_ledger SET ENCRYPTION ON;
""", {"AES", "X509"})

    _c("cobol", "CBEIDENC.cbl", """
       IDENTIFICATION DIVISION.
       PROGRAM-ID. CBEIDENC.
      * تشفير رقم الهوية الإماراتية قبل التخزين في ملف العملاء
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01  RULE-ARRAY-COUNT      PIC S9(9) COMP VALUE 2.
       01  RULE-ARRAY.
           05 FILLER             PIC X(8) VALUE 'AES     '.
           05 FILLER             PIC X(8) VALUE 'KEYIDENT'.
       01  KEY-LABEL             PIC X(64) VALUE 'CORE.EID.AES256.DATA'.
       01  CLEAR-EID             PIC X(16).
       01  CIPHER-EID            PIC X(32).
       PROCEDURE DIVISION.
           CALL 'CSNBSYE' USING RETURN-CODE REASON-CODE
                 EXIT-DATA-LENGTH EXIT-DATA
                 RULE-ARRAY-COUNT RULE-ARRAY
                 KEY-LABEL-LENGTH KEY-LABEL
                 KEY-PARMS-LENGTH KEY-PARMS
                 BLOCK-SIZE IV-LENGTH IV
                 CHAIN-DATA-LENGTH CHAIN-DATA
                 CLEAR-TEXT-LENGTH CLEAR-EID
                 CIPHER-TEXT-LENGTH CIPHER-EID
                 OPT-DATA-LENGTH OPT-DATA.
           GOBACK.
""", {"AES"})

    # ------------------------------------------------------------------ channels (Kotlin / Swift / TS)
    _c("kotlin", "JaywanTokenizer.kt", """
package ae.bank.mobile.cards

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator

/** Jaywan card tokenisation for tap-to-pay — device-bound AES key in StrongBox. */
class JaywanTokenizer {
    private val alias = "jaywan.token.kek"

    fun ensureKey() {
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        kg.init(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setIsStrongBoxBacked(true)
                .setKeySize(256)
                .build()
        )
        kg.generateKey()
    }

    fun wrap(token: ByteArray): ByteArray {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, ks.getKey(alias, null))
        return c.iv + c.doFinal(token)
    }
}
""", {"AES", "X509"})

    _c("swift", "UaePassLogin.swift", """
import Foundation
import CryptoKit
import AuthenticationServices

/// UAE PASS OIDC login with PKCE (S256) and an app-attestation signature.
final class UaePassLogin {
    func pkce() -> (verifier: String, challenge: String) {
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        let verifier = Data(bytes).base64EncodedString()
        let challenge = Data(SHA256.hash(data: Data(verifier.utf8))).base64EncodedString()
        return (verifier, challenge)
    }

    func attest(nonce: Data) throws -> Data {
        let key = try SecureEnclave.P256.Signing.PrivateKey()
        return try key.signature(for: nonce).rawRepresentation
    }
}
""", {"RNG", "SHA-256", "ECDSA"})

    _c("typescript", "aaniProxyPay.ts", """
import { createSign, createHash, randomUUID } from 'node:crypto';
import { SignJWT, importPKCS8 } from 'jose';

/** Aani proxy (mobile-number) payment request signing — JWS ES256 + request hash. */
export async function signRequest(body: object, pkcs8: string): Promise<string> {
  const key = await importPKCS8(pkcs8, 'ES256');
  return new SignJWT({ reqHash: createHash('sha256').update(JSON.stringify(body)).digest('base64url') })
    .setProtectedHeader({ alg: 'ES256', kid: 'aani-2025', typ: 'JOSE' })
    .setJti(randomUUID())
    .setIssuedAt()
    .sign(key);
}

export function legacyRsaSign(payload: string, pem: string): string {
  return createSign('RSA-SHA1').update(payload).sign(pem, 'base64');
}
""", {"JWT", "SHA-256", "RNG", "RSA", "SHA-1"})

    # ------------------------------------------------------------------ infra (configs)
    _c("config", "branch-sslvpn.conf", """
config vpn ssl settings
    set servercert "branch-vpn-2019"
    set ssl-min-proto-ver tls1-0
    set algorithm low
    set banned-cipher RC4 DES 3DES
    set dtls-tunnel enable
    set dtls-min-proto-ver dtls1-0
    set port 10443
end
""", {"TLS"})

    _c("config", "rdgateway.reg", """
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp]
"SecurityLayer"=dword:00000002
"UserAuthentication"=dword:00000001
"MinEncryptionLevel"=dword:00000003

[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Server]
"Enabled"=dword:00000001

[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\Triple DES 168]
"Enabled"=dword:00000001
""", {"TLS", "3DES"})

    _c("config", "cbuae-tls-baseline.conf", """
# CBUAE information-security baseline for customer-facing endpoints (applied by Ansible role tls_baseline)
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305;
ssl_ecdh_curve X25519:secp384r1;
ssl_prefer_server_ciphers on;
add_header Strict-Transport-Security "max-age=63072000" always;
""", {"TLS", "ECDH", "ECDSA", "RSA", "AES", "SHA-384", "CHACHA20", "X25519"})

    _c("config", "mq-aep-channel.mqsc", """
* IBM MQ channel to Al Etihad Payments — TLS 1.2 with a single suite, certificate label per channel
DEFINE CHANNEL('AEP.TO.BANK') CHLTYPE(RCVR) TRPTYPE(TCP) +
       SSLCIPH('TLS_RSA_WITH_AES_256_GCM_SHA384') SSLCAUTH(REQUIRED) +
       CERTLABL('ibmwebspheremqaep2025') SSLPEER('CN=aep-gw,O=Al Etihad Payments')
ALTER QMGR SSLKEYR('/var/mqm/qmgrs/BANK/ssl/key') CERTLABL('ibmwebspheremqbank2025')
""", {"TLS", "RSA", "AES", "SHA-384", "X509"})

    # ------------------------------------------------------------------ negatives
    _c("markdown", "README.ar.md", """
# نظام المدفوعات الفورية — دليل التشغيل

هذا المستودع يحتوي على خدمات الربط مع منصة "آني" التابعة للاتحاد للمدفوعات.
لا يتم تخزين أي مفاتيح في هذا المستودع؛ راجع فريق أمن المعلومات للحصول على الوصول.
""", set(), "negative")

    _c("json", "i18n.ar-AE.json", """
{
  "login.title": "تسجيل الدخول بالهوية الرقمية",
  "login.uaepass": "الدخول عبر UAE PASS",
  "payments.aani": "تحويل فوري عبر آني",
  "cards.jaywan": "بطاقة جيوان",
  "errors.pin": "رقم التعريف الشخصي غير صحيح"
}
""", set(), "negative")

    _c("python", "iban_ae_validate.py", """
\"\"\"UAE IBAN (AE + 2 check + 3 bank + 16 account) mod-97 validation — no cryptography.\"\"\"


def valid_ae_iban(iban: str) -> bool:
    s = iban.replace(" ", "").upper()
    if len(s) != 23 or not s.startswith("AE"):
        return False
    moved = s[4:] + s[:4]
    digits = "".join(str(int(ch, 36)) for ch in moved)
    return int(digits) % 97 == 1
""", set(), "negative")

    _c("yaml", "wps-schedule.yaml", """
# نافذة تحميل ملفات الرواتب
schedule:
  wps_upload: "0 6 * * 1-5"
  aani_reconcile: "*/15 * * * *"
  retention_days: 400
""", set(), "negative")
