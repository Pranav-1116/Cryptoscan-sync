"""Wave 11 — IBM i (AS/400) RPG IV / CL / SQLRPGLE, plus a PCI-PIN-style re-check of the
payments pack written from the *requirements* side (PCI PIN Security, ANSI X9.24 DUKPT,
ISO 9564 PIN block formats, TR-31) rather than from any library's API.

Blind for the payments half (no payments rule was touched while writing these); the
IBM i half is written alongside the new rpg_parser.py (NOT blind). Labels were written
before the first benchmark run and the first pass is recorded in FIRST_PASS_HISTORY.

Conventions (see corpus.py): TLS-CIPHERS/TLS-UNVERIFIED -> TLS family; ECDHE -> ECDH;
CSPRNG/PRNG -> RNG; keystores/DCM -> X509; PIN block / CVV / DUKPT / retail MAC -> 3DES
(ISO-4 / FORMAT04 -> AES); TR-31 -> AES; UNKNOWN never counted.
"""
from __future__ import annotations


def register(_c) -> None:  # noqa: C901
    # ---------------------------------------------------------------- IBM i RPG: Qc3 APIs
    _c("rpg", "w11_encpan.rpgle", """
**free
ctl-opt dftactgrp(*no) actgrp(*caller) option(*srcstmt:*nodebugio);

dcl-pr Qc3EncryptData extproc('Qc3EncryptData');
  clearData     char(65535) options(*varsize) const;
  clearLen      int(10) const;
  clearFmt      char(8) const;
  algDesc       char(64) options(*varsize) const;
  algFmt        char(8) const;
  keyDesc       char(64) options(*varsize) const;
  keyFmt        char(8) const;
  csp           char(1) const;
  cspDev        char(10) const;
  encData       char(65535) options(*varsize);
  encLenProv    int(10) const;
  encLenRtn     int(10);
  errCode       likeds(qusec);
end-pr;

dcl-ds algd0200 qualified;
  blockCipherAlg  int(10) inz(22);
  blockLength     int(10) inz(16);
  mode            char(1) inz('1');
  padOption       char(1) inz('1');
  padChar         char(1) inz(x'00');
  reserved        char(1) inz(x'00');
  macLength       int(10) inz(0);
  effKeySize      int(10) inz(0);
  initVector      char(32) inz(*allx'00');
end-ds;

dcl-ds keyd0200 qualified;
  keyType   int(10) inz(22);
  keyLen    int(10) inz(32);
  keyFormat char(1) inz('0');
  reserved  char(3);
  keyStr    char(32);
end-ds;

Qc3EncryptData(pan : %len(pan) : 'DATA0100' : algd0200 : 'ALGD0200'
             : keyd0200 : 'KEYD0200' : '0' : *blanks : encPan : %size(encPan)
             : rtnLen : qusec);
return;
""", {"AES"})
    _c("rpg", "w11_hashpwd_fixed.rpgle", """
     H DFTACTGRP(*NO) ACTGRP(*CALLER)
      *---------------------------------------------------------------
      * Hash a password with the Cryptographic Services API
      *---------------------------------------------------------------
     D Qc3CalculateHash...
     D                 PR                  extproc('Qc3CalculateHash')
     D  inData                    65535A   options(*varsize) const
     D  inLen                        10I 0 const
     D  inFmt                         8A   const
     D  algDesc                      64A   options(*varsize) const
     D  algFmt                        8A   const
     D  csp                           1A   const
     D  cspDev                       10A   const
     D  hash                         64A
     D  errCode                             likeds(qusec)
     D algd0500        DS                  qualified
     D  hashAlg                      10I 0 inz(3)
     D pwdHash         S             32A
     C                   callp     Qc3CalculateHash(pwd : %len(%trimr(pwd)) :
     C                             'DATA0100' : algd0500 : 'ALGD0500' :
     C                             '0' : *blanks : pwdHash : qusec)
     C                   return
""", {"SHA-256"})
    _c("rpg", "w11_hmac_legacy_md5.rpgle", """
**free
dcl-ds algd0500 qualified;
  hashAlg int(10) inz(1);
end-ds;
dcl-pr Qc3CalculateHMAC extproc('Qc3CalculateHMAC') end-pr;
Qc3CalculateHMAC(msg : %len(msg) : 'DATA0100' : algd0500 : 'ALGD0500'
               : keyd : 'KEYD0200' : '0' : '' : mac : qusec);
""", {"HMAC", "MD5"})
    _c("rpg", "w11_pgm_call_tdes.rpgle", """
     D encrypt         PR                  extpgm('QC3ENCDT')
     D  clear                     32767A   options(*varsize) const
     D  clearLen                     10I 0 const
     D  clearFmt                      8A   const
     D  algd                         64A   const
     D  algdFmt                       8A   const
     D  keyd                         64A   const
     D  keydFmt                       8A   const
     D  csp                           1A   const
     D  cspDev                       10A   const
     D  enc                       32767A   options(*varsize)
     D  encLen                       10I 0 const
     D  encRtn                       10I 0
     D  err                                likeds(qusec)
     D algd            DS
     D  blkCphAlg                    10I 0 inz(21)
     D  blkLen                       10I 0 inz(8)
     D  mode                          1A   inz('0')
     C                   callp     encrypt(pinblk : 8 : 'DATA0100' : algd :
     C                             'ALGD0200' : keyd : 'KEYD0200' : '0' :
     C                             *blanks : out : 8 : rtn : qusec)
""", {"3DES"})
    _c("rpg", "w11_sign_rsa.rpgle", """
**free
dcl-pr Qc3CalculateSignature extproc('Qc3CalculateSignature') end-pr;
dcl-ds algd0400 qualified;
  pkaAlg     int(10) inz(50);
  pkaBlkFmt  char(1) inz('1');
  reserved   char(3);
  signHash   int(10) inz(3);
end-ds;
Qc3CalculateSignature(payload : %len(payload) : 'DATA0100' : algd0400 : 'ALGD0400'
                    : keyd0400 : 'KEYD0400' : '0' : '' : sig : %size(sig) : sigLen : qusec);
""", {"RSA", "SHA-256"})
    _c("rpg", "w11_prng_token.rpgle", """
**free
dcl-pr Qc3GenPRNs extproc('Qc3GenPRNs');
  prnData char(65535) options(*varsize);
  prnLen  int(10) const;
  prnType char(1) const;
  parity  char(1) const;
  err     likeds(qusec);
end-pr;
Qc3GenPRNs(sessionToken : 32 : '0' : '0' : qusec);
""", {"RNG"})
    _c("rpg", "w11_cee_random_otp.rpgle", """
**free
dcl-pr CEERAN0 extproc('CEERAN0');
  seed int(10);
  rnd  float(8);
  fc   char(12) options(*omit);
end-pr;
CEERAN0(seed : rnd : *omit);
otp = %char(%int(rnd * 1000000));
""", {"RNG"})
    _c("rpg", "w11_keyctx_unknown.rpgle", """
**free
dcl-pr Qc3CreateKeyContext extproc('Qc3CreateKeyContext') end-pr;
dcl-pr Qc3DestroyKeyContext extproc('Qc3DestroyKeyContext') end-pr;
Qc3CreateKeyContext(keyStr : keyLen : '0' : keyType : keyFmt : '0' : '' : keyCtx : qusec);
""", set())  # key context with no algorithm anywhere -> UNKNOWN only
    _c("rpg", "w11_sqlrpgle_db2.sqlrpgle", """
**free
exec sql set encryption password = :pw;
exec sql update cardmast set pan_enc = ENCRYPT_AES(:pan) where acct = :acct;
exec sql select HASH_SHA256(:secret) into :h from sysibm.sysdummy1;
exec sql select decrypt_char(pan_enc) into :pan from cardmast where acct = :acct;
""", {"AES", "SHA-256"})
    _c("rpg", "w11_gskit_client.rpgle", """
**free
/copy qsysinc/qrpglesrc,gskssl
rc = gsk_environment_open(env);
rc = gsk_attribute_set_enum(env : GSK_PROTOCOL_TLSV12 : GSK_TRUE);
rc = gsk_attribute_set_enum(env : GSK_PROTOCOL_TLSV10 : GSK_FALSE);
rc = gsk_attribute_set_buffer(env : GSK_KEYRING_FILE : '/QIBM/USERDATA/ICSS/CERT/SERVER/DEFAULT.KDB' : 0);
rc = gsk_attribute_set_buffer(env : GSK_TLSV12_CIPHER_SPECS_EX : 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256' : 0);
rc = gsk_environment_init(env);
""", {"TLS", "X509", "AES", "SHA-256", "ECDH", "RSA"})
    _c("rpg", "w11_gskit_passthru.rpgle", """
**free
rc = gsk_attribute_set_enum(env : GSK_SERVER_AUTH_TYPE : GSK_SERVER_AUTH_PASSTHRU);
""", {"TLS", "X509"})
    _c("rpg", "w11_mi_cipher.rpgle", """
     D cipher          PR                  extproc('_CIPHER')
     D  receiver                       *   value
     D  controls                       *   value
     D  source                         *   value
     C                   callp     cipher(%addr(out) : %addr(ctl) : %addr(in))
""", {})  # MI CIPHER: algorithm in the control block only -> UNKNOWN, not counted
    # ---------------------------------------------------------------- CL
    _c("cl", "w11_sysval_tls.clle", """
             PGM
             CHGSYSVAL  SYSVAL(QSSLPCL) VALUE('*TLSV1.3 *TLSV1.2')
             CHGSYSVAL  SYSVAL(QSSLCSL) VALUE('*ECDHE_ECDSA_AES_256_GCM_SHA384 +
                          *ECDHE_RSA_AES_128_GCM_SHA256 *RSA_AES_128_CBC_SHA')
             CHGSYSVAL  SYSVAL(QSSLCSLCTL) VALUE(*USRDFN)
             ENDPGM
""", {"TLS", "AES", "SHA-384", "SHA-256", "SHA-1", "ECDH", "ECDSA", "RSA"})
    _c("cl", "w11_sysval_legacy.clp", """
             PGM
             CHGSYSVAL  SYSVAL(QSSLPCL) VALUE('*TLSV1 *SSLV3')
             CHGSYSVAL  SYSVAL(QSSLCSL) VALUE('*RSA_RC4_128_SHA *RSA_3DES_EDE_CBC_SHA')
             ENDPGM
""", {"TLS", "RC4", "3DES", "SHA-1", "RSA"})
    _c("cl", "w11_master_key.clle", """
             PGM        PARM(&PART)
             DCL        VAR(&PART) TYPE(*CHAR) LEN(32)
             ADDMSTPART MSTKEY(1) PASSPHRASE(&PART)
             SETMSTKEY  MSTKEY(1)
             ENDPGM
""", {"AES"})
    _c("cl", "w11_neg_ovrdbf.clle", """
             PGM
             OVRDBF     FILE(CUSTMAST) TOFILE(PRODLIB/CUSTMAST) SHARE(*YES)
             CHGSYSVAL  SYSVAL(QDATFMT) VALUE(YMD)
             CHGSYSVAL  SYSVAL(QPWDLVL) VALUE(3)
             ADDLIBLE   LIB(QC3LIB)
             CALL       PGM(ARP010C) PARM(&KEY)
             SNDPGMMSG  MSG('key list rebuilt')
             ENDPGM
""", set(), "negative")
    _c("rpg", "w11_neg_keyed_file.rpgle", """
**free
dcl-f custmast keyed usage(*input:*update);
dcl-ds keylist qualified;
  custno char(10);
end-ds;
chain (custno) custmast;
if %found(custmast);
  hash = %scan('QC3': libl);  // just a library name in a string
endif;
exec sql select count(*) into :n from cust where cust_key = :custno;
return;
""", set(), "negative")
    _c("rpg", "w11_neg_comment_only.rpgle", """
     H DFTACTGRP(*NO)
      * TODO: switch Qc3EncryptData to AES once the key store is migrated
      * Qc3CalculateHash SHA-256 not used yet
     C                   eval      total = total + amt
     C                   return
""", set(), "negative")
    # ---------------------------------------------------------------- PCI-PIN re-check (blind for the payments pack)
    _c("java", "w11_Iso9564Format0.java", """
package com.bank.pin;

public final class Iso9564Format0 {
    /** ISO 9564-1 format 0: PIN field XOR PAN field, then TDEA under the ZPK. */
    public byte[] encipher(String pin, String pan, javax.crypto.SecretKey zpk) throws Exception {
        byte[] pinField = pinField(pin);
        byte[] panField = panField(pan);
        byte[] clear = new byte[8];
        for (int i = 0; i < 8; i++) clear[i] = (byte) (pinField[i] ^ panField[i]);
        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("DESede/ECB/NoPadding");
        c.init(javax.crypto.Cipher.ENCRYPT_MODE, zpk);
        return c.doFinal(clear);
    }
}
""", {"3DES"})
    _c("java", "w11_Iso9564Format4.java", """
package com.bank.pin;

public final class Iso9564Format4 {
    /** ISO 9564-1 format 4: AES-128 PIN block (PCI PIN v3 requirement 18-3 migration). */
    public byte[] encipher(byte[] pinField, byte[] panField, javax.crypto.SecretKey pek) throws Exception {
        javax.crypto.Cipher aes = javax.crypto.Cipher.getInstance("AES/ECB/NoPadding");
        aes.init(javax.crypto.Cipher.ENCRYPT_MODE, pek);
        byte[] intermediate = aes.doFinal(pinField);
        for (int i = 0; i < 16; i++) intermediate[i] ^= panField[i];
        return aes.doFinal(intermediate);
    }
}
""", {"AES"})
    _c("java", "w11_DukptX924.java", """
package com.bank.pos;

/** ANSI X9.24-1 DUKPT: derive the PIN encryption key from IPEK + KSN (21 future keys). */
public final class DukptX924 {
    private static final byte[] PIN_VARIANT = {0, 0, 0, 0, 0, 0, (byte) 0xFF, 0, 0, 0, 0, 0, 0, 0, (byte) 0xFF, 0};

    public byte[] derivePinKey(byte[] ipek, byte[] ksn) throws Exception {
        byte[] key = ipek.clone();
        long counter = ksnCounter(ksn);
        for (int bit = 20; bit >= 0; bit--) {
            if ((counter & (1L << bit)) != 0) key = nonReversibleKeyGen(key, ksn, bit);
        }
        for (int i = 0; i < 16; i++) key[i] ^= PIN_VARIANT[i];
        return key;
    }

    private byte[] nonReversibleKeyGen(byte[] key, byte[] ksn, int bit) throws Exception {
        javax.crypto.Cipher des = javax.crypto.Cipher.getInstance("DES/ECB/NoPadding");
        des.init(javax.crypto.Cipher.ENCRYPT_MODE, new javax.crypto.spec.SecretKeySpec(java.util.Arrays.copyOf(key, 8), "DES"));
        return des.doFinal(ksn);
    }
}
""", {"DES", "3DES"})
    _c("java", "w11_Tr31KeyBlock.java", """
package com.bank.hsm;

/** ANSI X9.143 / TR-31 key block, version 'D' (AES key derivation binding). */
public final class Tr31KeyBlock {
    public String wrap(byte[] kbpk, byte[] key, char usage, char algorithm) throws Exception {
        String header = "D0112" + usage + "0" + algorithm + "E00N0000";
        byte[] kbek = deriveKbek(kbpk);
        byte[] kbak = deriveKbak(kbpk);
        javax.crypto.Mac cmac = javax.crypto.Mac.getInstance("AESCMAC", "BC");
        cmac.init(new javax.crypto.spec.SecretKeySpec(kbak, "AES"));
        byte[] mac = cmac.doFinal(concat(header.getBytes(), key));
        javax.crypto.Cipher cbc = javax.crypto.Cipher.getInstance("AES/CBC/NoPadding");
        cbc.init(javax.crypto.Cipher.ENCRYPT_MODE, new javax.crypto.spec.SecretKeySpec(kbek, "AES"), new javax.crypto.spec.IvParameterSpec(java.util.Arrays.copyOf(mac, 16)));
        return header + hex(cbc.doFinal(key)) + hex(mac);
    }
}
""", {"AES", "CMAC"})
    _c("java", "w11_Kcv.java", """
package com.bank.hsm;

/** Key check value per ANSI X9.24: encrypt 8 zero bytes, keep 3. */
public final class Kcv {
    public String of(javax.crypto.SecretKey key) throws Exception {
        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("DESede/ECB/NoPadding");
        c.init(javax.crypto.Cipher.ENCRYPT_MODE, key);
        return hex(c.doFinal(new byte[8])).substring(0, 6);
    }
}
""", {"3DES"})
    _c("python", "w11_pin_translate.py", """
# PIN translation ZPK->ZPK for the switch (ISO 9564 format 0 both sides)
from Crypto.Cipher import DES3


def translate(pin_block: bytes, zpk_in: bytes, zpk_out: bytes) -> bytes:
    clear = DES3.new(zpk_in, DES3.MODE_ECB).decrypt(pin_block)
    return DES3.new(zpk_out, DES3.MODE_ECB).encrypt(clear)
""", {"3DES"})
    _c("python", "w11_cvv_generate.py", """
# CVV/CVC generation (Visa CVV method): TDEA with CVK-A/CVK-B, decimalise.
from Crypto.Cipher import DES


def cvv(pan: str, expiry: str, service_code: str, cvk_a: bytes, cvk_b: bytes) -> str:
    data = (pan + expiry + service_code).ljust(32, "0")
    block1, block2 = bytes.fromhex(data[:16]), bytes.fromhex(data[16:])
    a = DES.new(cvk_a, DES.MODE_ECB)
    b = DES.new(cvk_b, DES.MODE_ECB)
    step = a.encrypt(block1)
    step = bytes(x ^ y for x, y in zip(step, block2))
    step = a.encrypt(step)
    step = b.decrypt(step)
    step = a.encrypt(step)
    return decimalise(step.hex())[:3]
""", {"DES"})
    _c("csharp", "w11_RetailMac.cs", """
using System.Security.Cryptography;

namespace Bank.Pos
{
    /// ISO 9797-1 MAC algorithm 3 (retail MAC) over the ISO 8583 message, as PCI PIN 4-1 requires for key exchange.
    public static class RetailMac
    {
        public static byte[] Compute(byte[] msg, byte[] macKey)
        {
            using var des = DES.Create();
            des.Mode = CipherMode.CBC; des.Padding = PaddingMode.None;
            des.Key = macKey[..8]; des.IV = new byte[8];
            var chain = des.CreateEncryptor().TransformFinalBlock(msg, 0, msg.Length)[^8..];
            using var tdes = TripleDES.Create();
            tdes.Mode = CipherMode.ECB; tdes.Padding = PaddingMode.None; tdes.Key = macKey;
            return tdes.CreateEncryptor().TransformFinalBlock(chain, 0, 8)[..4];
        }
    }
}
""", {"DES", "3DES"})
    _c("java", "w11_neg_pan_tokenizer_lookup.java", """
package com.bank.tok;

/** Vault tokenisation: no cryptography here, tokens are random lookups in the vault table. */
public final class PanTokenizerLookup {
    private final java.util.Map<String, String> vault = new java.util.concurrent.ConcurrentHashMap<>();

    public String tokenize(String pan) {
        String masked = pan.substring(0, 6) + "******" + pan.substring(pan.length() - 4);
        return vault.computeIfAbsent(pan, p -> masked + luhnCheck(p));
    }

    private static int luhnCheck(String pan) {
        int sum = 0; boolean alt = false;
        for (int i = pan.length() - 1; i >= 0; i--) {
            int n = pan.charAt(i) - '0';
            if (alt) { n *= 2; if (n > 9) n -= 9; }
            sum += n; alt = !alt;
        }
        return sum % 10;
    }
}
""", set(), "negative")
    _c("java", "w11_neg_iso8583_fields.java", """
package com.bank.iso;

public final class Iso8583Fields {
    public static final int PIN_DATA = 52;          // field 52 carries the PIN block
    public static final int SECURITY_CONTROL = 53;  // field 53 security related control info
    public static final int MAC = 64;               // field 64 message authentication code
    public static final int KEY_SERIAL_NUMBER = 55; // subelement in ICC data
}
""", set(), "negative")
