"""Wave 8 — BLIND, bank / payments realism. Written before running the scanner
against it, from idioms a payments-platform reviewer would expect to find in a
bank's Java estate: jPOS security module APIs, PIN blocks, EMV cryptograms,
DUKPT, TR-31 key blocks, retail MAC, PKCS#11 providers, Thales payShield
adapters, SWIFT LAU, 3-D Secure, plus negatives (non-crypto payment code that
merely *mentions* keys, PANs and tokens). Labels were not edited after the
first run — the first-pass score is recorded in FIRST_PASS_HISTORY.

Conventions (see corpus.py): PIN blocks / CVV / EMV cryptograms / DUKPT /
retail MAC -> 3DES (ISO 9564 format-4 PIN block -> AES); EMV offline data
authentication -> RSA; HSM adapters / PKCS#11 providers -> UNKNOWN (inventory
only, never counted); Base64 / PAN masking / Luhn -> nothing.
"""
from __future__ import annotations


def register(_c) -> None:  # noqa: C901
    # ---------------------------------------------------------------- jPOS
    _c("java", "w8_jpos_PinTranslate.java", """
import org.jpos.security.*;
import org.jpos.iso.ISOUtil;
public class PinTranslate {
    SMAdapter sm = (SMAdapter) NameRegistrar.get("s-m-adapter");
    EncryptedPIN translate(EncryptedPIN pinUnderKd1, SecureDESKey kd1, SecureDESKey kd2) throws SMException {
        return sm.translatePIN(pinUnderKd1, kd1, kd2, SMAdapter.FORMAT01);
    }
}
""", {"3DES"})
    _c("java", "w8_jpos_Format4Pin.java", """
import org.jpos.security.*;
public class Iso4 {
    EncryptedPIN toIso4(SMAdapter sm, EncryptedPIN pin, SecureKey aesKey) throws SMException {
        // ISO 9564-1 format 4 PIN block is AES based
        return sm.translatePIN(pin, (SecureDESKey) null, aesKey, SMAdapter.FORMAT04);
    }
}
""", {"AES", "3DES"})
    _c("java", "w8_jpos_Cvv.java", """
import org.jpos.security.*;
public class CvvCheck {
    boolean verify(SMAdapter sm, String pan, String exp, String svc, String cvv, SecureDESKey cvk) throws SMException {
        return sm.verifyCVV(pan, cvk, cvv, exp, svc);
    }
}
""", {"3DES"})
    _c("java", "w8_jpos_Arqc.java", """
import org.jpos.security.*;
import org.jpos.emv.cryptogram.*;
public class ArqcVerify {
    byte[] arpc(SMAdapter sm, SecureDESKey imkac, String pan, String seq, byte[] arqc, byte[] atc, byte[] upn, byte[] data) throws SMException {
        return sm.verifyARQCGenerateARPC(MKDMethod.OPTION_A, SKDMethod.VSDC, imkac, pan, seq, arqc, atc, upn, data, ARPCMethod.METHOD_1, null, null);
    }
}
""", {"3DES"})
    _c("java", "w8_jpos_Dukpt.java", """
import org.jpos.security.*;
public class Dukpt {
    EncryptedPIN importPin(SMAdapter sm, byte[] block, String pan, SecureDESKey bdk, String ksnHex) throws SMException {
        KeySerialNumber ksn = new KeySerialNumber(ksnHex);
        EncryptedPIN pin = new EncryptedPIN(block, SMAdapter.FORMAT01, pan);
        return sm.importPIN(pin, ksn, bdk);
    }
}
""", {"3DES"})
    _c("java", "w8_jpos_KeyBlock.java", """
import org.jpos.security.*;
public class KeyImport {
    SecureDESKey imp(SMAdapter sm, byte[] blob, SecureDESKey kek) throws SMException {
        return sm.importKey(SMAdapter.LENGTH_DES3_2KEY, SMAdapter.TYPE_ZPK, blob, kek, true);
    }
    SecureKey tr31(SMAdapter sm, String keyBlock, SecureDESKey kbpk) throws SMException {
        return sm.importKey(SMAdapter.LENGTH_DES3_3KEY, SMAdapter.TYPE_ZMK, keyBlock.getBytes(), kbpk, KeyScheme.R, true);
    }
}
""", {"3DES", "AES"})
    _c("java", "w8_jpos_RetailMac.java", """
import org.jpos.security.*;
public class Mac {
    byte[] mac(SMAdapter sm, byte[] msg, SecureDESKey zak) throws SMException {
        return sm.generateCBC_MAC(msg, zak);
    }
    byte[] emvMac(SMAdapter sm, byte[] msg, SecureDESKey key) throws SMException {
        return sm.generateEDE_MAC(msg, key);
    }
}
""", {"3DES"})
    _c("java", "w8_jpos_JceSecurityModule.xml", """
<security-module class="org.jpos.security.jceadapter.JCESecurityModule" logger="Q2">
  <property name="provider" value="com.sun.crypto.provider.SunJCE" />
  <property name="lmk" value="cfg/lmk-test" />
  <property name="rebuildlmk" value="false" />
</security-module>
""", set())
    _c("java", "w8_jpos_JceHandler.java", """
import org.jpos.security.jceadapter.JCEHandler;
import java.security.Key;
public class Raw {
    byte[] enc(JCEHandler h, byte[] data, Key k) throws Exception {
        return h.encryptData(data, k);
    }
    Key gen(JCEHandler h) throws Exception {
        return h.generateDESKey(SMAdapter.LENGTH_DES3_2KEY);
    }
}
""", {"3DES"})
    _c("java", "w8_jpos_EmvDerivedKey.java", """
import org.jpos.security.*;
public class Skd {
    byte[] derive(SMAdapter sm, SecureDESKey imk, String pan, String seq, byte[] atc) throws SMException {
        return sm.generateSM_MAC(MKDMethod.OPTION_A, SKDMethod.MCHIP, imk, pan, seq, atc, null, null);
    }
}
""", {"3DES"})
    _c("java", "w8_jpos_EmvOfflineAuth.java", """
import java.math.BigInteger;
public class IssuerPk {
    // EMV Book 2 — recover issuer public key from certificate with CA public key
    byte[] recover(byte[] cert, BigInteger caMod, BigInteger caExp) {
        return new BigInteger(1, cert).modPow(caExp, caMod).toByteArray();
    }
}
""", set())
    _c("java", "w8_jpos_Kcv.java", """
import org.jpos.security.*;
public class Check {
    byte[] kcv(SMAdapter sm, SecureDESKey key) throws SMException {
        return sm.generateKeyCheckValue(key);
    }
}
""", {"3DES"})
    _c("java", "w8_jpos_SecureKeyStore.java", """
import org.jpos.security.*;
public class Store {
    SecureKeyStore ks = new SimpleKeyFile("cfg/keys");
    SecureDESKey zpk() throws Exception {
        return (SecureDESKey) ks.getKey("zpk");
    }
}
""", {"3DES"})

    # --------------------------------------------------------- Thales / HSM
    _c("java", "w8_thales_Adapter.java", """
import org.jpos.ee.hsm.ThalesAdapter;
public class Hsm {
    ThalesAdapter hsm;
    String translatePin(String pinBlock, String zpkSrc, String zpkDst) {
        String cmd = "CA" + zpkSrc + zpkDst + "12" + pinBlock + "01" + "01";
        return hsm.command("CA", cmd);
    }
}
""", {"3DES"})
    _c("java", "w8_thales_LmkVariant.java", """
public class Lmk {
    // ZPK encrypted under LMK pair 06-07 (variant LMK)
    String zpkUnderLMK = "U1234567890ABCDEF1234567890ABCDEF";
    String kcv = "A1B2C3";
}
""", {"3DES"})
    _c("java", "w8_pkcs11_provider.java", """
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
public class Pkcs11 {
    KeyStore load() throws Exception {
        Provider p = Security.getProvider("SunPKCS11").configure("/etc/hsm/pkcs11.cfg");
        Security.addProvider(p);
        KeyStore ks = KeyStore.getInstance("PKCS11", p);
        ks.load(null, "1234".toCharArray());
        return ks;
    }
}
""", {"X509"})
    _c("java", "w8_pkcs11_iaik.java", """
import iaik.pkcs.pkcs11.*;
import iaik.pkcs.pkcs11.objects.*;
public class Iaik {
    void sign(Session s, PrivateKey k, byte[] d) throws TokenException {
        s.signInit(Mechanism.get(PKCS11Constants.CKM_SHA256_RSA_PKCS), k);
        s.sign(d);
        s.encryptInit(Mechanism.get(PKCS11Constants.CKM_AES_CBC_PAD), null);
        s.wrapKey(Mechanism.get(PKCS11Constants.CKM_DES3_ECB), null, null);
    }
}
""", {"RSA", "SHA-256", "AES", "3DES"})
    _c("java", "w8_luna_provider.java", """
import com.safenetinc.luna.provider.LunaProvider;
import java.security.Security;
import javax.crypto.Cipher;
public class Luna {
    void init() throws Exception {
        Security.addProvider(new LunaProvider());
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding", "LunaProvider");
    }
}
""", {"AES"})
    _c("java", "w8_cloudhsm.java", """
import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import java.security.Security;
import java.security.Signature;
public class Chsm {
    void sign() throws Exception {
        Security.addProvider(new CloudHsmProvider());
        Signature s = Signature.getInstance("SHA256withECDSA", CloudHsmProvider.PROVIDER_NAME);
    }
}
""", {"ECDSA", "SHA-256"})
    _c("java", "w8_ibm_jcecca.java", """
import java.security.Security;
import javax.crypto.Cipher;
public class Zos {
    void f() throws Exception {
        Security.addProvider(new com.ibm.crypto.hdwrCCA.provider.IBMJCECCA());
        Cipher c = Cipher.getInstance("DESede/CBC/NoPadding", "IBMJCECCA");
    }
}
""", {"3DES"})

    # --------------------------------------------------------- SWIFT / 3DS
    _c("java", "w8_swift_lau.java", """
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
public class Lau {
    // SWIFT Alliance Access LAU signature over the message
    String lau(byte[] msg, byte[] leftKey, byte[] rightKey) throws Exception {
        Mac m = Mac.getInstance("HmacSHA256");
        m.init(new SecretKeySpec(concat(leftKey, rightKey), "HmacSHA256"));
        return java.util.Base64.getEncoder().encodeToString(m.doFinal(msg));
    }
    static byte[] concat(byte[] a, byte[] b) { return a; }
}
""", {"HMAC", "SHA-256"})
    _c("java", "w8_threeds_Cavv.java", """
public class Cavv {
    // 3-D Secure CAVV / AAV verification through the HSM
    boolean verify(SMAdapter sm, String pan, String cavv, SecureDESKey cvk) throws SMException {
        return sm.verifyCAVV(pan, cvk, cavv, "0", "0", "0");
    }
}
""", {"3DES"})
    _c("java", "w8_threeds_Jws.java", """
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
public class AcsSigned {
    String sign(java.security.interfaces.RSAPrivateKey k, String payload) throws Exception {
        JWSObject o = new JWSObject(new JWSHeader(JWSAlgorithm.PS256), new Payload(payload));
        o.sign(new RSASSASigner(k));
        return o.serialize();
    }
}
""", {"JWT", "RSA"})

    # ---------------------------------------------------------- COBOL-ish / misc
    _c("java", "w8_tokenization_fpe.java", """
import com.voltage.securedata.enterprise.*;
public class Fpe {
    String tokenize(FPE fpe, String pan) throws Exception {
        return fpe.protect(pan);
    }
}
""", set())
    _c("java", "w8_ff1.java", """
import org.bouncycastle.crypto.fpe.FPEFF1Engine;
import org.bouncycastle.crypto.params.FPEParameters;
import org.bouncycastle.crypto.params.KeyParameter;
public class Ff1 {
    byte[] enc(byte[] key, byte[] tweak, byte[] in) {
        FPEFF1Engine e = new FPEFF1Engine();
        e.init(true, new FPEParameters(new KeyParameter(key), 10, tweak));
        byte[] out = new byte[in.length];
        e.processBlock(in, 0, in.length, out, 0);
        return out;
    }
}
""", {"AES"})

    # ------------------------------------------------------------- negatives
    _c("java", "w8_neg_Luhn.java", """
public class Luhn {
    static boolean check(String pan) {
        int sum = 0; boolean alt = false;
        for (int i = pan.length() - 1; i >= 0; i--) {
            int n = pan.charAt(i) - '0';
            if (alt) { n *= 2; if (n > 9) n -= 9; }
            sum += n; alt = !alt;
        }
        return sum % 10 == 0;
    }
}
""", set())
    _c("java", "w8_neg_PanMask.java", """
public class Mask {
    static String mask(String pan) {
        return pan.substring(0, 6) + "******" + pan.substring(pan.length() - 4);
    }
    static String token(String pan) { return java.util.UUID.randomUUID().toString(); }
}
""", set())
    _c("java", "w8_neg_Iso8583Fields.java", """
import org.jpos.iso.*;
public class Msg {
    void build(ISOMsg m) throws ISOException {
        m.set(2, "4111111111111111");
        m.set(52, "0000000000000000"); // PIN data
        m.set(53, "2001000000000000"); // security related control information
        m.set(64, "00000000");         // MAC
    }
}
""", set())
    _c("java", "w8_neg_KeyValueStore.java", """
import java.util.Map;
public class Kv {
    Map<String, String> keys;
    String primaryKey(String id) { return keys.get("pk:" + id); }
    String foreignKey(String id) { return keys.get("fk:" + id); }
}
""", set())
    _c("java", "w8_neg_Base64Only.java", """
import java.util.Base64;
public class Enc {
    String e(byte[] b) { return Base64.getEncoder().encodeToString(b); }
    byte[] d(String s) { return Base64.getDecoder().decode(s); }
}
""", set())
    _c("java", "w8_neg_SettlementBatch.java", """
public class Settlement {
    void run(java.util.List<Txn> batch) {
        for (Txn t : batch) { if (t.amount() > 0) ledger.post(t); }
    }
    Ledger ledger; interface Txn { long amount(); } interface Ledger { void post(Txn t); }
}
""", set())
