package com.example.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

/**
 * Intentionally mixed-quality payment crypto for the CryptoScan demo.
 */
public class PaymentService {

    public byte[] encryptCardLegacy(byte[] cardNumber) throws Exception {
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.ENCRYPT_MODE, desKey());
        return cipher.doFinal(cardNumber);
    }

    public byte[] encryptCardEcb(byte[] cardNumber) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey(128));
        return cipher.doFinal(cardNumber);
    }

    public byte[] encryptCardModern(byte[] cardNumber) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey(256));
        return cipher.doFinal(cardNumber);
    }

    public String describe(byte[] payload) {
        return new String(payload, StandardCharsets.UTF_8);
    }

    private SecretKey desKey() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("DES");
        generator.init(56);
        return generator.generateKey();
    }

    private SecretKey aesKey(int bits) throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(bits);
        return generator.generateKey();
    }
}
