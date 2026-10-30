package com.example.crypto;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;

public class RsaKeys {

    public KeyPair weakRsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        return generator.generateKeyPair();
    }

    public byte[] sign(byte[] payload) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(weakRsa().getPrivate());
        signature.update(payload);
        return signature.sign();
    }
}
