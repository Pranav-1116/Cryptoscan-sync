package com.example.samples;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.PBEKeySpec;
import javax.net.ssl.SSLContext;
import java.security.KeyStore;
import java.security.SecureRandom;

public class TlsAndProviderSamples {
    public void tls() throws Exception {
        SSLContext.getInstance("TLSv1.2");
        KeyStore.getInstance("JKS");
        KeyAgreement.getInstance("ECDH");
        SecureRandom.getInstance("SHA1PRNG");
        new PBEKeySpec("pw".toCharArray());
        Cipher.getInstance("AES/GCM/NoPadding", "BC");
    }
}
