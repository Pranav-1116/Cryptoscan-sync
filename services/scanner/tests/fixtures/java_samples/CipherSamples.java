package com.example.samples;

import javax.crypto.Cipher;

public class CipherSamples {
    public void des() throws Exception {
        Cipher.getInstance("DES");
    }

    public void aesEcb() throws Exception {
        Cipher.getInstance("AES/ECB/PKCS5Padding");
    }

    public void aesGcm() throws Exception {
        Cipher.getInstance("AES/GCM/NoPadding");
    }
}
