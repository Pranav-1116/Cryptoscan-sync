package com.example.samples;

import javax.crypto.KeyGenerator;
import java.security.KeyPairGenerator;

public class KeyGeneratorSamples {
    public void aes256() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
    }

    public void rsa1024() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);
    }
}
