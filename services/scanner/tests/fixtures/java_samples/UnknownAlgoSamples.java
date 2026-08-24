package com.example.samples;

import javax.crypto.Cipher;

public class UnknownAlgoSamples {
    public void dynamic(String algo) throws Exception {
        Cipher.getInstance(algo);
    }
}
