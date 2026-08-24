package com.example.samples;

import javax.crypto.Cipher;
import java.security.MessageDigest;

public class CompliantSamples {
    public void modern() throws Exception {
        Cipher.getInstance("AES/GCM/NoPadding");
        MessageDigest.getInstance("SHA-256");
    }
}
