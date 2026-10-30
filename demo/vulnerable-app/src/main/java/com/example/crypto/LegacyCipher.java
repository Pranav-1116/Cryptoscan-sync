package com.example.crypto;

import javax.crypto.Cipher;

public class LegacyCipher {

    public byte[] tripleDes(byte[] input) throws Exception {
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        return cipher.doFinal(input);
    }

    public byte[] rc4(byte[] input) throws Exception {
        Cipher cipher = Cipher.getInstance("RC4");
        return cipher.doFinal(input);
    }
}
