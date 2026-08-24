package com.example.samples;

import javax.crypto.spec.SecretKeySpec;

public class HardcodedKeySamples {
    public SecretKeySpec stringKey() {
        return new SecretKeySpec("supersecretkey!!".getBytes(), "AES");
    }

    public SecretKeySpec byteKey() {
        return new SecretKeySpec(new byte[] {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}, "AES");
    }
}
