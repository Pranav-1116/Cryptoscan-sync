package com.example.crypto;

import java.security.MessageDigest;

public class HashUtil {

    public byte[] md5(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("MD5");
        return digest.digest(data);
    }

    public byte[] sha1(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-1");
        return digest.digest(data);
    }

    public byte[] sha256(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(data);
    }
}
