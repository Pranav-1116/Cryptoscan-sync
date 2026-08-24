package com.example.samples;

import java.security.MessageDigest;

public class MessageDigestSamples {
    public void weak() throws Exception {
        MessageDigest.getInstance("MD5");
        MessageDigest.getInstance("SHA-1");
    }

    public void strong() throws Exception {
        MessageDigest.getInstance("SHA-256");
    }
}
