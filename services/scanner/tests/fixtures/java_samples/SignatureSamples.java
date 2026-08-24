package com.example.samples;

import java.security.Signature;

public class SignatureSamples {
    public void rsa() throws Exception {
        Signature.getInstance("SHA256withRSA");
    }
}
