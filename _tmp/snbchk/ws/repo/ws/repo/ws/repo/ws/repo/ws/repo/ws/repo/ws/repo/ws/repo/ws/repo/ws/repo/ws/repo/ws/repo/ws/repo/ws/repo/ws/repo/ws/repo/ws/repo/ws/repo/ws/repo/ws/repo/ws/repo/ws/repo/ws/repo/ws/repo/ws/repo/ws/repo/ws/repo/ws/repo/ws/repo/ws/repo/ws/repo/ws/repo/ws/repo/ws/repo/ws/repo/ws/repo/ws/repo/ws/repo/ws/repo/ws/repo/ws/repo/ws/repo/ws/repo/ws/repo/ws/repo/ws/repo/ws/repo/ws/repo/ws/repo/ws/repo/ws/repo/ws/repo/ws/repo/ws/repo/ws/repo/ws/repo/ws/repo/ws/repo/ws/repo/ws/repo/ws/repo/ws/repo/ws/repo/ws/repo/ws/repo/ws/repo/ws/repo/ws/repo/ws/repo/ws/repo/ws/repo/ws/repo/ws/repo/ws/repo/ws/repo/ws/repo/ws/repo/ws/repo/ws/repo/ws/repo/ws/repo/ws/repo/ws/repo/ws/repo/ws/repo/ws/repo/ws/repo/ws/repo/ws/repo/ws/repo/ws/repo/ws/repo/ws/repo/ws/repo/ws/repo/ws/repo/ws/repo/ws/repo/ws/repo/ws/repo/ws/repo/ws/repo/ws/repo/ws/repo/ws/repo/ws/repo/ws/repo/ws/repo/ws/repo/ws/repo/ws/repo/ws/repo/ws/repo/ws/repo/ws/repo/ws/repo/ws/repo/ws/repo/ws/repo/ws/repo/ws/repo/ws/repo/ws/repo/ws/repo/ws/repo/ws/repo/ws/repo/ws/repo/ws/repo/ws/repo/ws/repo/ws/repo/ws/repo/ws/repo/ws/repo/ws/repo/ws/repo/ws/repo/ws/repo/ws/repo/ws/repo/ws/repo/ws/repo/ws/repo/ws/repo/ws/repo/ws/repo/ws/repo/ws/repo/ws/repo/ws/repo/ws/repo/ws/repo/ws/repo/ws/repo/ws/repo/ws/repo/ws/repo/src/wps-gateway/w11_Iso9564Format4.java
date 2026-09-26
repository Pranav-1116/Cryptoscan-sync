package com.bank.pin;

public final class Iso9564Format4 {
    /** ISO 9564-1 format 4: AES-128 PIN block (PCI PIN v3 requirement 18-3 migration). */
    public byte[] encipher(byte[] pinField, byte[] panField, javax.crypto.SecretKey pek) throws Exception {
        javax.crypto.Cipher aes = javax.crypto.Cipher.getInstance("AES/ECB/NoPadding");
        aes.init(javax.crypto.Cipher.ENCRYPT_MODE, pek);
        byte[] intermediate = aes.doFinal(pinField);
        for (int i = 0; i < 16; i++) intermediate[i] ^= panField[i];
        return aes.doFinal(intermediate);
    }
}
