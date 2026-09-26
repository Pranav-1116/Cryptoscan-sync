package com.bank.pin;

public final class Iso9564Format0 {
    /** ISO 9564-1 format 0: PIN field XOR PAN field, then TDEA under the ZPK. */
    public byte[] encipher(String pin, String pan, javax.crypto.SecretKey zpk) throws Exception {
        byte[] pinField = pinField(pin);
        byte[] panField = panField(pan);
        byte[] clear = new byte[8];
        for (int i = 0; i < 8; i++) clear[i] = (byte) (pinField[i] ^ panField[i]);
        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("DESede/ECB/NoPadding");
        c.init(javax.crypto.Cipher.ENCRYPT_MODE, zpk);
        return c.doFinal(clear);
    }
}
