package com.demo.vault;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Crypto {
    private static final String KEY = "0123456789abcdef";

    public byte[] encrypt(byte[] data) throws Exception {
        SecretKeySpec spec = new SecretKeySpec(KEY.getBytes(), "AES");
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
        c.init(1, spec);
        return c.doFinal(data);
    }
}
