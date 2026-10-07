package com.demo.vault;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class PinStore {
    private static final byte[] MASTER = new byte[]{0x50, 0x49, 0x4e, 0x2d, 0x6d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x2d, 0x6b, 0x65, 0x79, 0x2d, 0x31};

    public byte[] protect(byte[] pin) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(1, new SecretKeySpec(MASTER, "AES"));
        return c.doFinal(pin);
    }
}
