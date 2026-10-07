package com.demo.vault;

import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class SessionCrypto {
    private static final String SCHEME = "AES";

    public byte[] seal(String password, byte[] data) throws Exception {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] key = f.generateSecret(new PBEKeySpec(password.toCharArray(), salt, 10000, 256)).getEncoded();
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(1, new SecretKeySpec(key, SCHEME));
        return c.doFinal(data);
    }
}
