package com.hooksmith.vulnlab;

import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class SessionCrypto {
    public byte[] seal(String password, byte[] data) throws Exception {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] key = f.generateSecret(new PBEKeySpec(password.toCharArray(), salt, 1000, 128)).getEncoded();
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
        return c.doFinal(data);
    }
}
