package com.hooksmith.vulnlab;

import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/* JADX INFO: loaded from: classes.dex */
public class SessionCrypto {
    public byte[] seal(String str, byte[] bArr) throws Exception {
        byte[] bArr2 = new byte[16];
        new SecureRandom().nextBytes(bArr2);
        byte[] encoded = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1").generateSecret(new PBEKeySpec(str.toCharArray(), bArr2, 1000, 128)).getEncoded();
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(1, new SecretKeySpec(encoded, "AES"));
        return cipher.doFinal(bArr);
    }
}
