package com.hooksmith.vulnlab;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/* JADX INFO: loaded from: classes.dex */
public class Crypto {
    private static final String KEY = "0123456789abcdef";

    public byte[] encrypt(byte[] bArr) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(KEY.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(1, secretKeySpec);
        return cipher.doFinal(bArr);
    }
}
