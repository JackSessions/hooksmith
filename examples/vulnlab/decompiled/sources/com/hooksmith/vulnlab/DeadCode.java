package com.hooksmith.vulnlab;

import javax.crypto.spec.SecretKeySpec;

/* JADX INFO: loaded from: classes.dex */
public class DeadCode {
    private static final byte[] LEGACY = {76, 69, 71, 65, 67, 89, 45, 75, 69, 89, 45, 49, 50, 51, 52, 53};

    public SecretKeySpec hiddenKey() {
        return new SecretKeySpec(LEGACY, "AES");
    }
}
