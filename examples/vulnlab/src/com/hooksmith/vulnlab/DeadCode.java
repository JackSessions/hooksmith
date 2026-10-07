package com.hooksmith.vulnlab;

import javax.crypto.spec.SecretKeySpec;

/** Looks terrible, but nothing ever calls it: the honest verdict is UNREACHABLE, not PROVEN. */
public class DeadCode {
    private static final byte[] LEGACY = new byte[]{0x4c, 0x45, 0x47, 0x41, 0x43, 0x59, 0x2d, 0x4b, 0x45, 0x59, 0x2d, 0x31, 0x32, 0x33, 0x34, 0x35};

    public SecretKeySpec hiddenKey() {
        return new SecretKeySpec(LEGACY, "AES");
    }
}
