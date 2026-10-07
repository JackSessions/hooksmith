package com.demo.jni;

public class NativeCrypto {
    static {
        System.loadLibrary("nativecrypto");
    }

    public native byte[] decrypt(byte[] blob);
}
