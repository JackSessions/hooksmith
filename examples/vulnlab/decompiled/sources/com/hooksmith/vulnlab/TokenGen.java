package com.hooksmith.vulnlab;

import java.util.Random;

/* JADX INFO: loaded from: classes.dex */
public class TokenGen {
    public String newSessionToken() {
        Random random = new Random();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 16; i++) {
            sb.append(Integer.toHexString(random.nextInt(16)));
        }
        return sb.toString();
    }
}
