package com.hooksmith.vulnlab;

import java.util.Random;

/* JADX INFO: loaded from: classes.dex */
public class Cosmetics {
    public int pickConfettiColor() {
        return new Random().nextInt(16777215);
    }
}
