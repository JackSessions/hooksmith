package com.demo.auth;

import java.util.Random;

public class PromoRotator {
    public int nextPromoCode() {
        Random seed = new Random(42L);
        return seed.nextInt(100000);
    }
}
