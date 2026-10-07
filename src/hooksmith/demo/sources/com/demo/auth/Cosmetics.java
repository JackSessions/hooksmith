package com.demo.auth;

import java.util.Random;

public class Cosmetics {
    public int pickConfettiColor() {
        return new Random().nextInt(0xFFFFFF);
    }
}
