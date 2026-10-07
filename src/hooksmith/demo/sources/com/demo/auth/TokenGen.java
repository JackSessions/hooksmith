package com.demo.auth;

import java.util.Random;

public class TokenGen {
    public String newSessionToken() {
        Random r = new Random();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 16; i++) {
            sb.append(Integer.toHexString(r.nextInt(16)));
        }
        return sb.toString();
    }
}
