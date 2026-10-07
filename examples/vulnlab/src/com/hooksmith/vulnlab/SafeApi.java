package com.hooksmith.vulnlab;

import java.net.HttpURLConnection;
import java.net.URL;

public class SafeApi {
    public int fetch(String url) {
        try {
            HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
            conn.setConnectTimeout(3000);
            conn.setReadTimeout(3000);
            return conn.getResponseCode();
        } catch (Exception e) {
            return -1;
        }
    }
}
