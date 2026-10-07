package com.demo.net;

import java.net.HttpURLConnection;
import java.net.URL;

public class LegacyApi {
    private static final String BASE = "http://upload.demo-corp.example/api/v1/";

    public int upload(String path, byte[] body) throws Exception {
        URL url = new URL(BASE + path);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.getOutputStream().write(body);
        return conn.getResponseCode();
    }
}
