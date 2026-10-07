package com.hooksmith.vulnlab;

import java.net.HttpURLConnection;
import java.net.URL;

/* JADX INFO: loaded from: classes.dex */
public class SafeApi {
    public int fetch(String str) {
        try {
            HttpURLConnection httpURLConnection = (HttpURLConnection) new URL(str).openConnection();
            httpURLConnection.setConnectTimeout(3000);
            httpURLConnection.setReadTimeout(3000);
            return httpURLConnection.getResponseCode();
        } catch (Exception e) {
            return -1;
        }
    }
}
