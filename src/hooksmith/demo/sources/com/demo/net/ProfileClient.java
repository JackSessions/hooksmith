package com.demo.net;

import okhttp3.OkHttpClient;
import okhttp3.Request;

public class ProfileClient {
    private final OkHttpClient client = new OkHttpClient();

    public String fetchProfile(String url) throws Exception {
        Request req = new Request.Builder().url(url).build();
        return client.newCall(req).execute().body().string();
    }
}
