package com.hooksmith.vulnlab;

import java.net.URL;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

/** Connects with a chosen trust manager and hostname verifier; returns the HTTP status or -1 on any failure. */
public class TlsLab {
    public int get(String url, TrustManager tm, HostnameVerifier hv) {
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, tm == null ? null : new TrustManager[]{tm}, null);
            HttpsURLConnection c = (HttpsURLConnection) new URL(url).openConnection();
            c.setSSLSocketFactory(ctx.getSocketFactory());
            if (hv != null) {
                c.setHostnameVerifier(hv);
            }
            c.setConnectTimeout(8000);
            c.setReadTimeout(8000);
            return c.getResponseCode();
        } catch (Exception e) {
            return -1;
        }
    }
}
