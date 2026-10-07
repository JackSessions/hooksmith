package com.hooksmith.vulnlab;

import java.net.URL;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

/* JADX INFO: loaded from: classes.dex */
public class TlsLab {
    public int get(String str, TrustManager trustManager, HostnameVerifier hostnameVerifier) {
        try {
            SSLContext sSLContext = SSLContext.getInstance("TLS");
            sSLContext.init(null, trustManager == null ? null : new TrustManager[]{trustManager}, null);
            HttpsURLConnection httpsURLConnection = (HttpsURLConnection) new URL(str).openConnection();
            httpsURLConnection.setSSLSocketFactory(sSLContext.getSocketFactory());
            if (hostnameVerifier != null) {
                httpsURLConnection.setHostnameVerifier(hostnameVerifier);
            }
            httpsURLConnection.setConnectTimeout(8000);
            httpsURLConnection.setReadTimeout(8000);
            return httpsURLConnection.getResponseCode();
        } catch (Exception e) {
            return -1;
        }
    }
}
