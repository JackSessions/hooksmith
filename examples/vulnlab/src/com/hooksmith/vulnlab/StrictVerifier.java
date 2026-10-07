package com.hooksmith.vulnlab;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;

/** The correct version: the platform's default verifier. */
public class StrictVerifier implements HostnameVerifier {
    @Override
    public boolean verify(String host, SSLSession session) {
        return HttpsURLConnection.getDefaultHostnameVerifier().verify(host, session);
    }
}
