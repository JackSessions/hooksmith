package com.hooksmith.vulnlab;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

/** Deliberately broken: any hostname is fine. */
public class AllowAllVerifier implements HostnameVerifier {
    @Override
    public boolean verify(String host, SSLSession session) {
        return true;
    }
}
