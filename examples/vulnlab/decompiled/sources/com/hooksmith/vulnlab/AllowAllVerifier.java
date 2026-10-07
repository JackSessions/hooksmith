package com.hooksmith.vulnlab;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

/* JADX INFO: loaded from: classes.dex */
public class AllowAllVerifier implements HostnameVerifier {
    @Override // javax.net.ssl.HostnameVerifier
    public boolean verify(String str, SSLSession sSLSession) {
        return true;
    }
}
