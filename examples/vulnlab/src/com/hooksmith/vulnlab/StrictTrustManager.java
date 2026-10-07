package com.hooksmith.vulnlab;

import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/** The correct version: delegates to the platform trust manager, so bad chains are rejected. */
public class StrictTrustManager implements X509TrustManager {
    private final X509TrustManager delegate;

    public StrictTrustManager() throws Exception {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init((KeyStore) null);
        X509TrustManager found = null;
        for (TrustManager t : tmf.getTrustManagers()) {
            if (t instanceof X509TrustManager) {
                found = (X509TrustManager) t;
            }
        }
        this.delegate = found;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        delegate.checkClientTrusted(chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        delegate.checkServerTrusted(chain, authType);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return delegate.getAcceptedIssuers();
    }
}
