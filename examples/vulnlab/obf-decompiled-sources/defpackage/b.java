package defpackage;

import java.net.HttpURLConnection;
import java.net.URL;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/* JADX INFO: loaded from: classes.dex */
public final class b {
    public final /* synthetic */ int a;

    public /* synthetic */ b(int i) {
        this.a = i;
    }

    public static void b(String str, X509TrustManager x509TrustManager, a aVar) {
        try {
            SSLContext sSLContext = SSLContext.getInstance("TLS");
            sSLContext.init(null, x509TrustManager == null ? null : new TrustManager[]{x509TrustManager}, null);
            HttpsURLConnection httpsURLConnection = (HttpsURLConnection) new URL(str).openConnection();
            httpsURLConnection.setSSLSocketFactory(sSLContext.getSocketFactory());
            if (aVar != null) {
                httpsURLConnection.setHostnameVerifier(aVar);
            }
            httpsURLConnection.setConnectTimeout(8000);
            httpsURLConnection.setReadTimeout(8000);
            httpsURLConnection.getResponseCode();
        } catch (Exception unused) {
        }
    }

    public final void a(String str) {
        switch (this.a) {
            case 0:
                try {
                    HttpURLConnection httpURLConnection = (HttpURLConnection) new URL(str).openConnection();
                    httpURLConnection.setConnectTimeout(3000);
                    httpURLConnection.setReadTimeout(3000);
                    httpURLConnection.getResponseCode();
                } catch (Exception unused) {
                    return;
                }
                break;
            default:
                try {
                    HttpURLConnection httpURLConnection2 = (HttpURLConnection) new URL(str).openConnection();
                    httpURLConnection2.setConnectTimeout(3000);
                    httpURLConnection2.setReadTimeout(3000);
                    httpURLConnection2.getResponseCode();
                } catch (Exception unused2) {
                    return;
                }
                break;
        }
    }
}
