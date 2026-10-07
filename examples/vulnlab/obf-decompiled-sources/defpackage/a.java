package defpackage;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;

/* JADX INFO: loaded from: classes.dex */
public final class a implements HostnameVerifier {
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i) {
        this.a = i;
    }

    @Override // javax.net.ssl.HostnameVerifier
    public final boolean verify(String str, SSLSession sSLSession) {
        switch (this.a) {
            case 0:
                return true;
            default:
                return HttpsURLConnection.getDefaultHostnameVerifier().verify(str, sSLSession);
        }
    }
}
