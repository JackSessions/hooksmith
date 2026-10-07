package com.hooksmith.vulnlab;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

/* JADX INFO: loaded from: classes.dex */
public class MainActivity extends Activity {
    /* JADX INFO: Access modifiers changed from: private */
    public void work() throws Exception {
        Log.i("VulnLab", "work() start");
        byte[] bytes = "top secret".getBytes();
        new Crypto().encrypt(bytes);
        new SessionCrypto().seal("pw", bytes);
        new SessionCrypto().seal("pw", bytes);
        new TokenGen().newSessionToken();
        new Cosmetics().pickConfettiColor();
        new Api().fetch("http://example.com/profile");
        new SafeApi().fetch("https://example.com/");
        TlsLab tlsLab = new TlsLab();
        tlsLab.get("https://self-signed.badssl.com/", new TrustAllManager(), null);
        tlsLab.get("https://expired.badssl.com/", new StrictTrustManager(), null);
        tlsLab.get("https://wrong.host.badssl.com/", null, new AllowAllVerifier());
        tlsLab.get("https://wrong.host.badssl.com/", null, new StrictVerifier());
        Log.i("VulnLab", "work() done");
    }

    @Override // android.app.Activity
    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        TextView textView = new TextView(this);
        textView.setText("HookSmith VulnLab");
        setContentView(textView);
        new Thread(new Runnable() { // from class: com.hooksmith.vulnlab.MainActivity.1
            @Override // java.lang.Runnable
            public void run() {
                try {
                    MainActivity.this.work();
                } catch (Throwable th) {
                    Log.e("VulnLab", "work failed", th);
                }
            }
        }).start();
    }
}
