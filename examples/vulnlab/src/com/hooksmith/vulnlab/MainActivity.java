package com.hooksmith.vulnlab;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

/** Deliberately vulnerable target for HookSmith. Exercises every code path on launch except DeadCode. */
public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        TextView t = new TextView(this);
        t.setText("HookSmith VulnLab");
        setContentView(t);
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    work();
                } catch (Throwable e) {
                    Log.e("VulnLab", "work failed", e);
                }
            }
        }).start();
    }

    private void work() throws Exception {
        Log.i("VulnLab", "work() start");
        byte[] data = "top secret".getBytes();
        new Crypto().encrypt(data);                    // hardcoded key           -> PROVEN
        new SessionCrypto().seal("pw", data);          // derived key (twice)     -> REFUTED
        new SessionCrypto().seal("pw", data);
        new TokenGen().newSessionToken();              // Random, security ctx    -> PROVEN
        new Cosmetics().pickConfettiColor();           // Random, cosmetic        -> REFUTED
        new Api().fetch("http://example.com/profile"); // cleartext               -> PROVEN
        new SafeApi().fetch("https://example.com/");   // https                   -> REFUTED
        TlsLab tls = new TlsLab();
        // public test hosts from badssl.com: valid chain / self-signed / expired / certificate for a different name
        tls.get("https://self-signed.badssl.com/", new TrustAllManager(), null);       // trust-all accepts a bad chain -> PROVEN
        tls.get("https://expired.badssl.com/", new StrictTrustManager(), null);        // strict manager rejects it     -> REFUTED
        tls.get("https://wrong.host.badssl.com/", null, new AllowAllVerifier());       // verifier accepts wrong host   -> PROVEN
        tls.get("https://wrong.host.badssl.com/", null, new StrictVerifier());         // verifier rejects wrong host   -> REFUTED
        Log.i("VulnLab", "work() done");
        // DeadCode.hiddenKey() is never called                                   -> UNREACHABLE
    }
}
