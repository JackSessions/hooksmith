package defpackage;

import android.util.Log;
import com.hooksmith.vulnlab.MainActivity;

/* JADX INFO: loaded from: classes.dex */
public final class c implements Runnable {
    public final /* synthetic */ MainActivity a;

    public c(MainActivity mainActivity) {
        this.a = mainActivity;
    }

    @Override // java.lang.Runnable
    public final void run() {
        try {
            this.a.work();
        } catch (Throwable th) {
            Log.e("VulnLab", "work failed", th);
        }
    }
}
