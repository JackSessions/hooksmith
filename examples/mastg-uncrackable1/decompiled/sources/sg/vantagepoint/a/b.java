package sg.vantagepoint.a;

import android.content.Context;

/* JADX INFO: loaded from: classes.dex */
public class b {
    public static boolean a(Context context) {
        return (context.getApplicationContext().getApplicationInfo().flags & 2) != 0;
    }
}
