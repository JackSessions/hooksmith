package sg.vantagepoint.uncrackable1;

import android.util.Base64;
import android.util.Log;

/* JADX INFO: loaded from: classes.dex */
public class a {
    public static boolean a(String str) {
        byte[] bArrA;
        byte[] bArr = new byte[0];
        try {
            bArrA = sg.vantagepoint.a.a.a(b("8d127684cbc37c17616d806cf50473cc"), Base64.decode("5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc=", 0));
        } catch (Exception e) {
            Log.d("CodeCheck", "AES error:" + e.getMessage());
            bArrA = bArr;
        }
        return str.equals(new String(bArrA));
    }

    public static byte[] b(String str) {
        int length = str.length();
        byte[] bArr = new byte[length / 2];
        for (int i = 0; i < length; i += 2) {
            bArr[i / 2] = (byte) ((Character.digit(str.charAt(i), 16) << 4) + Character.digit(str.charAt(i + 1), 16));
        }
        return bArr;
    }
}
