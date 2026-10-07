package com.hooksmith.vulnlab;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;
import defpackage.a;
import defpackage.b;
import defpackage.c;
import defpackage.d;
import defpackage.e;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/* JADX INFO: loaded from: classes.dex */
public class MainActivity extends Activity {
    /* JADX INFO: Access modifiers changed from: private */
    public void work() throws BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeyException {
        Log.i("VulnLab", "work() start");
        byte[] bytes = "top secret".getBytes();
        SecretKeySpec secretKeySpec = new SecretKeySpec("0123456789abcdef".getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        int i = 1;
        cipher.init(1, secretKeySpec);
        cipher.doFinal(bytes);
        byte[] bArr = new byte[16];
        new SecureRandom().nextBytes(bArr);
        byte[] encoded = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1").generateSecret(new PBEKeySpec("pw".toCharArray(), bArr, 1000, 128)).getEncoded();
        Cipher cipher2 = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher2.init(1, new SecretKeySpec(encoded, "AES"));
        cipher2.doFinal(bytes);
        byte[] bArr2 = new byte[16];
        new SecureRandom().nextBytes(bArr2);
        byte[] encoded2 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1").generateSecret(new PBEKeySpec("pw".toCharArray(), bArr2, 1000, 128)).getEncoded();
        Cipher cipher3 = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher3.init(1, new SecretKeySpec(encoded2, "AES"));
        cipher3.doFinal(bytes);
        Random random = new Random();
        int i2 = 0;
        for (int i3 = 0; i3 < 16; i3++) {
            Integer.toHexString(random.nextInt(16));
        }
        new Random().nextInt(16777215);
        new b(i2).a("http://example.com/profile");
        new b(3).a("https://example.com/");
        b.b("https://self-signed.badssl.com/", new e(), null);
        b.b("https://expired.badssl.com/", new d(), null);
        b.b("https://wrong.host.badssl.com/", null, new a(i2));
        b.b("https://wrong.host.badssl.com/", null, new a(i));
        Log.i("VulnLab", "work() done");
    }

    @Override // android.app.Activity
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        TextView textView = new TextView(this);
        textView.setText("HookSmith VulnLab");
        setContentView(textView);
        new Thread(new c(this)).start();
    }
}
