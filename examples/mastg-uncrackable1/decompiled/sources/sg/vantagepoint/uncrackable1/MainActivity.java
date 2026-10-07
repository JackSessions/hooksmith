package sg.vantagepoint.uncrackable1;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.os.Bundle;
import android.view.View;
import android.widget.EditText;
import owasp.mstg.uncrackable1.R;
import sg.vantagepoint.a.b;
import sg.vantagepoint.a.c;

/* JADX INFO: loaded from: classes.dex */
public class MainActivity extends Activity {
    private void a(String str) {
        AlertDialog alertDialogCreate = new AlertDialog.Builder(this).create();
        alertDialogCreate.setTitle(str);
        alertDialogCreate.setMessage("This is unacceptable. The app is now going to exit.");
        alertDialogCreate.setButton(-3, "OK", new DialogInterface.OnClickListener() { // from class: sg.vantagepoint.uncrackable1.MainActivity.1
            @Override // android.content.DialogInterface.OnClickListener
            public void onClick(DialogInterface dialogInterface, int i) {
                System.exit(0);
            }
        });
        alertDialogCreate.setCancelable(false);
        alertDialogCreate.show();
    }

    @Override // android.app.Activity
    protected void onCreate(Bundle bundle) {
        if (c.a() || c.b() || c.c()) {
            a("Root detected!");
        }
        if (b.a(getApplicationContext())) {
            a("App is debuggable!");
        }
        super.onCreate(bundle);
        setContentView(R.layout.activity_main);
    }

    public void verify(View view) {
        String str;
        String string = ((EditText) findViewById(R.id.edit_text)).getText().toString();
        AlertDialog alertDialogCreate = new AlertDialog.Builder(this).create();
        if (a.a(string)) {
            alertDialogCreate.setTitle("Success!");
            str = "This is the correct secret.";
        } else {
            alertDialogCreate.setTitle("Nope...");
            str = "That's not it. Try again.";
        }
        alertDialogCreate.setMessage(str);
        alertDialogCreate.setButton(-3, "OK", new DialogInterface.OnClickListener() { // from class: sg.vantagepoint.uncrackable1.MainActivity.2
            @Override // android.content.DialogInterface.OnClickListener
            public void onClick(DialogInterface dialogInterface, int i) {
                dialogInterface.dismiss();
            }
        });
        alertDialogCreate.show();
    }
}
