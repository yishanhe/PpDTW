package net.yishanhe.mobileppdtw;

import android.Manifest;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.design.widget.FloatingActionButton;
import android.support.design.widget.Snackbar;
import android.support.v4.app.ActivityCompat;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.view.View;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.Button;
import android.widget.Toast;

import net.yishanhe.benchmark.BenchmarkOT;
import net.yishanhe.benchmark.BenchmarkPaillier;
import net.yishanhe.main.MeasureMain;

public class MainActivity extends AppCompatActivity {


    private final static String[] PERMISSIONS = {Manifest.permission.READ_EXTERNAL_STORAGE};
    private final static int REQUEST_PERMISSIONS = 1;
    private Button paillierBtn;
    private Button otBtn;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        FloatingActionButton fab = (FloatingActionButton) findViewById(R.id.fab);
        fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Snackbar.make(view, "Call sclib on smartphone.", Snackbar.LENGTH_SHORT)
                        .setAction("Action", null).show();
//                MobilePPGRA.main(null);
//                /sdcard/fast/
                MeasureMain.Run("/sdcard/fast/check01.xml","/sdcard/fast/check01.xml");
                MeasureMain.Run("/sdcard/fast/check01.xml","/sdcard/fast/circle01.xml");
                MeasureMain.Run("/sdcard/fast/check01.xml","/sdcard/fast/delete_mark01.xml");
                MeasureMain.Run("/sdcard/fast/check01.xml","/sdcard/fast/pigtail01.xml");
                MeasureMain.Run("/sdcard/fast/check01.xml","/sdcard/fast/question_mark01.xml");
                MeasureMain.Run("/sdcard/fast/check01.xml","/sdcard/fast/rectangle01.xml");
                MeasureMain.Run("/sdcard/fast/check01.xml","/sdcard/fast/triangle01.xml");
            }
        });

        paillierBtn = (Button) findViewById(R.id.paillier);
        paillierBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                BenchmarkPaillier.benchmarking(64);
                BenchmarkPaillier.benchmarking(128);
                BenchmarkPaillier.benchmarking(256);
                BenchmarkPaillier.benchmarking(512);
                BenchmarkPaillier.benchmarking(1024);
                BenchmarkPaillier.benchmarking(2048);
            }
        });

        otBtn = (Button) findViewById(R.id.ot);
        otBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                BenchmarkOT.main(null);
            }
        });

        if (!hasPermissions(MainActivity.this, PERMISSIONS)) {
            ActivityCompat.requestPermissions(MainActivity.this, PERMISSIONS, REQUEST_PERMISSIONS);
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }


    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        switch (requestCode) {
            case REQUEST_PERMISSIONS:
                if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                    Toast.makeText(this, "Permission Granted", Toast.LENGTH_SHORT).show();
                    recreate();
                }
                else {
                    Toast.makeText(this, "Fail to get permission.", Toast.LENGTH_SHORT).show();
                    finish();
                }
        }
    }

    public static boolean hasPermissions(Context context, String[] permissions) {
        if (Build.VERSION.SDK_INT > Build.VERSION_CODES.M && context!=null) {
            for (String permission :
                    permissions) {
                if (ActivityCompat.checkSelfPermission(context, permission) != PackageManager.PERMISSION_GRANTED) {
                    return false;
                }
            }
        }
        return true;
    }
}
