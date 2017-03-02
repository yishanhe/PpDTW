package net.yishanhe.mobileppgra;

import android.os.Bundle;
import android.support.design.widget.FloatingActionButton;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.view.View;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.Button;

import net.yishanhe.benchmark.BenchmarkOT;
import net.yishanhe.benchmark.BenchmarkPaillier;
import net.yishanhe.main.MobilePPGRA;

public class MainActivity extends AppCompatActivity {

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
                MobilePPGRA.main(null);
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
}
