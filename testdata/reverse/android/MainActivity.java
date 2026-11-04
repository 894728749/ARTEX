package org.artex.fixture;

import android.app.Activity;
import android.os.Bundle;
import android.os.Handler;
import android.util.Log;

/** Synthetic local sample; no network permission or external data. */
public final class MainActivity extends Activity {
    public static synchronized int transform(int value) { return value * 3 + 7; }
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        final Handler handler = new Handler();
        handler.postDelayed(new Runnable() {
            int remaining = 100;
            @Override public void run() {
                Log.i("ARTEX_FIXTURE", "transform=" + transform(3));
                if (--remaining > 0) handler.postDelayed(this, 100);
            }
        }, 200);
    }
}
