package com.alteredworlds.keystoretest;

import android.app.Application;

import timber.log.Timber;

/**
 * Created by twcgilbert on 23/01/2018.
 */

public class MainApplication extends Application {
    @Override
    public void onCreate() {
        super.onCreate();

        // use Jake Wharton's Timber library for logging
        if (BuildConfig.DEBUG) {
            // only output logs in DEBUG builds
            Timber.plant(new Timber.DebugTree());
        }
    }
}
