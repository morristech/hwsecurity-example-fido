package de.cotech.hw.fido.example;


import android.app.Application;

import de.cotech.hw.SecurityKeyManager;
import de.cotech.hw.SecurityKeyManagerConfig;
import timber.log.Timber;

public class FidoExampleApplication extends Application {
    @Override
    public void onCreate() {
        super.onCreate();

        SecurityKeyManager securityKeyManager = SecurityKeyManager.getInstance();
        SecurityKeyManagerConfig.Builder configBuilder = new SecurityKeyManagerConfig.Builder();

        configBuilder.setAllowUntestedUsbDevices(true);

        if (BuildConfig.DEBUG) {
            Timber.plant(new Timber.DebugTree());
            configBuilder.setEnableDebugLogging(true);
        }

        securityKeyManager.init(this, configBuilder.build());
    }
}