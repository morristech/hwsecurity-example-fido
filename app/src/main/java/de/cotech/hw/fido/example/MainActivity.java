package de.cotech.hw.fido.example;


import java.io.IOException;
import java.util.NoSuchElementException;

import android.os.Bundle;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import de.cotech.hw.fido.FidoAuthenticateRequest;
import de.cotech.hw.fido.FidoAuthenticateResponse;
import de.cotech.hw.fido.FidoRegisterRequest;
import de.cotech.hw.fido.FidoRegisterResponse;
import de.cotech.hw.fido.ParsedFidoAuthenticateResponse;
import de.cotech.hw.fido.ParsedFidoRegisterResponse;
import de.cotech.hw.fido.ui.FidoDialogFragment;
import de.cotech.hw.fido.ui.FidoDialogFragment.OnFidoAuthenticateCallback;
import de.cotech.hw.fido.ui.FidoDialogFragment.OnFidoRegisterCallback;
import timber.log.Timber;


/**
 * This is an example Activity which performs registration and authentication operations
 * on a FIDO Security Key, using the Cotech Hardware Security SDK.
 */
public class MainActivity extends AppCompatActivity implements OnFidoAuthenticateCallback, OnFidoRegisterCallback {
    private static final String USERNAME = "testuser";

    private TextView log;

    // A simple interface to a (fake) FIDO server backend. See FidoFakeServerInteractor for details.
    private FidoFakeServerInteractor fidoFakeServerInteractor;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        log = findViewById(R.id.textLog);

        fidoFakeServerInteractor = new FidoFakeServerInteractor(getApplicationContext());

        findViewById(R.id.buttonFidoRegister).setOnClickListener(v -> showFidoRegisterDialog());
        findViewById(R.id.buttonFidoAuthenticate).setOnClickListener(v -> showFidoAuthenticateDialog());
    }


    private void showFidoRegisterDialog() {
        // Make a registration request to the server. In a real application, this would perform
        // an HTTP request. The server sends us a challenge (and some other data), that we proceed
        // to sign with our FIDO Security Key.
        FidoRegisterRequest registerRequest = fidoFakeServerInteractor.fidoRegisterRequest(USERNAME);

        // This opens a UI fragment, which takes care of the user interaction as well as all FIDO
        // internal operations for us, and triggers a callback to #onRegisterResponse(FidoRegisterResponse).
        FidoDialogFragment fidoDialogFragment = FidoDialogFragment.newInstance(registerRequest);
        fidoDialogFragment.show(getSupportFragmentManager());
    }

    @Override
    public void onRegisterResponse(@NonNull FidoRegisterResponse registerResponse) {
        try {
            // Output some debug information. Usually, we would not care about the actual content of the
            // response and just forward it to the server.
            ParsedFidoRegisterResponse parsedResponse = registerResponse.toParsedFidoRegisterResponse();
            showDebugInfo(parsedResponse);

            // Forward the registration response from the FIDO Security Key to our server application.
            // The server will perform some checks, and then remember this FIDO key as a registered
            // login mechanism for this user.
            fidoFakeServerInteractor.fidoRegisterFinish(USERNAME, registerResponse);

            // Success!
            Toast.makeText(this, "Registration successful!", Toast.LENGTH_LONG).show();
        } catch (IOException e) {
            Timber.e(e);
            Toast.makeText(this, "Register operation failed!", Toast.LENGTH_LONG).show();
        }
    }


    private void showFidoAuthenticateDialog() {
        // Make an authentication request to the server. In a real application, this would perform
        // an HTTP request. The server will send us a challenge based on the FIDO key we registered
        // before (see above), asking us to prove we still have the same key.
        FidoAuthenticateRequest authenticateRequest;
        try {
            authenticateRequest = fidoFakeServerInteractor.fidoAuthenticateRequest(USERNAME);
        } catch (NoSuchElementException e) {
            Toast.makeText(this, "No FIDO key registered - use register operation first!", Toast.LENGTH_LONG).show();
            return;
        }

        // This opens a UI fragment, which takes care of the user interaction as well as all FIDO internal
        // operations for us, and triggers a callback to #onAuthenticateResponse(FidoAuthenticateResponse).
        FidoDialogFragment fidoDialogFragment = FidoDialogFragment.newInstance(authenticateRequest);
        fidoDialogFragment.show(getSupportFragmentManager());
    }

    @Override
    public void onAuthenticateResponse(@NonNull FidoAuthenticateResponse authenticateResponse) {
        try {
            // Output some debug information. Usually, we would not care about the actual content of the
            // response and just forward it to the server.
            ParsedFidoAuthenticateResponse parsedResponse = authenticateResponse.toParsedFidoAuthenticateResponse();
            showDebugInfo(parsedResponse);

            // Forward the authentication response from the FIDO Security Key to our server application.
            // The server will check that the signature matches the FIDO key we registered with, and if
            // so we have successfully logged in.
            fidoFakeServerInteractor.fidoAuthenticateFinish(USERNAME, authenticateResponse);

            // Success!
            Toast.makeText(this, "Authentication successful!", Toast.LENGTH_LONG).show();
        } catch (IOException e) {
            Timber.e(e);
            Toast.makeText(this, "Authentication operation failed!", Toast.LENGTH_LONG).show();
        }
    }

    private void showDebugInfo(Object debugObject) {
        // Simply output the String representation of whatever object we get, in the UI and logcat
        Timber.d("%s: %s", debugObject.getClass().getSimpleName(), debugObject);
        log.setText(debugObject.toString());
    }
}
