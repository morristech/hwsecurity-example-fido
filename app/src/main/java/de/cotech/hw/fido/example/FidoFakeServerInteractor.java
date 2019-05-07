package de.cotech.hw.fido.example;


import java.io.IOException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.NoSuchElementException;

import android.content.Context;

import de.cotech.hw.fido.FidoAuthenticateRequest;
import de.cotech.hw.fido.FidoAuthenticateResponse;
import de.cotech.hw.fido.FidoFacetIdUtil;
import de.cotech.hw.fido.FidoRegisterRequest;
import de.cotech.hw.fido.FidoRegisterResponse;
import de.cotech.hw.fido.ParsedFidoAuthenticateResponse;
import de.cotech.hw.fido.ParsedFidoRegisterResponse;
import de.cotech.hw.fido.internal.FidoU2fBase64;


/**
 * A simple stand-in for a FIDO-authentication enabled web server, for demonstration purposes.
 */
@SuppressWarnings({ "WeakerAccess", "unused", "UnnecessaryLocalVariable" }) // for demonstration purposes
public class FidoFakeServerInteractor {
    // A FIDO AppID that identifies our "application" as a whole. See https://developers.yubico.com/U2F/App_ID.html
    private static final String FIDO_APP_ID = "https://fido-login.example.com/app-id.json";

    // The FIDO facet id, which identifiers this specific App.
    private final String fidoFacetId;

    // As a "database" of user logins, we simply remember a key handle and public key per registered username.
    private HashMap<String, RegisteredUser> registeredFidoKeyHandleByUsername = new HashMap<>();

    public FidoFakeServerInteractor(Context context) {
        // Generate the FacetID that identifiers this particular App. This is based on the signing key,
        // and thus uniquely identifies this App.
        fidoFacetId = FidoFacetIdUtil.getFacetIdForApp(context);
    }


    // Registration

    public FidoRegisterRequest fidoRegisterRequest(String username) {
        // Generate a challenge, and remember it for this user.
        String challenge = generateRegistrationChallengeForUser(username);
        return FidoRegisterRequest.create(FIDO_APP_ID, fidoFacetId, challenge);
    }

    public void fidoRegisterFinish(String username, FidoRegisterResponse registerResponse) throws IOException {
        // Perform checks, if anything fails throw an exception
        RegisteredUser registeredUser = checkRegistrationChallengeForUsername(username, registerResponse);
        // If successful, save the public key and key handle, which identify the FIDO Security Key for this user.
        registeredFidoKeyHandleByUsername.put(username, registeredUser);
    }

    private String generateRegistrationChallengeForUser(String username) {
        String registrationChallenge = generateChallenge();

        // TODO
        // A real server would persist this challenge for the user, to check later on that the signed challenge
        // matches what we generated here.

        return registrationChallenge;
    }

    private RegisteredUser checkRegistrationChallengeForUsername(String username, FidoRegisterResponse registerResponse)
            throws IOException {
        ParsedFidoRegisterResponse parsedResponse = registerResponse.toParsedFidoRegisterResponse();

        // TODO
        // On a real server, this would check that the signature in FidoRegisterResponse matches the client data
        // as expected, and that the signed challenge is one we generated for this user. We could also check the
        // attestation of the FIDO Security Key, to make sure it's from a trusted hardware vendor.

        // For this demo, we just skip these checks.

        return new RegisteredUser(parsedResponse.getUserPublicKey(), parsedResponse.getKeyHandle());
    }


    // Authentication

    public FidoAuthenticateRequest fidoAuthenticateRequest(String username) {
        // Get key handle and public key struct, which identifies the FIDO Security Key that the user registered before.
        RegisteredUser registeredUser = registeredFidoKeyHandleByUsername.get(username);
        if (registeredUser == null) {
            throw new NoSuchElementException();
        }

        // Generate an authentication challenge, and remember it for this user.
        String fidoChallenge = generateAuthenticationChallengeForUser(username);
        return FidoAuthenticateRequest.create(FIDO_APP_ID, fidoFacetId, fidoChallenge, registeredUser.keyHandle);
    }

    public void fidoAuthenticateFinish(String username, FidoAuthenticateResponse authenticateResponse) throws IOException {
        // Get key handle and public key struct, which identifies the FIDO Security Key that the user registered before.
        RegisteredUser registeredUser = registeredFidoKeyHandleByUsername.get(username);
        if (registeredUser == null) {
            throw new IOException("No such registered user!");
        }

        // Perform checks, if anything fails throw an exception
        checkAuthenticationChallengeForUsername(username, registeredUser, authenticateResponse);
    }

    private String generateAuthenticationChallengeForUser(String username) {
        String authChallenge = generateChallenge();

        // TODO
        // A real server would persist this challenge for the user, to check later on that the signed challenge
        // matches what we generated here (see below)

        return authChallenge;
    }

    private void checkAuthenticationChallengeForUsername(String username, RegisteredUser user,
            FidoAuthenticateResponse authenticateResponse) throws IOException {
        ParsedFidoAuthenticateResponse parsedResponse = authenticateResponse.toParsedFidoAuthenticateResponse();

        // TODO
        // On a real server, we would check here that the signature in FidoAuthenticateResponse matches the
        // client data, and that the client data is what we expect (type, presence, and challenge)
    }


    private String generateChallenge() {
        // Returns a newly generated 16 bytes random challenge, in url-safe base64 encoding
        SecureRandom secureRandom = new SecureRandom();
        byte[] challengeBytes = new byte[16];
        secureRandom.nextBytes(challengeBytes);
        return FidoU2fBase64.encode(challengeBytes);
    }


    /** A registered user is identified by their public key and key handle. */
    private static class RegisteredUser {
        private final byte[] userPublicKey;
        private final byte[] keyHandle;

        public RegisteredUser(byte[] userPublicKey, byte[] keyHandle) {
            this.userPublicKey = userPublicKey;
            this.keyHandle = keyHandle;
        }
    }
}
