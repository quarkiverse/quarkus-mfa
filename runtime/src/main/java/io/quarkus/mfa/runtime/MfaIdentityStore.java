package io.quarkus.mfa.runtime;

import java.util.Map;

import io.quarkus.security.credential.PasswordCredential;

public interface MfaIdentityStore {

    public AuthenticationResult authenticate(String username, PasswordCredential password, Map<String, Object> attributes);

    public PasswordResetResult passwordReset(String username, PasswordCredential currentPassword,
            PasswordCredential newPassword, Map<String, Object> attributes);

    public VerificationResult verifyTotp(String username, TotpCallback callback, Map<String, Object> attributes);

    public String storeTotpKey(String username, PasswordCredential toptKey);

    @FunctionalInterface
    public interface TotpCallback {
        boolean verify(PasswordCredential toptKey);
    }

    public static enum AuthenticationResult {
        SUCCESS,
        SUCCESS_VERIFY_TOTP,
        SUCCESS_REGISTER_TOTP,
        SUCCESS_RESET_PASSWORD,
        FAILED,
        FAILED_ACCOUNT_LOCKED;
    }

    public static enum PasswordResetResult {
        SUCCESS,
        SUCCESS_VERIFY_TOTP,
        SUCCESS_REGISTER_TOTP,
        FAILED_CURRENT,
        FAILED_POLICY,
        FAILED_ACCOUNT_LOCKED;
    }

    public static enum VerificationResult {
        SUCCESS,
        FAILED,
        FAILED_ACCOUNT_LOCKED;
    }
}
