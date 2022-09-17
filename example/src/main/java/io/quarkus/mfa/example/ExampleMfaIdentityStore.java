package io.quarkus.mfa.example;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;

import org.jboss.logging.Logger;

import com.j256.twofactorauth.TimeBasedOneTimePasswordUtil;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import de.mkammerer.argon2.Argon2Factory.Argon2Types;
import io.quarkus.arc.Unremovable;
import io.quarkus.logging.Log;
import io.quarkus.mfa.runtime.MfaIdentityStore;
import io.quarkus.security.credential.PasswordCredential;

@Unremovable
@ApplicationScoped
public class ExampleMfaIdentityStore implements MfaIdentityStore {

    private static final Logger log = Logger.getLogger(ExampleMfaIdentityStore.class);

    Map<String, User> users = new HashMap<>();

    @PostConstruct
    public void init() {
        List<User> allUsers = new ArrayList<>(5);
        String password = "$argon2id$v=19$m=1048576,t=4,p=8$18aRyS8hi3Crk4wKJKKPig$UcoE0R/YCHYFxd9okNx3khG2b1Hjfno8ZCO8sx4kG98";
        String totpKey = "EQ36AZVNKIOW6D67";

        allUsers.add(new User("jdoe1", "jdoe1@acme.com", password, totpKey));
        allUsers.add(new User("jdoe2", "jdoe2@acme.com", password, totpKey));
        allUsers.add(new User("jdoe3", "jdoe3@acme.com", password, totpKey));
        allUsers.add(new User("jdoe4", "jdoe4@acme.com", password, totpKey));
        allUsers.add(new User("jdoe5", "jdoe5@acme.com", password, totpKey));
        users.putAll(allUsers.stream().collect(Collectors.toMap(u -> u.userName, Function.identity())));

        users.get("jdoe1").groups = new String[] { "admin" };
        users.get("jdoe2").mfaExempt = true;
        users.get("jdoe3").authFailedAttempts = 5;
        users.get("jdoe4").passwordExpired = true;
        users.get("jdoe5").totpSecret = null;
    }

    public String totpKey(String username) {
        User user = users.get(username);
        if (user != null) {
            return user.totpSecret;
        }
        return null;
    }

    @Override
    public AuthenticationResult authenticate(String username, PasswordCredential password, Map<String, Object> attributes) {
        User user = users.get(username);
        if (user != null) {
            if (user.authFailedAttempts >= 5) {
                return AuthenticationResult.FAILED_ACCOUNT_LOCKED;
            }
            Argon2 argon2 = Argon2Factory.create(Argon2Types.ARGON2id);
            if (argon2.verify(user.passwordHash, password.getPassword())) {
                user.authFailedAttempts = 0;
                if (user.passwordExpired) {
                    return AuthenticationResult.SUCCESS_RESET_PASSWORD;
                }
                if (user.mfaExempt) {
                    userToAttributes(user, attributes);
                    return AuthenticationResult.SUCCESS;
                }
                if (user.totpSecret == null) {
                    return AuthenticationResult.SUCCESS_REGISTER_TOTP;
                }
                printPasscode(user);
                return AuthenticationResult.SUCCESS_VERIFY_TOTP;
            } else {
                user.authFailedAttempts++;

            }
        }

        return AuthenticationResult.FAILED;

    }

    private void printPasscode(User user) {
        Thread pc = new Thread(() -> {
            for (int i = 0; i < 30; i++) {
                try {
                    long diff = TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS
                            - ((System.currentTimeMillis() / 1000) % TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS);
                    String code = TimeBasedOneTimePasswordUtil.generateCurrentNumberString(user.totpSecret);
                    log.infof("User: %s secret code: %s changes in %s seconds\n", user.subject, code, diff);
                    Thread.sleep(1000);
                } catch (Exception e) {
                    Log.errorf(e, "TOTP display error");
                }
            }
        });
        pc.start();
    }

    private void userToAttributes(User user, Map<String, Object> attributes) {
        attributes.put("sub", user.subject);
        attributes.put("groups", user.groups);
    }

    @Override
    public PasswordResetResult passwordReset(String username, PasswordCredential currentPassword,
            PasswordCredential newPassword, Map<String, Object> attributes) {
        User user = users.get(username);
        if (user != null) {
            if (user.authFailedAttempts >= 5) {
                return PasswordResetResult.FAILED_ACCOUNT_LOCKED;
            }
            Argon2 argon2 = Argon2Factory.create(Argon2Types.ARGON2id);
            if (argon2.verify(user.passwordHash, currentPassword.getPassword())) {
                user.authFailedAttempts = 0;
                if (newPassword.getPassword().length > 3) {
                    return PasswordResetResult.FAILED_POLICY;
                }
                user.passwordHash = argon2.hash(4, 1024 * 1024, 8, newPassword.getPassword());
                user.passwordExpired = false;
                if (user.mfaExempt) {
                    userToAttributes(user, attributes);
                    return PasswordResetResult.SUCCESS;
                }
                if (user.totpSecret == null) {
                    return PasswordResetResult.SUCCESS_REGISTER_TOTP;
                }
                printPasscode(user);
                return PasswordResetResult.SUCCESS_VERIFY_TOTP;
            } else {
                user.authFailedAttempts++;

            }
        }

        return PasswordResetResult.FAILED_CURRENT;
    }

    @Override
    public VerificationResult verifyTotp(String username, TotpCallback callback, Map<String, Object> attributes) {
        User user = users.get(username);
        if (user != null) {
            if (user.authFailedAttempts >= 5) {
                return VerificationResult.FAILED_ACCOUNT_LOCKED;
            }
            if (callback.verify(new PasswordCredential(user.totpSecret.toCharArray()))) {
                user.authFailedAttempts = 0;
                userToAttributes(user, attributes);
                return VerificationResult.SUCCESS;
            } else {
                user.authFailedAttempts++;

            }
        }
        return VerificationResult.FAILED;
    }

    @Override
    public String storeTotpKey(String username, PasswordCredential toptKey) {
        User user = users.get(username);
        if (user != null) {
            user.totpSecret = new String(toptKey.getPassword());
            printPasscode(user);
            return "Quarkus MFA Test";
        }
        return null;
    }

    private static class User {
        String userName;
        String subject;
        String passwordHash;
        String totpSecret = null;
        String[] groups = new String[0];

        int authFailedAttempts = 0;
        boolean passwordExpired = false;
        boolean mfaExempt;

        public User(String userName, String subject, String passwordHash, String totpSecret) {
            this.userName = userName;
            this.subject = subject;
            this.passwordHash = passwordHash;
            this.totpSecret = totpSecret;
        }

    }

    public static void main(String[] args) {
        Argon2 argon2 = Argon2Factory.create(Argon2Types.ARGON2id);
        System.out.format("Password Hash: %s\n", argon2.hash(4, 1024 * 1024, 8, "mfa".toCharArray()));
        System.out.format("Example TOTP Key: %s\n", TimeBasedOneTimePasswordUtil.generateBase32Secret());
    }

}
