package io.quarkus.mfa.runtime;

import static io.quarkus.mfa.runtime.MfaAuthConstants.AUTH_CLAIMS_KEY;
import static io.quarkus.mfa.runtime.MfaAuthConstants.AUTH_CONTEXT_KEY;
import static io.vertx.core.http.HttpHeaders.CONTENT_TYPE;
import static io.vertx.core.http.HttpHeaders.LOCATION;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;

import org.jboss.logging.Logger;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;

import com.j256.twofactorauth.TimeBasedOneTimePasswordUtil;

import io.quarkus.arc.Arc;
import io.quarkus.mfa.runtime.MfaAuthConstants.FormFields;
import io.quarkus.mfa.runtime.MfaAuthConstants.MfaAuthContext;
import io.quarkus.mfa.runtime.MfaAuthConstants.ViewAction;
import io.quarkus.mfa.runtime.MfaAuthConstants.ViewStatus;
import io.quarkus.mfa.runtime.MfaIdentityStore.AuthenticationResult;
import io.quarkus.mfa.runtime.MfaIdentityStore.PasswordResetResult;
import io.quarkus.mfa.runtime.MfaIdentityStore.TotpCallback;
import io.quarkus.mfa.runtime.MfaIdentityStore.VerificationResult;
import io.quarkus.security.credential.PasswordCredential;
import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.AuthenticationRequest;
import io.quarkus.vertx.http.runtime.security.ChallengeData;
import io.quarkus.vertx.http.runtime.security.HttpAuthenticationMechanism;
import io.quarkus.vertx.http.runtime.security.HttpCredentialTransport;
import io.quarkus.vertx.http.runtime.security.HttpSecurityUtils;
import io.smallrye.mutiny.Uni;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;

public class MfaAuthenticationMechanism implements HttpAuthenticationMechanism {

	private static final Logger log = Logger.getLogger(MfaAuthenticationMechanism.class);

	private final String loginView;
	private final String logoutView;
	private final String loginAction;
	private final JWELoginManager loginManager;

	MfaAuthenticationMechanism(String loginView, String logoutView, String loginAction, JWELoginManager loginManager) {
		this.loginView = loginView;
		this.logoutView = logoutView;
		this.loginAction = loginAction;
		this.loginManager = loginManager;
	}

	@Override
	public Uni<SecurityIdentity> authenticate(RoutingContext context, IdentityProviderManager identityProviderManager) {
		String path = context.request().path();
		log.debugf("authenticating %s", path);
		boolean loginAttempt = loginView.equals(path);
		boolean logoutAttempt = logoutView.equals(path) || (loginAction.equals(path) && context.request().params().contains("logout"));
		JwtClaims claims = loginManager.restore(context);
		if (loginManager.hasSubject(claims) && !logoutAttempt && !loginAttempt) {
			// TODO explorer chaining this Uni together with the code below so that a re-authentication is attempted instead of a 403 if the SecurityIdentity is null.
			return restoreIdentity(claims, context, identityProviderManager);
		}
		if (claims == null || loginManager.newCookieNeeded(claims)) {
			claims = new JwtClaims();
		}
		context.put(AUTH_CLAIMS_KEY, claims);

		if (loginAttempt) {
			if (!claims.hasClaim("action")) {
				claims.setClaim("action", ViewAction.LOGIN);
			}
			context.put(AUTH_CONTEXT_KEY, new MfaAuthContext(ViewAction.get(claims.getClaimValueAsString("action")), ViewStatus.get(claims.getClaimValueAsString("status")), claims.getClaimValueAsString("totp-url")));
			loginManager.save(claims, context);
		} else if (logoutAttempt) {
			if (!claims.hasClaim("action")) {
				claims.setClaim("action", ViewAction.LOGOUT.toString());
			}
			context.put(AUTH_CONTEXT_KEY, new MfaAuthContext(ViewAction.get(claims.getClaimValueAsString("action")), null, null));
			loginManager.clear(context);
		} else if (loginAction.equals(path)) {
			if (!claims.hasClaim("action")) { // zero form login
				claims.setClaim("action", ViewAction.LOGIN.toString());
				claims.setClaim("path", "/");
			}
		} else {
			claims.setClaim("path", path);
		}

		return Uni.createFrom().nullItem();
	}

	public Uni<SecurityIdentity> restoreIdentity(JwtClaims claims, RoutingContext context, IdentityProviderManager identityProviderManager) {
		// previously authenticated. Automatically login using trusted credentials
		context.put(HttpAuthenticationMechanism.class.getName(), this);
		Uni<SecurityIdentity> ret = identityProviderManager.authenticate(HttpSecurityUtils.setRoutingContextAttribute(new MfaAuthenticationRequest(claims), context));
		return ret.onItem().invoke(new Consumer<SecurityIdentity>() {
			@Override
			public void accept(SecurityIdentity securityIdentity) {
				if (securityIdentity != null && loginManager.newCookieNeeded(claims)) {
					loginManager.save(claims, context);
				}
			}
		});
	}

	public void action(RoutingContext context) {
		MfaIdentityStore mfaIdentityStore = Arc.container().instance(MfaIdentityStore.class).get();
		if (mfaIdentityStore == null) {
			throw new IllegalStateException("MfaIdentityStore implementation is unavailable");
		}
		JwtClaims authContext = context.get(AUTH_CLAIMS_KEY);
		boolean isJson = "application/json".equals(context.getAcceptableContentType());

		if (context.request().method() == HttpMethod.GET) {
			if (context.request().params().contains("logout")) {
				handleLogout(context, isJson, authContext);
			} else {
				sendJson(context, authContext);
			}
		} else {
			// authentication claims would only be empty if the user was already authenticated
			ViewAction action = ViewAction.get(authContext.getClaimValueAsString("action"));

			if (ViewAction.LOGIN == action) {
				handleLogin(context, isJson, authContext, mfaIdentityStore);
			} else if (ViewAction.LOGOUT == action) {
				handleLogout(context, isJson, authContext);
			} else if (ViewAction.PASSWORD_RESET == action) {
				handlePasswordReset(context, isJson, authContext, mfaIdentityStore);
			} else if (ViewAction.VERIFY_TOTP == action) {
				handleVerifyTotp(context, isJson, authContext, mfaIdentityStore);
			} else if (ViewAction.REGISTER_TOTP == action) {
				if (context.request().getParam(FormFields.PASSCODE.toString()) != null) {
					// allow zero page/direct passcode verification after registration
					authContext.setClaim("action", ViewAction.VERIFY_TOTP);
					handleVerifyTotp(context, isJson, authContext, mfaIdentityStore);
				} else {
					handleRegisterTotp(context, isJson, authContext);
				}
			} else {
				HttpServerResponse response = context.response();
				response.setStatusCode(500);
				log.errorf("unexpected state %s", authContext.getClaimValueAsString("action"));
				response.setStatusMessage("unexpected state");
				context.response().end();
			}
		}

	}

	private void sendJson(RoutingContext context, JwtClaims authContext) {
		JsonObject response = new JsonObject();
		response.put("action", authContext.getClaimValueAsString("action"));
		response.put("status", authContext.getClaimValueAsString("status"));
		Optional.ofNullable(authContext.getClaimValueAsString("path")).ifPresent(c -> response.put("path", c));
		Optional.ofNullable(authContext.getClaimValueAsString("totp-url")).ifPresent(c -> response.put("totp-url", c));
		Optional.ofNullable(authContext.getClaimValue("exp")).ifPresent(c -> response.put("exp", c));

		context.response().setStatusCode(200);
		context.response().putHeader(CONTENT_TYPE, "application/json");
		context.response().setChunked(true);
		context.response().write(response.toBuffer());
		context.response().end();
	}

	private void successfulLogin(RoutingContext context, boolean isJson, JwtClaims authContext, Map<String, Object> attributes) {
		String path = authContext.getClaimValueAsString("path");
		path = path != null ? path : "/";
		JwtClaims authenticated = new JwtClaims();
		authenticated.setIssuedAt(NumericDate.now());
		attributes.entrySet().forEach(e -> authenticated.setClaim(e.getKey(), e.getValue()));
		if (!authenticated.hasClaim("sub")) {
			log.errorf("Mandatory subject claim 'sub' not set by identity store");
		}
		if (log.isDebugEnabled()) {
			log.debugf("login success - path: %s claims: %s ", path, authenticated.toJson());
		}
		loginManager.save(authenticated, context);

		if (isJson) {
			authContext.setClaim("action", "login");
			authContext.setClaim("status", "success");
			authContext.setClaim("exp", authenticated.getClaimValue("exp"));
			sendJson(context, authContext);
		} else {
			sendRedirect(context, path);
		}
	}

	private void handleLogin(RoutingContext context, boolean isJson, JwtClaims authContext, MfaIdentityStore mfaIdentityStore) {
		log.debugf("processing login");
		Map<String, Object> attributes = new HashMap<>();

		String username = null;
		String password = null;
		if (isJson) {
			JsonObject request = context.body().asJsonObject();
			username = request.getString(FormFields.USERNAME.toString());
			password = request.getString(FormFields.PASSWORD.toString());
		} else {
			username = context.request().getFormAttribute(FormFields.USERNAME.toString());
			password = context.request().getFormAttribute(FormFields.PASSWORD.toString());

		}
		if (username == null || password == null) {
			sendLogin(context, isJson, authContext);
		} else {
			AuthenticationResult authResult = mfaIdentityStore.authenticate(username, new PasswordCredential(password.toCharArray()), attributes);
			if (authResult == AuthenticationResult.SUCCESS) {
				successfulLogin(context, isJson, authContext, attributes);
			} else {
				if (authResult == AuthenticationResult.SUCCESS_VERIFY_TOTP) {
					authContext.setClaim("action", ViewAction.VERIFY_TOTP);
					authContext.setClaim("auth-sub", username);
					authContext.unsetClaim("status");
					log.debugf("login success - verify TOTP");
				} else if (authResult == AuthenticationResult.SUCCESS_REGISTER_TOTP) {
					registerTotp(username, authContext, mfaIdentityStore);
					log.debugf("login success - register TOTP");
				} else if (authResult == AuthenticationResult.SUCCESS_RESET_PASSWORD) {
					authContext.setClaim("action", ViewAction.PASSWORD_RESET);
					authContext.setClaim("auth-sub", username);
					authContext.unsetClaim("status");
					log.debugf("login success - password reset");
				} else if (authResult == AuthenticationResult.FAILED_ACCOUNT_LOCKED) {
					authContext.setClaim("status", ViewStatus.ACCOUNT_LOCKED);
					log.debugf("login failed - account locekd");
				} else if (authResult == AuthenticationResult.FAILED) {
					authContext.setClaim("status", ViewStatus.FAILED);
					log.debugf("login failed");
				}
				if (log.isDebugEnabled()) {
					log.debugf("login redirect claims: %s", authContext.toJson());
				}

				loginManager.save(authContext, context);
				if (isJson) {
					sendJson(context, authContext);
				} else {
					sendRedirect(context, loginView);
				}

			}

		}

	}

	private void handleLogout(RoutingContext context, boolean isJson, JwtClaims authContext) {
		log.debugf("processing logout");
		loginManager.clear(context);
		if (log.isDebugEnabled()) {
			log.debugf("login redirect claims: %s", authContext.toJson());
		}
		if (isJson) {
			authContext = new JwtClaims(); // could be null if the user is authenticated
			authContext.setClaim("action", "logout");
			authContext.setClaim("status", "success");
			sendJson(context, authContext);
		} else {
			sendRedirect(context, loginView);
		}
	}

	private void registerTotp(String username, JwtClaims authContext, MfaIdentityStore mfaIdentityStore) {
		authContext.setClaim("action", ViewAction.REGISTER_TOTP);
		authContext.setClaim("auth-sub", username);
		String base32Secret = TimeBasedOneTimePasswordUtil.generateBase32Secret();
		String keyId = mfaIdentityStore.storeTotpKey(username, new PasswordCredential(base32Secret.toCharArray()));
		String imageURL = TimeBasedOneTimePasswordUtil.qrImageUrl(keyId, base32Secret);
		authContext.setClaim("totp-url", imageURL);
		authContext.unsetClaim("status");

	}

	private void sendLogin(RoutingContext context, boolean isJson, JwtClaims authContext) {
		authContext.setClaim("action", ViewAction.LOGIN);
		authContext.unsetClaim("status");
		loginManager.save(authContext, context);
		if (isJson) {
			sendJson(context, authContext);
		} else {
			sendRedirect(context, loginView);
		}

	}

	private void handlePasswordReset(RoutingContext context, boolean isJson, JwtClaims authContext, MfaIdentityStore mfaIdentityStore) {
		log.debugf("processing password reset");
		String username = authContext.getClaimValueAsString("auth-sub");
		String currentPassword = null;
		String newPassword = null;
		if (isJson) {
			JsonObject request = context.body().asJsonObject();
			currentPassword = request.getString(FormFields.PASSWORD.toString());
			newPassword = request.getString(FormFields.NEW_PASSWORD.toString());
		} else {
			currentPassword = context.request().getFormAttribute(FormFields.PASSWORD.toString());
			newPassword = context.request().getFormAttribute(FormFields.NEW_PASSWORD.toString());
		}
		if (username == null || currentPassword == null || newPassword == null) {
			sendLogin(context, isJson, authContext);
		} else {
			Map<String, Object> attributes = new HashMap<>();
			PasswordResetResult authResult = mfaIdentityStore.passwordReset(username, new PasswordCredential(currentPassword.toCharArray()), new PasswordCredential(newPassword.toCharArray()), attributes);
			if (authResult == PasswordResetResult.SUCCESS) {
				successfulLogin(context, isJson, authContext, attributes);
			} else {
				if (authResult == PasswordResetResult.SUCCESS_VERIFY_TOTP) {
					authContext.setClaim("action", ViewAction.VERIFY_TOTP);
					authContext.setClaim("auth-sub", username);
					authContext.unsetClaim("status");
					log.debugf("password reset success - verify TOTP");
				} else if (authResult == PasswordResetResult.SUCCESS_REGISTER_TOTP) {
					registerTotp(username, authContext, mfaIdentityStore);
					log.debugf("password reset success - register TOTP");
				} else if (authResult == PasswordResetResult.FAILED_CURRENT) {
					authContext.setClaim("status", ViewStatus.FAILED_CURRENT);
					log.debugf("password reset failed - current password");
				} else if (authResult == PasswordResetResult.FAILED_POLICY) {
					authContext.setClaim("status", ViewStatus.FAILED_POLICY);
					log.debugf("password reset failed - password policy");
				}

				loginManager.save(authContext, context);
				if (isJson) {
					sendJson(context, authContext);
				} else {
					sendRedirect(context, loginView);
				}
			}
		}
	}

	private void handleVerifyTotp(RoutingContext context, boolean isJson, JwtClaims authContext, MfaIdentityStore mfaIdentityStore) {
		log.debugf("processing verify TOTP");
		String username = authContext.getClaimValueAsString("auth-sub");
		String passcode = null;
		if (isJson) {
			JsonObject request = context.body().asJsonObject();
			passcode = request.getString(FormFields.PASSCODE.toString());
		} else {
			passcode = context.request().getFormAttribute(FormFields.PASSCODE.toString());
		}
		if (username == null || passcode == null) {
			sendLogin(context, isJson, authContext);
		} else {
			Map<String, Object> attributes = new HashMap<>();
			final String fpasscode = passcode;
			TotpCallback callback = p -> {
				try {
					String currentPasscode = TimeBasedOneTimePasswordUtil.generateCurrentNumberString(new String(p.getPassword()));
					return currentPasscode.equals(fpasscode);
				} catch (GeneralSecurityException e) {
					log.errorf(e, "passcode error");
					return false;
				}

			};
			VerificationResult authResult = mfaIdentityStore.verifyTotp(username, callback, attributes);
			if (authResult == VerificationResult.SUCCESS) {
				successfulLogin(context, isJson, authContext, attributes);
			} else {
				if (authResult == VerificationResult.FAILED) {
					authContext.setClaim("status", ViewStatus.FAILED);
				}

				loginManager.save(authContext, context);
				if (isJson) {
					sendJson(context, authContext);
				} else {
					sendRedirect(context, loginView);
				}
			}
		}
	}

	private void handleRegisterTotp(RoutingContext context, boolean isJson, JwtClaims authContext) {
		log.debugf("processing register TOTP"); // redirect back to login page. Could be handled client side as well
		String username = authContext.getClaimValueAsString("auth-sub");
		if (username == null) {
			sendLogin(context, isJson, authContext);
		} else {
			authContext.setClaim("action", ViewAction.VERIFY_TOTP);
			authContext.unsetClaim("status");
			authContext.unsetClaim("totp-url");

			loginManager.save(authContext, context);
			if (isJson) {
				sendJson(context, authContext);
			} else {
				sendRedirect(context, loginView);
			}
		}
	}

	@Override
	public Uni<ChallengeData> getChallenge(RoutingContext context) {
		log.debugf("Serving login form %s for %s", loginView, context);
		JwtClaims authContext = context.get(AUTH_CLAIMS_KEY);
		loginManager.save(authContext, context);
		return getChallengeRedirect(context, loginView);
	}

	static Uni<ChallengeData> getChallengeRedirect(final RoutingContext exchange, final String location) {
		String loc = exchange.request().scheme() + "://" + exchange.request().host() + location;
		return Uni.createFrom().item(new ChallengeData(302, LOCATION, loc));
	}

	static void sendRedirect(final RoutingContext exchange, final String location) {
		String loc = exchange.request().scheme() + "://" + exchange.request().host() + location;
		exchange.response().setStatusCode(302).putHeader(LOCATION, loc).end();
	}

	@Override
	public Set<Class<? extends AuthenticationRequest>> getCredentialTypes() {
		return new HashSet<>(Arrays.asList(MfaAuthenticationRequest.class));
	}

	@Override
	public Uni<HttpCredentialTransport> getCredentialTransport(RoutingContext context) {
		return Uni.createFrom().nullItem();
	}

}
