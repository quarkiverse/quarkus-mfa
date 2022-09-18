package io.quarkus.mfa.example;

import static io.quarkus.mfa.runtime.MfaAuthConstants.AUTH_CONTEXT_KEY;
import static io.vertx.core.http.HttpHeaders.CACHE_CONTROL;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.function.BiFunction;

import javax.annotation.Priority;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;

import org.jboss.logging.Logger;

import io.quarkus.mfa.runtime.MfaAuthConstants.MfaAuthContext;
import io.quarkus.mfa.runtime.MfaAuthConstants.ViewStatus;
import io.quarkus.vertx.http.runtime.security.QuarkusHttpUser;
import io.vertx.core.Handler;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.impl.BlockingHandlerDecorator;

@ApplicationScoped
public class SPARouter {

	private static final Logger log = Logger.getLogger(SPARouter.class);

	public void setupRouter(@Observes @Priority(value = 1) Router router) {
		log.infof("Setting up routes\n");

		Handler<RoutingContext> notFound = template("not-found.html", "/", null);
		router.route("/not-found").handler(notFound);
		router.errorHandler(404, notFound);
		router.route("/favicon.ico").handler(notFound);

		Handler<RoutingContext> accessDenied = template("access-denied.html", "/", null);
		router.route("/access-denied").handler(accessDenied);
		router.errorHandler(401, accessDenied);

		router.route("/mfa_login").handler(this::handleLogin);
		router.route("/mfa_logout").handler(this::handleLogout);

		router.route("/").handler(this::handleRoot);
		router.route("/home").handler(this::handleHome);

		router.route("/spa").handler(this::handleSPA);
		router.route("/spa-secure").handler(this::handleSPASecure);
	}

	private void handleRoot(RoutingContext context) {
		log.debugf("handleRoot");
		QuarkusHttpUser quser = (QuarkusHttpUser) context.user();
		final String user = quser.principal().getString("username");
		template("index.html", "/", (t, c) -> {
			t = t.replace("@@USER@@", user);
			return t;
		}).handle(context);
	}

	private void handleSPA(RoutingContext context) {
		QuarkusHttpUser quser = (QuarkusHttpUser) context.user();
		final String user = quser.principal().getString("username");
		log.debugf("handleSPA");
		template("spa.html", "/", (t, c) -> {
			t = t.replace("@@USER@@", user);
			return t;
		}).handle(context);

	}

	private void handleSPASecure(RoutingContext context) {
		log.debugf("handleSPASecure");
		HttpServerResponse response = context.response();
		response.setStatusCode(200);
		response.setChunked(true);
		JsonObject content = new JsonObject();
		content.put("message", "Successfully accessed secure content");
		response.write(content.toBuffer());
		context.response().end();

	}

	private void handleHome(RoutingContext context) {
		QuarkusHttpUser quser = (QuarkusHttpUser) context.user();
		final String user = quser.principal().getString("username");
		log.debugf("handleHome");
		template("home.html", "/", (t, c) -> {
			t = t.replace("@@USER@@", user);
			return t;
		}).handle(context);

	}

	private void handleLogin(RoutingContext context) {
		log.debugf("handleLogin");
		QuarkusHttpUser quser = (QuarkusHttpUser) context.user();
		final String user = quser.principal().getString("username");
		MfaAuthContext authContext = context.get(AUTH_CONTEXT_KEY);

		switch (authContext.getViewAction()) {
		case LOGIN:
			template("login.html", "/", (t, c) -> {
				if (authContext.getViewStatus() == ViewStatus.FAILED) {
					t = t.replace("@@HIDE@@", "");
					t = t.replace("@@ERROR_MSG@@", "Authentication Failed");
				} else if (authContext.getViewStatus() == ViewStatus.ACCOUNT_LOCKED) {
					t = t.replace("@@HIDE@@", "");
					t = t.replace("@@ERROR_MSG@@", "Account Locked");
				} else {
					t = t.replace("@@HIDE@@", "hidden");
					t = t.replace("@@ERROR_MSG@@", "");
				}

				return t;
			}).handle(context);
			break;
		case PASSWORD_RESET:
			template("password-reset.html", "/", (t, c) -> {
				if (authContext.getViewStatus() == ViewStatus.FAILED_CURRENT) {
					t = t.replace("@@HIDE@@", "");
					t = t.replace("@@ERROR_MSG@@", "Current Password Failed Authentication");
				} else if (authContext.getViewStatus() == ViewStatus.FAILED_POLICY) {
					t = t.replace("@@HIDE@@", "");
					t = t.replace("@@ERROR_MSG@@", "Password Policy Violation");
				} else {
					t = t.replace("@@HIDE@@", "hidden");
					t = t.replace("@@ERROR_MSG@@", "");
				}

				return t;
			}).handle(context);
			break;
		case VERIFY_TOTP:
			template("verify-passcode.html", "/", (t, c) -> {
				if (authContext.getViewStatus() == ViewStatus.FAILED) {
					t = t.replace("@@HIDE@@", "");
					t = t.replace("@@ERROR_MSG@@", "Passcode Authentication Failed");
				} else {
					t = t.replace("@@HIDE@@", "hidden");
					t = t.replace("@@ERROR_MSG@@", "");
				}

				return t;
			}).handle(context);
			break;
		case REGISTER_TOTP:
			template("register-passcode.html", "/", (t, c) -> {
				t = t.replace("@@QR_CODE_IMAGE@@", authContext.getToptURL());
				return t;
			}).handle(context);
			break;
		}

	}

	private void handleLogout(RoutingContext context) {
		log.debugf("handleLogout");
		template("logout.html", "/", null).handle(context);
	}

	public String lookupTemplate(String templateName, String base) {

		InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream("/META-INF/resources/" + templateName);
		if (is != null) {
			try {
				String template = new String(is.readAllBytes(), StandardCharsets.UTF_8);
				return template;
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return null;

	}

	private Handler<RoutingContext> template(String templateName, String base, BiFunction<String, RoutingContext, String> mapper) {

		return new BlockingHandlerDecorator(ctx -> {

			HttpServerResponse response = ctx.response();
			String template = lookupTemplate(templateName, base);
			if (template != null) {
				if (mapper != null) {
					template = mapper.apply(template, ctx);
				}
				response.setStatusCode(200);
				response.setChunked(true);
				response.putHeader(CACHE_CONTROL, "no-store, no-cache, no-transform, must-revalidate, max-age=0");
				response.write(template);
			} else {
				response.setStatusCode(404);
			}

			ctx.response().end();
		}, true);
	}

}
