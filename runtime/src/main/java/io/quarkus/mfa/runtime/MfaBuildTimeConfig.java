package io.quarkus.mfa.runtime;

import io.quarkus.runtime.annotations.ConfigPhase;
import io.quarkus.runtime.annotations.ConfigRoot;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;

@ConfigMapping(prefix = "quarkus.mfa")
@ConfigRoot(phase = ConfigPhase.BUILD_AND_RUN_TIME_FIXED)
public interface MfaBuildTimeConfig {

    /**
     * If the MFA extension is enabled.
     */
    @WithDefault("true")
    boolean enabled();

    /**
     * The login view handler
     */
    @WithDefault("/mfa_login")
    String loginView();

    /**
     * The logout view handler
     */
    @WithDefault("/mfa_logout")
    String logoutView();

    /**
     * The login action handler
     */
    @WithDefault("/mfa_action")
    String loginAction();

    /**
     * The landing page to redirect to if there is no saved page to redirect back to
     */
    @WithDefault("/")
    String landingPage();

    /**
     * Option to disable redirect to landingPage if there is no saved page to redirect back to. MFA POST is followed by redirect
     * to landingPage by default.
     */
    @WithDefault("true")
    boolean redirectAfterLogin();

}
